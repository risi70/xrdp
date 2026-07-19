"""Keycloak OIDC authentication at the broker boundary.

Keycloak authenticates the user. The broker validates the Keycloak token,
applies its own target policy, and issues a separate broker-neutral BAF
assertion. XRDP never consumes Keycloak tokens or Keycloak signing keys.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient

from reference_broker import AuthContext, BrokerError, ReferenceBroker

DEFAULT_ALGORITHMS = ("RS256",)
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_TOKEN_BYTES = 16384
DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 900
MAX_CLAIM_ITEMS = 64
MAX_CLAIM_LENGTH = 255
MAX_AUTH_METHOD_ITEMS = 16
MAX_AUTH_METHOD_LENGTH = 64


class KeycloakError(ValueError):
    """The Keycloak authentication or broker mapping failed."""


@dataclass(frozen=True)
class KeycloakIdentity:
    """Bounded identity data extracted from a verified Keycloak token."""

    username: str
    subject: str
    groups: tuple[str, ...]
    realm_roles: tuple[str, ...]
    client_roles: tuple[str, ...]
    auth_method: tuple[str, ...]
    assurance: str

    @property
    def roles(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.realm_roles) | set(self.client_roles)))


class KeycloakAuthenticator:
    """Verify Keycloak tokens and map selected claims to broker identity."""

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        *,
        audience: str | None = None,
        include_realm_roles: bool = True,
        include_client_roles: bool = True,
        algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_token_bytes: int = DEFAULT_MAX_TOKEN_BYTES,
        max_token_lifetime_seconds: int = DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
        expected_token_type: str = "Bearer",
        allow_http_for_tests: bool = False,
    ):
        if not base_url or not realm or not client_id:
            raise KeycloakError("base_url, realm and client_id are required")
        if "/" in realm or len(realm) > MAX_CLAIM_LENGTH:
            raise KeycloakError("invalid Keycloak realm")
        if len(client_id) > MAX_CLAIM_LENGTH:
            raise KeycloakError("invalid Keycloak client_id")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and not allow_http_for_tests:
            raise KeycloakError("Keycloak base_url must use HTTPS")
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise KeycloakError("invalid Keycloak base_url")
        if not algorithms or any(alg not in ("RS256", "ES256")
                                 for alg in algorithms):
            raise KeycloakError("unsupported Keycloak token algorithm")
        if (timeout_seconds <= 0 or max_token_bytes <= 0 or
                max_token_lifetime_seconds <= 0):
            raise KeycloakError("invalid Keycloak verifier limits")
        if not expected_token_type:
            raise KeycloakError("expected_token_type is required")

        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.audience = audience or client_id
        self.include_realm_roles = include_realm_roles
        self.include_client_roles = include_client_roles
        self.algorithms = list(algorithms)
        self.timeout_seconds = timeout_seconds
        self.max_token_bytes = max_token_bytes
        self.max_token_lifetime_seconds = max_token_lifetime_seconds
        self.expected_token_type = expected_token_type
        self.issuer = f"{self.base_url}/realms/{realm}"
        self.jwks_uri = f"{self.issuer}/protocol/openid-connect/certs"
        self._jwk_client: PyJWKClient | None = None

    def validate_token(self, token: str) -> KeycloakIdentity:
        """Verify a Keycloak JWT and return its bounded identity data."""
        if not isinstance(token, str) or not token:
            raise KeycloakError("empty token")
        if len(token.encode("utf-8")) > self.max_token_bytes:
            raise KeycloakError("token exceeds configured size limit")

        try:
            if self._jwk_client is None:
                self._jwk_client = PyJWKClient(
                    self.jwks_uri, timeout=self.timeout_seconds
                )
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud"],
                    "verify_aud": True,
                },
            )
        except Exception as exc:
            raise KeycloakError("token verification failed") from exc

        self._validate_authorized_party(claims)
        self._validate_lifetime(claims)
        if claims.get("typ") != self.expected_token_type:
            raise KeycloakError("token type mismatch")
        return self.identity_from_claims(claims)

    def _validate_authorized_party(self, claims: Mapping[str, Any]) -> None:
        authorized_party = claims.get("azp")
        if authorized_party != self.client_id:
            raise KeycloakError("token authorized party mismatch")

    def _validate_lifetime(self, claims: Mapping[str, Any]) -> None:
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if (not isinstance(issued_at, (int, float)) or
                not isinstance(expires_at, (int, float)) or
                expires_at <= issued_at or
                expires_at - issued_at > self.max_token_lifetime_seconds):
            raise KeycloakError("token lifetime is outside policy")

    def identity_from_claims(
        self, claims: Mapping[str, Any]
    ) -> KeycloakIdentity:
        """Map already verified claims to broker identity fields."""
        subject = _required_string(claims, "sub")
        username = _required_string(claims, "preferred_username")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in username):
            raise KeycloakError("preferred_username contains control characters")
        groups = _string_list(claims.get("groups"), "groups")

        realm_roles: tuple[str, ...] = ()
        realm_access = _mapping(claims.get("realm_access"), "realm_access")
        if self.include_realm_roles and realm_access:
            realm_roles = _string_list(
                realm_access.get("roles"), "realm_access.roles", unique=True
            )

        client_roles: tuple[str, ...] = ()
        resource_access = _mapping(
            claims.get("resource_access"), "resource_access"
        )
        if self.include_client_roles and resource_access:
            client_access = _mapping(
                resource_access.get(self.client_id),
                f"resource_access.{self.client_id}",
            )
            if client_access:
                client_roles = _string_list(
                    client_access.get("roles"),
                    f"resource_access.{self.client_id}.roles",
                    unique=True,
                )

        auth_method = _string_list(
            claims.get("amr"),
            "amr",
            max_items=MAX_AUTH_METHOD_ITEMS,
            max_length=MAX_AUTH_METHOD_LENGTH,
            unique=True,
        ) or ("oidc",)
        assurance_value = claims.get("acr")
        if assurance_value is None:
            assurance = "unknown"
        elif isinstance(assurance_value, str) and assurance_value:
            assurance = _bounded_string(assurance_value, "acr")
        else:
            raise KeycloakError("acr must be a non-empty string")

        return KeycloakIdentity(
            username=username,
            subject=_broker_subject(self.issuer, subject),
            groups=tuple(sorted(set(groups))),
            realm_roles=tuple(sorted(realm_roles)),
            client_roles=tuple(sorted(client_roles)),
            auth_method=auth_method,
            assurance=assurance,
        )


@dataclass(frozen=True)
class KeycloakBrokerAdapter:
    """Apply Keycloak authentication before broker target authorization."""

    authenticator: KeycloakAuthenticator
    broker: ReferenceBroker
    allowed_targets: Mapping[str, tuple[str, ...]]
    required_client_role: str = "desktop-user"

    def __post_init__(self) -> None:
        if not self.required_client_role:
            raise KeycloakError("required_client_role is required")

    def launch_token(self, token: str, target: str) -> dict[str, Any]:
        identity = self.authenticator.validate_token(token)
        if self.required_client_role not in identity.client_roles:
            raise BrokerError("Keycloak identity is not authorized for desktop use")

        broker_user = self.broker.users.get(identity.username)
        if broker_user is None or broker_user.subject != identity.subject:
            raise BrokerError("Keycloak identity is not mapped to a broker user")
        if target not in self.allowed_targets.get(identity.username, ()):
            raise BrokerError("Keycloak identity is not authorized for target")

        context = AuthContext(
            auth_method=identity.auth_method,
            assurance_level=identity.assurance,
            device_trust="unknown",
        )
        return self.broker.launch_connection(
            identity.username, target, auth_context=context
        )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise KeycloakError(f"{name} must be an object")
    return value


def _required_string(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise KeycloakError(f"{name} must be a non-empty string")
    return _bounded_string(value, name)


def _bounded_string(value: str, name: str) -> str:
    if len(value.encode("utf-8")) > MAX_CLAIM_LENGTH:
        raise KeycloakError(f"{name} exceeds configured length")
    return value


def _string_list(
    value: Any,
    name: str,
    *,
    max_items: int = MAX_CLAIM_ITEMS,
    max_length: int = MAX_CLAIM_LENGTH,
    unique: bool = False,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise KeycloakError(f"{name} must be an array")
    if len(value) > max_items:
        raise KeycloakError(f"{name} has too many values")
    result = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise KeycloakError(f"{name} values must be non-empty strings")
        if len(item.encode("utf-8")) > max_length:
            raise KeycloakError(f"{name} exceeds configured length")
        result.append(item)
    if unique and len(result) != len(set(result)):
        raise KeycloakError(f"{name} contains duplicate values")
    return tuple(result)


def _broker_subject(issuer: str, subject: str) -> str:
    digest = hashlib.sha256(f"{issuer}\0{subject}".encode("utf-8")).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"keycloak:{encoded}"
