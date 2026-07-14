"""Keycloak (OIDC) authentication for the reference broker.

Models the "Keycloak -> broker -> Broker-RDP Handle" flow described in the deployment
guide (§5.2): Keycloak is the identity provider that authenticates the user;
this module turns a Keycloak-issued OIDC token into the identity fields the
BAF issuer needs (username, groups, roles, auth method, assurance). The broker
then mints and signs the BAF assertion with its *own* key exactly as for any
other authenticated user.

Two entry points, both non-interactive so they suit a headless broker/CLI:

- ``validate_token(token)`` — the front-end already obtained a Keycloak OIDC
  token (ID or access token). This is the realistic broker behaviour: consume
  and verify the token, don't re-authenticate. The token is verified against
  the realm JWKS (signature, issuer, expiry).
- ``password_login(username, password, otp=...)`` — Resource Owner Password
  (Keycloak "Direct access grants") for self-contained/testing use: the broker
  posts the credentials to the realm token endpoint and then verifies the
  returned token exactly as above.

Keycloak is *not* the issuer XRDP trusts: XRDP validates the broker's assertion
against a local RS256 TrustAnchor. This module never produces the BAF assertion
and performs no XRDP-side authorization; production identity binding, UID 0
rejection and PAM approval still happen in xrdp-sesexec.

Depends only on PyJWT (JWKS + verification) and the standard library, so it adds
no dependency beyond what the reference issuer already needs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping

import jwt
from jwt import PyJWKClient

DEFAULT_ALGORITHMS = ("RS256", "ES256")
DEFAULT_TIMEOUT = 10


class KeycloakError(ValueError):
    """Raised when Keycloak authentication fails. Fail closed."""


@dataclass
class KeycloakIdentity:
    """The identity extracted from a verified Keycloak token."""

    username: str
    subject: str
    groups: list[str]
    roles: list[str]
    auth_method: list[str]
    assurance: str
    claims: dict[str, Any] = field(default_factory=dict)


class KeycloakAuthenticator:
    """Verifies Keycloak OIDC tokens and maps their claims to a BAF identity."""

    def __init__(self, base_url: str, realm: str, client_id: str, *,
                 client_secret: str | None = None,
                 audience: str | None = None,
                 verify_audience: bool = False,
                 include_client_roles: bool = True,
                 algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS,
                 timeout: int = DEFAULT_TIMEOUT):
        if not base_url or not realm or not client_id:
            raise KeycloakError("base_url, realm and client_id are required")
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.verify_audience = verify_audience
        self.include_client_roles = include_client_roles
        self.algorithms = list(algorithms)
        self.timeout = timeout
        self.issuer = f"{self.base_url}/realms/{realm}"
        self.jwks_uri = f"{self.issuer}/protocol/openid-connect/certs"
        self.token_endpoint = f"{self.issuer}/protocol/openid-connect/token"
        self._jwk_client: PyJWKClient | None = None

    # -- verification -----------------------------------------------------
    def validate_token(self, token: str) -> KeycloakIdentity:
        """Verify a Keycloak-issued JWT and return the mapped identity."""
        if not token:
            raise KeycloakError("empty token")
        try:
            if self._jwk_client is None:
                self._jwk_client = PyJWKClient(self.jwks_uri,
                                               timeout=self.timeout)
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience if self.verify_audience else None,
                options={"verify_aud": self.verify_audience,
                         "require": ["exp", "iss"]},
            )
        except KeycloakError:
            raise
        except Exception as exc:  # jwt.*Error, urllib errors, etc.
            raise KeycloakError(f"token verification failed: {exc}") from exc
        return self.identity_from_claims(claims)

    # -- direct grant (ROPC) ---------------------------------------------
    def password_login(self, username: str, password: str, *,
                       otp: str | None = None,
                       scope: str = "openid") -> KeycloakIdentity:
        """Authenticate via the Keycloak Direct Access Grant, then verify."""
        if not username or not password:
            raise KeycloakError("username and password are required")
        form = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": username,
            "password": password,
            "scope": scope,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        if otp:
            form["totp"] = otp
        body = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(
            self.token_endpoint, data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            # Keycloak returns error/error_description JSON; do not leak the body
            # verbatim (may echo input), but surface the OAuth error code.
            code = _oauth_error(exc)
            raise KeycloakError(f"direct grant rejected ({exc.code} {code})") \
                from exc
        except Exception as exc:
            raise KeycloakError(f"direct grant failed: {exc}") from exc
        token = payload.get("id_token") or payload.get("access_token")
        if not token:
            raise KeycloakError("Keycloak returned no id_token/access_token")
        return self.validate_token(token)

    # -- claim mapping (pure; unit-testable without network) --------------
    def identity_from_claims(self, claims: Mapping[str, Any]) -> KeycloakIdentity:
        """Map verified OIDC claims to the BAF identity fields."""
        username = claims.get("preferred_username") or claims.get("sub")
        if not isinstance(username, str) or not username:
            raise KeycloakError("token has no preferred_username/sub")

        # Keycloak group paths look like "/vdi/users"; BAF group names are the
        # leaf segments, matching the VDI's NSS/SSSD group names.
        groups = sorted({g.rstrip("/").rsplit("/", 1)[-1]
                         for g in _as_str_list(claims.get("groups")) if g})

        roles = set(_as_str_list(
            (claims.get("realm_access") or {}).get("roles")))
        if self.include_client_roles:
            resource_access = claims.get("resource_access") or {}
            for entry in resource_access.values():
                if isinstance(entry, Mapping):
                    roles.update(_as_str_list(entry.get("roles")))

        auth_method = _as_str_list(claims.get("amr")) or ["pwd"]
        assurance = str(claims.get("acr") or "unknown")
        subject = "keycloak-" + str(claims.get("sub") or username)

        return KeycloakIdentity(
            username=username,
            subject=subject,
            groups=groups,
            roles=sorted(roles),
            auth_method=auth_method,
            assurance=assurance,
            claims=dict(claims),
        )


def _as_str_list(value: Any) -> list[str]:
    """Coerce a claim to a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return [str(value)]


def _oauth_error(exc: urllib.error.HTTPError) -> str:
    """Best-effort extraction of the OAuth error code from a token error."""
    try:
        data = json.loads(exc.read().decode(errors="replace"))
        return str(data.get("error", "invalid_grant"))
    except Exception:
        return "invalid_grant"
