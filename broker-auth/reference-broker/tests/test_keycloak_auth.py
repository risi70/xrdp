#!/usr/bin/env python3
"""Offline tests for the Keycloak reference-broker adapter."""

import sys
import time
import unittest
from pathlib import Path

import jwt

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-issuer"))

from broker_issuer import generate_rsa_keypair  # noqa: E402
from keycloak_auth import (  # noqa: E402
    KeycloakAuthenticator,
    KeycloakBrokerAdapter,
    KeycloakError,
)
from reference_broker import (  # noqa: E402
    BrokerError,
    BrokerTarget,
    BrokerUser,
    LocalAuthorizationPolicy,
    ReferenceBroker,
)


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJwkClient:
    def __init__(self, public_pem):
        self.public_pem = public_pem

    def get_signing_key_from_jwt(self, _token):
        return _FakeSigningKey(self.public_pem)


class KeycloakTests(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_rsa_keypair()
        self.authenticator = KeycloakAuthenticator(
            "https://keycloak.example.test", "vdi", "baf-broker"
        )
        self.authenticator._jwk_client = _FakeJwkClient(self.public_pem)

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": self.authenticator.issuer,
            "sub": "user-uuid",
            "preferred_username": "alice",
            "aud": "baf-broker",
            "azp": "baf-broker",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
            "groups": ["/vdi/users"],
            "realm_access": {"roles": ["desktop-user"]},
            "resource_access": {
                "baf-broker": {"roles": ["desktop-launch", "desktop-user"]},
                "other-client": {"roles": ["ignored"]},
            },
            "amr": ["pwd", "otp"],
            "acr": "gold",
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            self.private_pem,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def test_valid_token_is_strictly_mapped(self):
        identity = self.authenticator.validate_token(self.token())
        self.assertEqual(identity.username, "alice")
        self.assertTrue(identity.subject.startswith("keycloak:"))
        self.assertEqual(len(identity.subject), 52)
        self.assertEqual(identity.groups, ("/vdi/users",))
        self.assertEqual(
            identity.roles, ("desktop-launch", "desktop-user")
        )
        self.assertEqual(identity.auth_method, ("pwd", "otp"))

    def test_missing_amr_does_not_invent_password_authentication(self):
        identity = self.authenticator.validate_token(self.token(amr=None))
        self.assertEqual(identity.auth_method, ("oidc",))

    def test_missing_or_wrong_audience_is_rejected(self):
        for audience in (None, "another-client"):
            with self.subTest(audience=audience), self.assertRaises(KeycloakError):
                self.authenticator.validate_token(self.token(aud=audience))

    def test_multiple_audiences_require_matching_authorized_party(self):
        valid = self.token(aud=["baf-broker", "account"], azp="baf-broker")
        self.authenticator.validate_token(valid)
        invalid = self.token(aud=["baf-broker", "account"], azp="account")
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(invalid)

    def test_single_audience_requires_matching_authorized_party(self):
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(self.token(azp="account"))

    def test_access_token_profile_is_required(self):
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(self.token(typ="ID"))

    def test_required_identity_claims_are_rejected_when_missing(self):
        for claim in ("sub", "preferred_username"):
            with self.subTest(claim=claim), self.assertRaises(KeycloakError):
                self.authenticator.validate_token(self.token(**{claim: None}))

    def test_malformed_structured_claims_are_rejected(self):
        cases = (
            {"groups": "vdi"},
            {"realm_access": []},
            {"resource_access": []},
            {"amr": ["pwd", 1]},
        )
        for claims in cases:
            with self.subTest(claims=claims), self.assertRaises(KeycloakError):
                self.authenticator.validate_token(self.token(**claims))

    def test_expired_wrong_issuer_and_tampered_tokens_are_rejected(self):
        now = int(time.time())
        tokens = [
            self.token(exp=now - 1),
            self.token(iss="https://wrong.example.test/realms/vdi"),
        ]
        valid = self.token()
        tokens.append(valid[:-4] + "AAAA")
        for token in tokens:
            with self.assertRaises(KeycloakError):
                self.authenticator.validate_token(token)

    def test_token_lifetime_is_bounded(self):
        now = int(time.time())
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(
                self.token(iat=now, exp=now + 901)
            )

    def test_token_and_claim_limits_are_enforced(self):
        small = KeycloakAuthenticator(
            "https://keycloak.example.test",
            "vdi",
            "baf-broker",
            max_token_bytes=16,
        )
        with self.assertRaises(KeycloakError):
            small.validate_token(self.token())
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(
                self.token(groups=["g"] * 65)
            )
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(
                self.token(amr=[f"method-{i}" for i in range(17)])
            )
        with self.assertRaises(KeycloakError):
            self.authenticator.validate_token(self.token(amr=["pwd", "pwd"]))

    def test_duplicate_groups_are_deduplicated(self):
        # Keycloak emits duplicate leaf names when "Full group path" is
        # disabled and same-named subgroups exist; this must not deny login.
        identity = self.authenticator.validate_token(
            self.token(groups=["/vdi/users", "/vdi/users"])
        )
        self.assertEqual(identity.groups, ("/vdi/users",))

    def test_symmetric_and_disabled_algorithms_are_rejected(self):
        for algorithms in (("none",), ("HS256",), ("RS256", "HS256"), ()):
            with self.subTest(algorithms=algorithms), \
                    self.assertRaises(KeycloakError):
                KeycloakAuthenticator(
                    "https://keycloak.example.test",
                    "vdi",
                    "baf-broker",
                    algorithms=algorithms,
                )

    def test_subject_binding_includes_issuer(self):
        claims = {
            "sub": "same-subject",
            "preferred_username": "alice",
        }
        first = self.authenticator.identity_from_claims(claims)
        other = KeycloakAuthenticator(
            "https://other-keycloak.example.test", "vdi", "baf-broker"
        ).identity_from_claims(claims)
        self.assertNotEqual(first.subject, other.subject)

    def test_https_is_required_outside_tests(self):
        with self.assertRaises(KeycloakError):
            KeycloakAuthenticator("http://keycloak", "vdi", "baf-broker")
        KeycloakAuthenticator(
            "http://keycloak",
            "vdi",
            "baf-broker",
            allow_http_for_tests=True,
        )

    def test_broker_adapter_enforces_role_user_mapping_and_target_policy(self):
        broker_private, _ = generate_rsa_keypair()
        identity = self.authenticator.validate_token(self.token())
        user = BrokerUser(
            subject=identity.subject,
            username="alice",
            roles=("desktop-user",),
        )
        broker = ReferenceBroker(
            issuer="https://broker.example.test",
            key_id="broker-key",
            private_key=broker_private,
            default_audience="xrdp",
            targets={
                "vdi-1": BrokerTarget("vdi-1", "vdi-1.example.test", "xrdp"),
                "vdi-2": BrokerTarget("vdi-2", "vdi-2.example.test", "xrdp"),
            },
            users={"alice": user},
            policy=LocalAuthorizationPolicy({"alice": user}),
        )
        adapter = KeycloakBrokerAdapter(
            self.authenticator, broker, {"alice": ("vdi-1",)}
        )
        result = adapter.launch_token(self.token(), "vdi-1")
        self.assertEqual(result["target"], "vdi-1")

        with self.assertRaises(BrokerError):
            adapter.launch_token(
                self.token(resource_access={
                    "baf-broker": {"roles": ["viewer"]}
                }), "vdi-1"
            )
        with self.assertRaises(BrokerError):
            adapter.launch_token(
                self.token(preferred_username="unknown"), "vdi-1"
            )
        with self.assertRaises(BrokerError):
            adapter.launch_token(self.token(), "vdi-2")
        with self.assertRaises(KeycloakError):
            KeycloakBrokerAdapter(
                self.authenticator,
                broker,
                {"alice": ("vdi-1",)},
                required_client_role="",
            )


if __name__ == "__main__":
    unittest.main()
