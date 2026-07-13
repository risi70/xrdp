#!/usr/bin/env python3
"""Tests for the Keycloak (OIDC) reference authenticator.

Covers the claim mapping (pure) and token verification (offline: a fake JWKS
client returns a locally generated key, so no Keycloak/network is needed).
"""

import time
import sys
import unittest
from pathlib import Path

import jwt

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-issuer"))

from keycloak_auth import KeycloakAuthenticator, KeycloakError  # noqa: E402
from broker_issuer import generate_rsa_keypair  # noqa: E402


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJwkClient:
    """Stand-in for PyJWKClient that returns a fixed local key (no network)."""

    def __init__(self, public_pem):
        self._public_pem = public_pem

    def get_signing_key_from_jwt(self, token):
        return _FakeSigningKey(self._public_pem)


class KeycloakClaimMappingTests(unittest.TestCase):
    def setUp(self):
        self.kc = KeycloakAuthenticator(
            "https://keycloak.example.com", "vdi", "baf-broker")

    def test_group_paths_reduced_to_leaf_and_roles_merged(self):
        ident = self.kc.identity_from_claims({
            "preferred_username": "alice",
            "sub": "abc-123",
            "groups": ["/vdi/users", "/staff", ""],
            "realm_access": {"roles": ["desktop-user", "offline_access"]},
            "resource_access": {"baf-broker": {"roles": ["viewer"]}},
            "amr": ["pwd", "otp"],
            "acr": "gold",
        })
        self.assertEqual(ident.username, "alice")
        self.assertEqual(ident.subject, "keycloak-abc-123")
        self.assertEqual(ident.groups, ["staff", "users"])
        self.assertEqual(ident.roles,
                         ["desktop-user", "offline_access", "viewer"])
        self.assertEqual(ident.auth_method, ["pwd", "otp"])
        self.assertEqual(ident.assurance, "gold")

    def test_defaults_when_optional_claims_absent(self):
        ident = self.kc.identity_from_claims({"preferred_username": "bob"})
        self.assertEqual(ident.username, "bob")
        self.assertEqual(ident.subject, "keycloak-bob")  # sub falls back to name
        self.assertEqual(ident.groups, [])
        self.assertEqual(ident.roles, [])
        self.assertEqual(ident.auth_method, ["pwd"])
        self.assertEqual(ident.assurance, "unknown")

    def test_client_roles_excluded_when_disabled(self):
        kc = KeycloakAuthenticator(
            "https://keycloak.example.com", "vdi", "baf-broker",
            include_client_roles=False)
        ident = kc.identity_from_claims({
            "preferred_username": "carol",
            "realm_access": {"roles": ["desktop-user"]},
            "resource_access": {"baf-broker": {"roles": ["viewer"]}},
        })
        self.assertEqual(ident.roles, ["desktop-user"])

    def test_missing_username_and_sub_fails_closed(self):
        with self.assertRaises(KeycloakError):
            self.kc.identity_from_claims({"groups": ["/vdi"]})

    def test_constructor_requires_core_fields(self):
        with self.assertRaises(KeycloakError):
            KeycloakAuthenticator("", "vdi", "baf-broker")


class KeycloakTokenVerificationTests(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_rsa_keypair()
        self.kc = KeycloakAuthenticator(
            "https://keycloak.example.com", "vdi", "baf-broker")
        # inject the offline key source
        self.kc._jwk_client = _FakeJwkClient(self.public_pem)

    def _token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": self.kc.issuer,
            "sub": "user-uuid",
            "preferred_username": "dave",
            "groups": ["/vdi"],
            "realm_access": {"roles": ["desktop-user"]},
            "amr": ["pwd"],
            "acr": "silver",
            "iat": now,
            "exp": now + 300,
            "aud": "baf-broker",
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_pem, algorithm="RS256",
                          headers={"kid": "test-key"})

    def test_valid_token_maps_to_identity(self):
        ident = self.kc.validate_token(self._token())
        self.assertEqual(ident.username, "dave")
        self.assertEqual(ident.groups, ["vdi"])
        self.assertEqual(ident.roles, ["desktop-user"])
        self.assertEqual(ident.assurance, "silver")

    def test_expired_token_rejected(self):
        now = int(time.time())
        with self.assertRaises(KeycloakError):
            self.kc.validate_token(self._token(exp=now - 10, iat=now - 300))

    def test_wrong_issuer_rejected(self):
        with self.assertRaises(KeycloakError):
            self.kc.validate_token(self._token(iss="https://evil.example.com"))

    def test_tampered_signature_rejected(self):
        token = self._token()
        tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
        with self.assertRaises(KeycloakError):
            self.kc.validate_token(tampered)

    def test_empty_token_rejected(self):
        with self.assertRaises(KeycloakError):
            self.kc.validate_token("")


if __name__ == "__main__":
    unittest.main()
