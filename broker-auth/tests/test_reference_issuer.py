#!/usr/bin/env python3

import json
import sys
import tempfile
import unittest
from pathlib import Path

import jwt
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference-issuer"))

from broker_issuer import (
    build_claims,
    generate_rsa_keypair,
    sign_claims,
    validate_claims,
)
from test_vectors import generate_vectors


class ReferenceIssuerTests(unittest.TestCase):
    def test_rs256_round_trip_and_required_claims(self):
        private_key, public_key = generate_rsa_keypair()
        claims = build_claims(
            issuer="https://issuer.test",
            audience="xrdp-sesman",
            subject="subject-1",
            preferred_username="alice",
            groups=["users"],
            roles=["desktop-user"],
            target="host.test",
            session_id="session-1",
            auth_context={"acr": "mfa"},
            now=1700000000,
            jti="jti-123456789012",
        )
        token = sign_claims(claims, private_key, key_id="key-1")
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="xrdp-sesman",
            issuer="https://issuer.test",
            options={"verify_exp": False, "verify_nbf": False},
        )
        self.assertEqual(decoded, claims)

    def test_schema_rejects_missing_required_claim(self):
        private_key, _ = generate_rsa_keypair()
        with self.assertRaises(ValidationError):
            sign_claims({}, private_key, key_id="key-1")

    def test_vectors_cover_valid_and_invalid_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            generate_vectors(output)
            document = json.loads(
                (output / "vectors.json").read_text(encoding="utf-8")
            )
            names = {item["name"] for item in document["vectors"]}
            self.assertIn("valid", names)
            self.assertIn("expired", names)
            self.assertIn("wrong-audience", names)
            self.assertIn("wrong-target", names)
            self.assertIn("missing-jti", names)
            self.assertIn("tampered-signature", names)
            self.assertTrue(
                any(item["expected_valid"] for item in document["vectors"])
            )
            self.assertTrue(
                any(not item["expected_valid"] for item in document["vectors"])
            )
            public_key = (output / "public-key.pem").read_bytes()
            for vector in document["vectors"]:
                valid = True
                try:
                    claims = jwt.decode(
                        vector["token"],
                        public_key,
                        algorithms=["RS256"],
                        audience=document["expected_audience"],
                        issuer=document["expected_issuer"],
                        options={"verify_exp": False, "verify_nbf": False},
                    )
                    validate_claims(claims)
                    if claims["exp"] <= document["validation_time"]:
                        valid = False
                    if claims["target"] != document["expected_target"]:
                        valid = False
                except (jwt.PyJWTError, ValidationError, ValueError, KeyError):
                    valid = False
                self.assertEqual(
                    valid, vector["expected_valid"], msg=vector["name"]
                )


if __name__ == "__main__":
    unittest.main()
