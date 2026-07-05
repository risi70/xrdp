#!/usr/bin/env python3
"""Regenerate the deterministic BAF Phase 2 conformance corpus."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

import jwt


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIVATE_KEY = REPO_ROOT / "tests/baf/data/test-private.pem"
DEFAULT_PUBLIC_KEY = REPO_ROOT / "tests/baf/data/test-public.pem"
DEFAULT_OUTPUT = REPO_ROOT / "broker-auth/vectors"

NOW = 1_700_000_000
ISSUER = "https://issuer.example.test"
AUDIENCE = "urn:baf:xrdp:test"
TARGET = "urn:baf:desktop:test"
KID = "test-rsa-1"

DESCRIPTIONS = {
    "valid-rs256": "Complete, correctly signed RS256 BAF assertion.",
    "expired": "Correctly signed assertion whose expiration precedes the fixed clock.",
    "not-yet-valid": "Correctly signed assertion whose not-before time exceeds allowed skew.",
    "lifetime-too-long": "Correctly signed assertion exceeding the configured maximum lifetime.",
    "wrong-issuer": "Correctly signed assertion with a different issuer.",
    "wrong-audience": "Correctly signed assertion without the expected audience.",
    "wrong-target": "Correctly signed assertion bound to a different desktop target.",
    "missing-mandatory-claim": "Correctly signed assertion missing preferred_username.",
    "unknown-kid": "Correctly signed assertion naming an unconfigured key identifier.",
    "unknown-crit": "Correctly signed assertion with an unsupported critical header.",
    "jku-header": "Correctly signed assertion containing a token-controlled JWK URL.",
    "x5u-header": "Correctly signed assertion containing a token-controlled certificate URL.",
    "embedded-jwk": "Correctly signed assertion containing an embedded token key.",
    "alg-none": "Unsecured JWT using alg none.",
    "mac-hs256": "JWT signed with the prohibited HS256 MAC algorithm.",
    "bad-signature": "Structurally valid RS256 assertion with a corrupted signature.",
    "duplicate-json-member": "Compact JWS with duplicate alg protected-header members.",
    "replayed-jti": "Second validation of the valid vector with the same issuer and JTI.",
    "oversized-assertion": "Input exceeding the default maximum encoded assertion size.",
    "malformed-compact": "Input with fewer than three compact-JWS segments.",
    "invalid-base64url": "Compact JWS containing forbidden base64url padding.",
    "ps256-unsupported": "Compact JWS declaring deferred PS256.",
    "es256-unsupported": "Compact JWS declaring deferred ES256.",
}

REASONS = {
    "valid-rs256": "Valid RS256 BAF assertion.",
    "expired": "exp is before the fixed validation time.",
    "not-yet-valid": "nbf is beyond the permitted clock skew.",
    "lifetime-too-long": "exp - iat exceeds max_lifetime.",
    "wrong-issuer": "iss does not exactly match configured issuer.",
    "wrong-audience": "aud does not contain configured audience.",
    "wrong-target": "target does not exactly match local target.",
    "missing-mandatory-claim": "preferred_username is absent.",
    "unknown-kid": "kid is not in the issuer-bound trust set.",
    "unknown-crit": "crit names an unsupported protected header.",
    "jku-header": "Token-controlled key URL is prohibited.",
    "x5u-header": "Token-controlled certificate URL is prohibited.",
    "embedded-jwk": "Token-controlled embedded key is prohibited.",
    "alg-none": "Unsecured JWT algorithm is prohibited.",
    "mac-hs256": "MAC algorithms are prohibited.",
    "bad-signature": "Signature octets do not verify.",
    "duplicate-json-member": "Protected header contains duplicate alg members.",
    "replayed-jti": "Second reservation of the same (iss,jti) must fail.",
    "oversized-assertion": "Encoded assertion exceeds the 16 KiB default.",
    "malformed-compact": "Compact serialization has the wrong segment count.",
    "invalid-base64url": "Protected segment contains forbidden padding.",
    "ps256-unsupported": "PS256 is a future extension and unsupported in Phase 2.",
    "es256-unsupported": "ES256 is a future extension and unsupported in Phase 2.",
}


def _base_claims() -> dict[str, Any]:
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "subject-1",
        "preferred_username": "alice",
        "groups": ["engineering"],
        "roles": ["desktop-user"],
        "auth_method": ["pwd", "otp"],
        "assurance_level": "urn:test:aal2",
        "broker_session_id": "session-1",
        "target": TARGET,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 100,
        "jti": "0123456789abcdef",
        "device_trust": {"status": "trusted"},
    }


def generate(private_key: bytes) -> dict[str, Any]:
    base = _base_claims()

    def sign(
        claims: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        algorithm: str = "RS256",
        key: bytes | str = private_key,
    ) -> str:
        return jwt.encode(
            base if claims is None else claims,
            key,
            algorithm=algorithm,
            headers={"kid": KID, "typ": "baf+jwt", **(headers or {})},
        )

    vectors: list[dict[str, Any]] = []

    def add(name: str, token: str, status: str = "invalid") -> None:
        vector: dict[str, Any] = {
            "name": name,
            "expected_status": status,
            "token": token,
            "expected_result": {
                "success": "accepted",
                "invalid": "rejected",
                "replay": "replay-rejected",
            }[status],
            "reason": REASONS[name],
            "static": True,
            "expected_validator_status": status,
            "description": DESCRIPTIONS[name],
            "validator_config_overrides": {},
        }
        vectors.append(vector)

    valid = sign()
    add("valid-rs256", valid, "success")

    mutations = (
        ("expired", {"iat": NOW - 200, "nbf": NOW - 200, "exp": NOW - 100}),
        ("not-yet-valid", {"nbf": NOW + 60}),
        ("lifetime-too-long", {"exp": NOW + 301}),
        ("wrong-issuer", {"iss": "https://wrong.example.test"}),
        ("wrong-audience", {"aud": "wrong"}),
        ("wrong-target", {"target": "wrong"}),
    )
    for name, changes in mutations:
        claims = dict(base)
        claims.update(changes)
        claims["jti"] = (name.replace("-", "") + "0" * 32)[:32]
        add(name, sign(claims))

    missing = dict(base)
    del missing["preferred_username"]
    add("missing-mandatory-claim", sign(missing))

    header_cases = (
        ("unknown-kid", {"kid": "unknown"}),
        ("unknown-crit", {"crit": ["unknown"]}),
        ("jku-header", {"jku": "https://attacker.invalid/jwks"}),
        ("x5u-header", {"x5u": "https://attacker.invalid/cert"}),
        ("embedded-jwk", {"jwk": {"kty": "RSA", "n": "AA", "e": "AQAB"}}),
    )
    for name, headers in header_cases:
        add(name, sign(headers=headers))

    add(
        "alg-none",
        jwt.encode(base, "", algorithm="none",
                   headers={"kid": KID, "typ": "baf+jwt"}),
    )
    add(
        "mac-hs256",
        jwt.encode(base, "test-secret-test-secret-1234567890", algorithm="HS256",
                   headers={"kid": KID, "typ": "baf+jwt"}),
    )
    prefix, signature = valid.rsplit(".", 1)
    replacement = "A" if signature[0] != "A" else "B"
    add("bad-signature", prefix + "." + replacement + signature[1:])

    duplicate = (
        '{"alg":"RS256","alg":"RS256","kid":"test-rsa-1",'
        '"typ":"baf+jwt"}'
    ).encode()
    add(
        "duplicate-json-member",
        base64.urlsafe_b64encode(duplicate).rstrip(b"=").decode() + ".e30.AA",
    )
    add("replayed-jti", valid, "replay")
    vectors[-1]["generation_parameters"] = {
        "sequence": [
            "validate valid-rs256 once",
            "validate this identical token before replay expiry",
        ]
    }
    add("oversized-assertion", "a" * 16385)
    add("malformed-compact", "only.two")
    add("invalid-base64url", "a=.e30.AA")

    payload = valid.split(".")[1]
    for name, algorithm in (
        ("ps256-unsupported", "PS256"),
        ("es256-unsupported", "ES256"),
    ):
        header = json.dumps(
            {"alg": algorithm, "kid": KID, "typ": "baf+jwt"},
            separators=(",", ":"),
        ).encode()
        token = (
            base64.urlsafe_b64encode(header).rstrip(b"=").decode()
            + "." + payload + ".AA"
        )
        add(name, token)

    return {
        "profile": "BAF 1.0",
        "media_type": "application/baf+jwt",
        "validation_time": NOW,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "target": TARGET,
        "kid": KID,
        "vectors": vectors,
        "vector_format": "BAF phase2 static corpus v1",
        "usage": (
            "Validate at validation_time with the bundled public key; "
            "replayed-jti requires the documented sequence."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    document = generate(args.private_key.read_bytes())
    (args.output_dir / "phase2-vectors.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "test-public.pem").write_bytes(
        args.public_key.read_bytes()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
