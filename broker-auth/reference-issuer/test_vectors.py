"""Generate broker-assertion interoperability vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from broker_issuer import build_claims, generate_rsa_keypair, sign_claims

KID = "reference-2026-01"


def _tamper_signature(token: str) -> str:
    head, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return ".".join((head, payload, replacement + signature[1:]))


def generate_vectors(output_dir: Path, now: int = 1700000000) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_rsa_keypair()
    base = build_claims(
        issuer="https://broker.example.test",
        audience="xrdp-sesman",
        subject="user-1234",
        preferred_username="alice",
        groups=["remote-desktop", "engineering"],
        roles=["desktop-user"],
        target="rdp-host.example.test",
        session_id="broker-session-0001",
        auth_context={"acr": "urn:example:mfa", "amr": ["pwd", "otp"]},
        now=now,
        lifetime=300,
        jti="00000000-0000-4000-8000-000000000001",
    )

    vectors: list[dict[str, Any]] = []

    def add(name: str, claims: dict[str, Any], valid: bool, reason: str) -> None:
        vectors.append(
            {
                "name": name,
                "expected_valid": valid,
                "reason": reason,
                "claims": claims,
                "token": sign_claims(
                    claims, private_key, key_id=KID, validate=valid
                ),
            }
        )

    add("valid", dict(base), True, "valid assertion")

    expired = dict(base)
    expired.update({"iat": now - 600, "nbf": now - 600, "exp": now - 300})
    add("expired", expired, False, "exp is in the past")

    wrong_audience = dict(base)
    wrong_audience["aud"] = "other-service"
    add("wrong-audience", wrong_audience, False, "audience mismatch")

    wrong_target = dict(base)
    wrong_target["target"] = "other-host.example.test"
    add("wrong-target", wrong_target, False, "target mismatch")

    missing_jti = dict(base)
    del missing_jti["jti"]
    add("missing-jti", missing_jti, False, "required jti is absent")

    tampered = sign_claims(base, private_key, key_id=KID)
    vectors.append(
        {
            "name": "tampered-signature",
            "expected_valid": False,
            "reason": "signature does not verify",
            "claims": base,
            "token": _tamper_signature(tampered),
        }
    )

    (output_dir / "public-key.pem").write_bytes(public_key)
    (output_dir / "vectors.json").write_text(
        json.dumps(
            {
                "algorithm": "RS256",
                "kid": KID,
                "validation_time": now,
                "expected_issuer": base["iss"],
                "expected_audience": base["aud"],
                "expected_target": base["target"],
                "vectors": vectors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    generate_vectors(Path(__file__).resolve().parents[1] / "tests" / "vectors")
