#!/usr/bin/env python3
"""Reference issuer for XRDP broker assertions."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jsonschema import Draft202012Validator

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "spec"
    / "broker-assertion.schema.json"
)
DEFAULT_LIFETIME = 300


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        schema = json.load(stream)
    Draft202012Validator.check_schema(schema)
    return schema


def validate_claims(
    claims: Mapping[str, Any], schema: Mapping[str, Any] | None = None
) -> None:
    """Validate structural and temporal invariants before signing."""
    Draft202012Validator(schema or load_schema()).validate(dict(claims))
    if claims["nbf"] < claims["iat"]:
        raise ValueError("nbf must not precede iat")
    if claims["exp"] <= claims["nbf"]:
        raise ValueError("exp must be later than nbf")


def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    if bits < 2048:
        raise ValueError("RSA keys must be at least 2048 bits")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def build_claims(
    *,
    issuer: str,
    audience: str | Sequence[str],
    subject: str,
    preferred_username: str,
    groups: Sequence[str],
    roles: Sequence[str],
    target: str,
    session_id: str,
    auth_context: Mapping[str, Any],
    now: int | None = None,
    lifetime: int = DEFAULT_LIFETIME,
    jti: str | None = None,
) -> dict[str, Any]:
    issued_at = int(time.time()) if now is None else int(now)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "preferred_username": preferred_username,
        "groups": list(groups),
        "roles": list(roles),
        "auth_method": list(auth_context.get("amr", ["unknown"])),
        "assurance_level": str(auth_context.get("acr", "unknown")),
        "broker_session_id": session_id,
        "target": target,
        "device_trust": {
            "status": str(auth_context.get("device_trust", "unknown"))
        },
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + lifetime,
        "jti": jti or str(uuid.uuid4()),
    }
    validate_claims(claims)
    return claims


def sign_claims(
    claims: Mapping[str, Any],
    private_key: bytes | str,
    *,
    key_id: str,
    validate: bool = True,
) -> str:
    if validate:
        validate_claims(claims)
    return jwt.encode(
        dict(claims),
        private_key,
        algorithm="RS256",
        headers={"kid": key_id, "typ": "baf+jwt"},
    )


def write_keypair(private_path: Path, public_path: Path, bits: int) -> None:
    private_pem, public_pem = generate_rsa_keypair(bits)
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)
    public_path.write_bytes(public_pem)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="generate an RSA key pair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    keygen.add_argument("--bits", type=int, default=2048)

    issue = commands.add_parser("issue", help="issue one broker assertion")
    issue.add_argument("--private-key", type=Path, required=True)
    issue.add_argument("--kid", required=True)
    issue.add_argument("--issuer", required=True)
    issue.add_argument("--audience", action="append", required=True)
    issue.add_argument("--subject", required=True)
    issue.add_argument("--username", required=True)
    issue.add_argument("--group", action="append", default=[])
    issue.add_argument("--role", action="append", default=[])
    issue.add_argument("--target", required=True)
    issue.add_argument("--session-id", required=True)
    issue.add_argument("--auth-context", type=json.loads, required=True)
    issue.add_argument("--lifetime", type=int, default=DEFAULT_LIFETIME)
    issue.add_argument("--jti")

    vectors = commands.add_parser(
        "vectors", help="generate valid and invalid signed test vectors"
    )
    vectors.add_argument("--output-dir", type=Path, required=True)
    vectors.add_argument("--now", type=int, default=1700000000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "keygen":
        write_keypair(args.private_key, args.public_key, args.bits)
        return 0
    if args.command == "vectors":
        from test_vectors import generate_vectors

        generate_vectors(args.output_dir, args.now)
        return 0

    audience: str | list[str]
    audience = args.audience[0] if len(args.audience) == 1 else args.audience
    claims = build_claims(
        issuer=args.issuer,
        audience=audience,
        subject=args.subject,
        preferred_username=args.username,
        groups=args.group,
        roles=args.role,
        target=args.target,
        session_id=args.session_id,
        auth_context=args.auth_context,
        lifetime=args.lifetime,
        jti=args.jti,
    )
    token = sign_claims(
        claims, args.private_key.read_bytes(), key_id=args.kid
    )
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
