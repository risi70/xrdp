#!/usr/bin/env python3
"""Issue a generic BAF assertion for Phase 5 interoperability tests."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

REFERENCE_ISSUER = Path(__file__).resolve().parents[1] / "reference-issuer"
if str(REFERENCE_ISSUER) not in sys.path:
    sys.path.insert(0, str(REFERENCE_ISSUER))

from broker_issuer import build_claims, sign_claims


def _split_csv_items(values: Sequence[str]) -> list[str]:
    """Split comma-separated entries so CLI and config forms behave alike."""
    return [
        part.strip()
        for value in values
        for part in value.split(",")
        if part.strip()
    ]


def _load_simple_config(path: Path | None) -> dict[str, Any]:
    """Load a minimal YAML-like key/value config without external deps."""
    if path is None:
        return {}
    result: dict[str, Any] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"unsupported config line: {raw_line!r}")
        key, value = line.split(":", 1)
        value = value.strip().strip('"').strip("'")
        if "," in value:
            result[key.strip()] = _split_csv_items([value])
        else:
            result[key.strip()] = value
    return result


def _value(
    args: argparse.Namespace,
    config: dict[str, Any],
    name: str,
    default: Any = None,
) -> Any:
    value = getattr(args, name)
    return config.get(name, default) if value is None else value


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path)
    p.add_argument("--private-key", type=Path)
    p.add_argument("--kid")
    p.add_argument("--issuer")
    p.add_argument("--audience", action="append")
    p.add_argument("--target")
    p.add_argument("--subject")
    p.add_argument("--preferred-username")
    p.add_argument("--broker-session-id")
    p.add_argument("--auth-method", action="append")
    p.add_argument("--assurance-level")
    p.add_argument("--lifetime", type=int)
    p.add_argument("--jti")
    p.add_argument("--now", type=int)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    config = _load_simple_config(args.config)

    private_key_path = _value(args, config, "private_key")
    if private_key_path is None:
        raise SystemExit("--private-key or private_key config is required")

    # A plain string audience stays a string: build_claims() emits "aud"
    # unchanged, and collapsing str/list would alter the token shape.
    audience = args.audience if args.audience else config.get("audience")
    if isinstance(audience, list):
        audience = _split_csv_items(audience)

    auth_method = args.auth_method if args.auth_method else config.get(
        "auth_method", ["broker"]
    )
    auth_method = _split_csv_items(
        [auth_method] if isinstance(auth_method, str) else auth_method
    )

    now = _value(args, config, "now")
    now = int(time.time()) if now is None else int(now)

    claims = build_claims(
        issuer=_value(args, config, "issuer"),
        audience=audience,
        subject=_value(args, config, "subject"),
        preferred_username=_value(args, config, "preferred_username"),
        groups=[],
        roles=["desktop-user"],
        target=_value(args, config, "target"),
        session_id=_value(args, config, "broker_session_id"),
        auth_context={
            "amr": auth_method,
            "acr": _value(args, config, "assurance_level", "mfa"),
            "device_trust": config.get("device_trust", "unknown"),
        },
        now=now,
        lifetime=int(_value(args, config, "lifetime", 300)),
        jti=_value(args, config, "jti"),
    )
    token = sign_claims(
        claims,
        Path(private_key_path).read_bytes(),
        key_id=_value(args, config, "kid"),
    )
    sys.stdout.write(token)
    sys.stdout.write("\n")
    if config.get("write_claims_json"):
        Path(config["write_claims_json"]).write_text(
            json.dumps(claims, sort_keys=True, indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
