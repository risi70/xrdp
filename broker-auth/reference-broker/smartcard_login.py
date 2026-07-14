#!/usr/bin/env python3
"""Smart-card broker login: card -> broker -> BAF assertion.

Authenticates a virtual smart card to the reference broker by certificate
challenge-response (proof of possession) + trust-anchor validation, maps the
certificate identity to a Linux user, and mints a nonce-bound BAF assertion
for that user. The caller registers the assertion with the trusted handle
service to obtain a one-time handle, which then rides the Broker-RDP Handle path.

Prints the compact JWS assertion on stdout. Fails closed (non-zero exit) on
any authentication error.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ISSUER_DIR = HERE.parent / "reference-issuer"
for p in (str(HERE), str(ISSUER_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from broker_issuer import build_claims, sign_claims  # noqa: E402
from smartcard_auth import (  # noqa: E402
    P12Card, Pkcs11Card, SmartCardAuthenticator, SmartCardError,
)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    # Card (choose one backend)
    p.add_argument("--p12", help="PKCS#12 file backing the virtual smart card")
    p.add_argument("--pin", default="", help="card PIN / p12 password")
    p.add_argument("--pkcs11-module", help="PKCS#11 module .so (SoftHSM2 path)")
    p.add_argument("--token-label", help="PKCS#11 token label")
    p.add_argument("--card-cert", help="card certificate PEM (PKCS#11 mode)")
    p.add_argument("--key-id", default="01", help="PKCS#11 key id")
    # Broker trust + identity
    p.add_argument("--ca", required=True, help="trust anchor CA certificate PEM")
    p.add_argument("--map", action="append", default=[],
                   help="cert-identity=local-user override (repeatable)")
    # Assertion issuance
    p.add_argument("--issuer-key", required=True, help="broker issuer private key PEM")
    p.add_argument("--issuer", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--kid", required=True)
    p.add_argument("--nonce", help="urn:baf:ts_nonce value to bind, if any")
    p.add_argument("--lifetime", type=int, default=120)
    return p


def main(argv=None) -> int:
    args = _parser().parse_args(argv)

    if args.p12:
        card = P12Card(args.p12, args.pin)
    elif args.pkcs11_module and args.token_label and args.card_cert:
        card = Pkcs11Card(args.pkcs11_module, args.token_label, args.pin,
                          args.card_cert, args.key_id)
    else:
        print("error: provide --p12 OR --pkcs11-module/--token-label/--card-cert",
              file=sys.stderr)
        return 2

    identity_map = {}
    for entry in args.map:
        k, _, v = entry.partition("=")
        if k and v:
            identity_map[k] = v

    authenticator = SmartCardAuthenticator(
        trust_anchor_pem=Path(args.ca).read_bytes(),
        identity_map=identity_map or None,
    )

    # The full card <-> broker challenge-response proof of possession.
    try:
        challenge = authenticator.new_challenge()
        signature = card.sign(challenge)
        username, auth_method, assurance = authenticator.authenticate(
            card.certificate_pem(), challenge, signature
        )
    except SmartCardError as exc:
        print(f"smart-card authentication failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # card backend / crypto failure
        print(f"smart-card error: {exc}", file=sys.stderr)
        return 1

    claims = build_claims(
        issuer=args.issuer,
        audience=args.audience,
        subject="sc-" + username,
        preferred_username=username,
        groups=["vdi"],
        roles=["desktop-user"],
        target=args.target,
        session_id="sc-" + uuid.uuid4().hex,
        auth_context={"amr": list(auth_method), "acr": assurance,
                      "device_trust": "unknown"},
        lifetime=args.lifetime,
    )
    if args.nonce:
        claims["extensions"] = {"urn:baf:ts_nonce": args.nonce}

    token = sign_claims(claims, Path(args.issuer_key).read_bytes(),
                        key_id=args.kid)
    sys.stdout.write(token)
    print(f"# authenticated smart-card user: {username} "
          f"({'+'.join(auth_method)}, {assurance})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
