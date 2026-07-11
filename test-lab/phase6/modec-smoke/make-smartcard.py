#!/usr/bin/env python3
"""Generate lab smart-card material: a CA and a user PKCS#12 credential.

The p12 is the "simulated smart card" backing store. The certificate carries
the login identity in its CommonName and a SAN rfc822Name (user@domain).

Usage:
  make-smartcard.py ca   --out-cert ca.pem --out-key ca.key [--cn "Lab CA"]
  make-smartcard.py user --ca-cert ca.pem --ca-key ca.key \\
       --cn bafuser --email bafuser@xrdp-baf.test \\
       --out-p12 card.p12 --pin 123456 [--out-cert card.pem]
  make-smartcard.py user ... --self-signed   # negative: not issued by the CA
  make-smartcard.py user ... --not-after -1   # negative: already expired
"""
from __future__ import annotations

import argparse
import datetime
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, \
    PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def make_ca(args):
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), True)
        .sign(key, hashes.SHA256())
    )
    open(args.out_cert, "wb").write(cert.public_bytes(Encoding.PEM))
    open(args.out_key, "wb").write(key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    print(f"CA written: {args.out_cert}")


def make_user(args):
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=args.not_after))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_cert_sign=False, crl_sign=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), True)
        .add_extension(x509.ExtendedKeyUsage(
            [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")]), False)  # clientAuth
        .add_extension(x509.SubjectAlternativeName(
            [x509.RFC822Name(args.email)]), False)
    )
    if args.self_signed:
        # Negative case: leaf signed by its own key, not the CA.
        builder = builder.issuer_name(subject)
        cert = builder.sign(key, hashes.SHA256())
    else:
        ca_cert = x509.load_pem_x509_certificate(open(args.ca_cert, "rb").read())
        ca_key = serialization.load_pem_private_key(
            open(args.ca_key, "rb").read(), password=None)
        builder = builder.issuer_name(ca_cert.subject)
        cert = builder.sign(ca_key, hashes.SHA256())

    p12 = pkcs12.serialize_key_and_certificates(
        name=args.cn.encode(), key=key, cert=cert, cas=None,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(args.pin.encode())
            if args.pin else NoEncryption()),
    )
    open(args.out_p12, "wb").write(p12)
    if args.out_cert:
        open(args.out_cert, "wb").write(cert.public_bytes(Encoding.PEM))
    print(f"smart card (p12) written: {args.out_p12} for CN={args.cn}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    ca = sub.add_parser("ca")
    ca.add_argument("--out-cert", required=True)
    ca.add_argument("--out-key", required=True)
    ca.add_argument("--cn", default="XRDP BAF Lab Smart Card CA")
    ca.set_defaults(func=make_ca)

    u = sub.add_parser("user")
    u.add_argument("--ca-cert")
    u.add_argument("--ca-key")
    u.add_argument("--cn", required=True)
    u.add_argument("--email", required=True)
    u.add_argument("--out-p12", required=True)
    u.add_argument("--out-cert")
    u.add_argument("--pin", default="123456")
    u.add_argument("--self-signed", action="store_true")
    u.add_argument("--not-after", type=int, default=3650,
                   help="days until expiry (negative = already expired)")
    u.set_defaults(func=make_user)

    args = p.parse_args(argv)
    if args.cmd == "user" and not args.self_signed and not (
            args.ca_cert and args.ca_key):
        p.error("user certs need --ca-cert and --ca-key (or --self-signed)")
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
