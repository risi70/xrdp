"""Smart-card (certificate PoP) authentication for the reference broker.

Models the "card -> broker -> Mode C" flow: a virtual smart card proves
possession of an X.509 credential to the broker via challenge-response, the
broker validates the certificate chain to a trust anchor and maps the
certificate identity to a Linux user, and the broker then mints a BAF
assertion exactly as for any other authenticated user.

The smart card itself is abstracted behind a signer interface:

- ``P12Card`` keeps a PIN-protected key in a PKCS#12 file and signs with it
  directly. This is the portable simulation used by the headless proof.
- ``Pkcs11Card`` drives a real PKCS#11 token (e.g. SoftHSM2 loaded from the
  same p12) through ``pkcs11-tool`` for higher fidelity on the lab VM.

Both present the same certificate and produce the same challenge signature,
so the broker-side validation is identical.

This is a broker-neutral reference component. It performs no XRDP-side
authorization: production identity binding, UID 0 rejection and PAM approval
still happen in xrdp-sesexec.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

CHALLENGE_BYTES = 32


class SmartCardError(ValueError):
    """Raised when smart-card authentication fails. Fail closed."""


# --------------------------------------------------------------------------
# Client-side card signers
# --------------------------------------------------------------------------
class Card(Protocol):
    """A virtual smart card: presents a certificate and signs a challenge."""

    def certificate_pem(self) -> bytes: ...

    def sign(self, challenge: bytes) -> bytes: ...


@dataclass
class P12Card:
    """Virtual smart card backed by a PIN-protected PKCS#12 file."""

    p12_path: str
    pin: str

    def _load(self):
        data = open(self.p12_path, "rb").read()
        key, cert, _ = pkcs12.load_key_and_certificates(
            data, self.pin.encode() if self.pin else None
        )
        if key is None or cert is None:
            raise SmartCardError("p12 does not contain a key and certificate")
        return key, cert

    def certificate_pem(self) -> bytes:
        _, cert = self._load()
        return cert.public_bytes(serialization.Encoding.PEM)

    def sign(self, challenge: bytes) -> bytes:
        key, _ = self._load()
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SmartCardError("only RSA smart-card keys are supported")
        return key.sign(challenge, padding.PKCS1v15(), hashes.SHA256())


@dataclass
class Pkcs11Card:
    """Virtual smart card backed by a PKCS#11 token (e.g. SoftHSM2).

    Signing is delegated to ``pkcs11-tool`` so the private key operation goes
    through the token, never touching key bytes in this process.
    """

    module: str          # path to the PKCS#11 module (.so)
    token_label: str
    pin: str
    cert_pem_path: str   # the card's certificate, exported once at provisioning
    key_id: str = "01"

    def certificate_pem(self) -> bytes:
        return open(self.cert_pem_path, "rb").read()

    def sign(self, challenge: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "challenge.bin")
            out = os.path.join(d, "sig.bin")
            with open(inp, "wb") as fh:
                fh.write(challenge)
            # RSA-PKCS with a SHA-256 digestinfo, matching the P12Card scheme.
            subprocess.run(
                ["pkcs11-tool", "--module", self.module,
                 "--token-label", self.token_label, "--login",
                 "--pin", self.pin, "--id", self.key_id,
                 "--mechanism", "SHA256-RSA-PKCS",
                 "--sign", "--input-file", inp, "--output-file", out],
                check=True, capture_output=True,
            )
            return open(out, "rb").read()


# --------------------------------------------------------------------------
# Broker-side authenticator
# --------------------------------------------------------------------------
def _default_identity_from_cert(cert: x509.Certificate) -> str:
    """Derive a login name from the certificate.

    Prefers a SAN userPrincipalName / rfc822Name local part; falls back to the
    subject CommonName. The domain suffix is stripped so ``bafuser@lab`` and
    ``bafuser`` both map to ``bafuser``.
    """
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        for name in san.get_values_for_type(x509.RFC822Name):
            return name.split("@", 1)[0]
        # userPrincipalName is carried as an otherName; cryptography exposes
        # it via OtherName with the MS UPN OID.
        for other in san.get_values_for_type(x509.OtherName):
            if other.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3":
                # value is a DER-encoded UTF8String; take the printable tail.
                text = other.value.decode("utf-8", "ignore")
                cleaned = "".join(c for c in text if c.isprintable())
                return cleaned.lstrip("\x0c").split("@", 1)[0]
    except x509.ExtensionNotFound:
        pass
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        return str(cns[0].value).split("@", 1)[0]
    raise SmartCardError("certificate has no usable identity")


@dataclass
class SmartCardAuthenticator:
    """Validates a card's certificate + challenge signature (broker side)."""

    trust_anchor_pem: bytes
    # Optional explicit map of cert identity -> local username. When absent,
    # the derived identity is used directly.
    identity_map: dict[str, str] | None = None

    def _trust_anchors(self) -> list[x509.Certificate]:
        anchors = []
        data = self.trust_anchor_pem
        # Support a bundle of concatenated PEM certificates.
        marker = b"-----END CERTIFICATE-----"
        for chunk in data.split(marker):
            chunk = chunk.strip()
            if chunk:
                anchors.append(x509.load_pem_x509_certificate(chunk + b"\n" + marker))
        if not anchors:
            raise SmartCardError("no trust anchor configured")
        return anchors

    def new_challenge(self) -> bytes:
        return os.urandom(CHALLENGE_BYTES)

    def authenticate(
        self, cert_pem: bytes, challenge: bytes, signature: bytes,
        *, now=None,
    ) -> tuple[str, tuple[str, ...], str]:
        """Return ``(username, auth_method, assurance_level)`` or raise.

        Fail-closed on any of: untrusted issuer, expired/not-yet-valid cert,
        bad proof-of-possession signature, or unmapped identity.
        """
        import datetime

        if len(challenge) < CHALLENGE_BYTES:
            raise SmartCardError("challenge too short")
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except ValueError as exc:
            raise SmartCardError(f"unparseable certificate: {exc}") from exc

        # 1. Validity window (tolerate cryptography < 42 which lacks *_utc).
        now = now or datetime.datetime.now(datetime.timezone.utc)
        not_before = getattr(cert, "not_valid_before_utc", None)
        if not_before is None:
            not_before = cert.not_valid_before.replace(
                tzinfo=datetime.timezone.utc)
            not_after = cert.not_valid_after.replace(
                tzinfo=datetime.timezone.utc)
        else:
            not_after = cert.not_valid_after_utc
        if now < not_before or now >= not_after:
            raise SmartCardError("certificate is expired or not yet valid")

        # 2. Chain to a configured trust anchor (single-level lab chain: the
        #    leaf must be signed by one of the trusted CA certificates).
        verified = False
        for anchor in self._trust_anchors():
            try:
                anchor.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                verified = True
                break
            except Exception:
                continue
        if not verified:
            raise SmartCardError("certificate not issued by a trusted anchor")

        # 3. Proof of possession: the card signed the broker challenge.
        try:
            cert.public_key().verify(
                signature, challenge, padding.PKCS1v15(), hashes.SHA256()
            )
        except Exception as exc:
            raise SmartCardError("proof-of-possession failed") from exc

        # 4. Identity mapping.
        identity = _default_identity_from_cert(cert)
        username = (self.identity_map or {}).get(identity, identity)
        if not username or "/" in username or "\x00" in username:
            raise SmartCardError("unsafe mapped username")

        return username, ("smartcard", "pki"), "high"
