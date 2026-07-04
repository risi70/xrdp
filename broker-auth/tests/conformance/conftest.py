import sys
import time
from pathlib import Path

import pytest

BROKER_AUTH_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BROKER_AUTH_ROOT))
sys.path.insert(0, str(BROKER_AUTH_ROOT / "reference-issuer"))

from broker_issuer import build_claims, generate_rsa_keypair, sign_claims


@pytest.fixture(scope="session")
def keypair():
    return generate_rsa_keypair()


@pytest.fixture
def profile():
    return {
        "issuer": "https://issuer.example.test",
        "audience": "xrdp-sesman",
        "target": "rdp-host.example.test",
    }


@pytest.fixture
def valid_claims(profile):
    return build_claims(
        issuer=profile["issuer"],
        audience=profile["audience"],
        subject="user-1234",
        preferred_username="alice",
        groups=["remote-desktop"],
        roles=["desktop-user"],
        target=profile["target"],
        session_id="session-1234",
        auth_context={"acr": "urn:example:mfa", "amr": ["pwd", "otp"]},
        now=int(time.time()) - 1,
        lifetime=300,
        jti="jti-1234",
    )


@pytest.fixture
def issue(keypair):
    private_key, _ = keypair

    def _issue(claims, *, validate=False):
        return sign_claims(
            claims,
            private_key,
            key_id="conformance-key",
            validate=validate,
        )

    return _issue
