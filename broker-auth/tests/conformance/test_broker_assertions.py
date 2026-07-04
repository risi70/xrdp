import time

import pytest

from conformance.verifier import ConformanceError, verify_assertion


def verify(token, keypair, profile):
    _, public_key = keypair
    return verify_assertion(
        token,
        public_key,
        issuer=profile["issuer"],
        audience=profile["audience"],
        target=profile["target"],
    )


def test_valid_assertion(valid_claims, issue, keypair, profile):
    token = issue(valid_claims, validate=True)
    assert verify(token, keypair, profile) == valid_claims


def test_expired_assertion(valid_claims, issue, keypair, profile):
    now = int(time.time())
    claims = dict(valid_claims, iat=now - 120, nbf=now - 120, exp=now - 60)
    with pytest.raises(ConformanceError):
        verify(issue(claims), keypair, profile)


def test_wrong_audience(valid_claims, issue, keypair, profile):
    token = issue(dict(valid_claims, aud="other-service"))
    with pytest.raises(ConformanceError):
        verify(token, keypair, profile)


def test_wrong_issuer(valid_claims, issue, keypair, profile):
    token = issue(dict(valid_claims, iss="https://other-issuer.test"))
    with pytest.raises(ConformanceError):
        verify(token, keypair, profile)


def test_wrong_target(valid_claims, issue, keypair, profile):
    token = issue(dict(valid_claims, target="other-host.example.test"))
    with pytest.raises(ConformanceError):
        verify(token, keypair, profile)


def test_missing_username(valid_claims, issue, keypair, profile):
    claims = dict(valid_claims)
    del claims["preferred_username"]
    with pytest.raises(ConformanceError):
        verify(issue(claims), keypair, profile)


def test_missing_jti(valid_claims, issue, keypair, profile):
    claims = dict(valid_claims)
    del claims["jti"]
    with pytest.raises(ConformanceError):
        verify(issue(claims), keypair, profile)


def test_future_not_before(valid_claims, issue, keypair, profile):
    now = int(time.time())
    claims = dict(valid_claims, iat=now, nbf=now + 60, exp=now + 300)
    with pytest.raises(ConformanceError):
        verify(issue(claims), keypair, profile)


@pytest.mark.parametrize(
    "token",
    (
        "",
        "not-a-jwt",
        "only.two",
        "three.parts.but-not-base64",
    ),
)
def test_malformed_token(token, keypair, profile):
    with pytest.raises(ConformanceError):
        verify(token, keypair, profile)


def test_bad_signature(valid_claims, issue, profile):
    token = issue(valid_claims)
    signature_keypair = __import__(
        "broker_issuer", fromlist=["generate_rsa_keypair"]
    ).generate_rsa_keypair()
    with pytest.raises(ConformanceError):
        verify(token, signature_keypair, profile)
