import json
from pathlib import Path

import jwt


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors" / "phase2-vectors.json"
PUBLIC_KEY = ROOT / "vectors" / "test-public.pem"

REQUIRED_NAMES = {
    "valid-rs256",
    "expired",
    "not-yet-valid",
    "lifetime-too-long",
    "wrong-issuer",
    "wrong-audience",
    "wrong-target",
    "missing-mandatory-claim",
    "duplicate-json-member",
    "alg-none",
    "mac-hs256",
    "bad-signature",
    "unknown-kid",
    "unknown-crit",
    "jku-header",
    "x5u-header",
    "embedded-jwk",
    "replayed-jti",
    "oversized-assertion",
    "malformed-compact",
    "invalid-base64url",
    "ps256-unsupported",
    "es256-unsupported",
}


def test_phase2_vector_manifest_is_complete():
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    vectors = {item["name"]: item for item in document["vectors"]}
    assert REQUIRED_NAMES <= vectors.keys()
    assert vectors["valid-rs256"]["expected_status"] == "success"
    assert vectors["replayed-jti"]["expected_status"] == "replay"
    for vector in vectors.values():
        assert vector["token"]
        assert vector["reason"]
        assert vector["static"] is True
        assert vector["expected_result"] in {
            "accepted",
            "rejected",
            "replay-rejected",
        }
        assert vector["expected_status"] in {"success", "invalid", "replay"}
        assert vector["expected_validator_status"] == vector["expected_status"]
    assert vectors["replayed-jti"]["generation_parameters"]["sequence"]


def test_valid_phase2_vector_is_baf_rs256():
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = next(
        item for item in document["vectors"] if item["name"] == "valid-rs256"
    )
    header = jwt.get_unverified_header(vector["token"])
    assert header == {
        "alg": "RS256",
        "kid": document["kid"],
        "typ": "baf+jwt",
    }
    claims = jwt.decode(
        vector["token"],
        PUBLIC_KEY.read_bytes(),
        algorithms=["RS256"],
        audience=document["audience"],
        issuer=document["issuer"],
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert claims["target"] == document["target"]
