"""End-to-end and policy tests for the issuance service."""

import http.client
import json
import ssl
from pathlib import Path

import jwt
import pytest

import baf_issuance_service
from baf_issuance_service import ConfigError, Policy, ServiceConfig
from BAFRDP.core.broker_client import BrokerClient, BrokerClientConfig
from BAFRDP.core.errors import BrokerDeniedError, BrokerUnreachableError


def broker_client(lab, cert="client_cert", key="client_key"):
    return BrokerClient(BrokerClientConfig(
        base_url=lab["base_url"],
        ca_file=str(lab["server_cert"]),
        client_cert=str(lab[cert]),
        client_key=str(lab[key]),
        timeout_seconds=5,
    ))


def issue(client, target="baflab-vdi-01", username="bafuser"):
    return client.issue(
        subject="uds:1234",
        preferred_username=username,
        target=target,
        broker_session_id="uds-e2e",
    )


def raw_connection(lab, cert_key=("client_cert", "client_key")):
    context = ssl.create_default_context(cafile=str(lab["server_cert"]))
    context.load_cert_chain(
        str(lab[cert_key[0]]), str(lab[cert_key[1]])
    )
    host, port = lab["base_url"].removeprefix("https://").split(":")
    return http.client.HTTPSConnection(
        host, int(port), context=context, timeout=5
    )


class TestEndToEnd:
    def test_plugin_client_obtains_verifiable_assertion(self, lab):
        assertion = issue(broker_client(lab))
        public_key = lab["signing_pub"].read_bytes()
        header = jwt.get_unverified_header(assertion)
        assert header["kid"] == "lab-key-1"
        assert header["typ"] == "baf+jwt"
        claims = jwt.decode(
            assertion, public_key, algorithms=["RS256"],
            audience="xrdp://baflab-vdi-01",
            issuer="https://broker.lab.test/baf",
        )
        assert claims["preferred_username"] == "bafuser"
        assert claims["target"] == "baflab-vdi-01"
        assert claims["roles"] == ["desktop-user"]
        assert claims["groups"] == ["/vdi/users"]
        assert claims["auth_method"] == ["broker"]
        assert claims["exp"] - claims["iat"] == 120

    def test_jti_is_unique_per_issuance(self, lab):
        client = broker_client(lab)
        first = jwt.decode(
            issue(client), options={"verify_signature": False}
        )
        second = jwt.decode(
            issue(client), options={"verify_signature": False}
        )
        assert first["jti"] != second["jti"]

    def test_disallowed_target_is_denied(self, lab):
        with pytest.raises(BrokerDeniedError):
            issue(broker_client(lab), target="baflab-vdi-02")

    def test_unknown_user_is_denied(self, lab):
        with pytest.raises(BrokerDeniedError):
            issue(broker_client(lab), username="mallory")

    def test_unknown_client_cn_is_denied(self, lab):
        with pytest.raises(BrokerDeniedError):
            issue(broker_client(lab, "other_cert", "other_key"))

    def test_untrusted_client_certificate_fails_handshake(self, lab):
        with pytest.raises(BrokerUnreachableError):
            issue(broker_client(lab, "outsider_cert", "outsider_key"))

    def test_healthz_and_unknown_path(self, lab):
        connection = raw_connection(lab)
        connection.request("GET", "/healthz")
        assert connection.getresponse().status == 200
        connection.request("GET", "/v1/other")
        assert connection.getresponse().status == 404
        connection.close()

    def test_malformed_body_is_rejected(self, lab):
        connection = raw_connection(lab)
        connection.request(
            "POST", "/v1/assertions", body=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert connection.getresponse().status == 400
        connection.request(
            "POST", "/v1/assertions",
            body=json.dumps({"preferred_username": "bafuser"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert connection.getresponse().status == 403
        connection.close()

    def test_oversized_body_is_rejected(self, lab):
        connection = raw_connection(lab)
        connection.request(
            "POST", "/v1/assertions",
            body=b"x" * (baf_issuance_service.MAX_BODY + 1),
            headers={"Content-Type": "application/json"},
        )
        assert connection.getresponse().status == 400
        connection.close()


class TestRateLimit:
    def test_limit_denies_excess_requests(self):
        limiter = baf_issuance_service.RateLimiter(2)
        assert limiter.allow("uds-server")
        assert limiter.allow("uds-server")
        assert not limiter.allow("uds-server")
        assert limiter.allow("another-client")


class TestPolicy:
    def test_rejects_structural_defects(self):
        with pytest.raises(ConfigError):
            Policy({"users": {}})
        with pytest.raises(ConfigError):
            Policy({
                "users": {"u": {"targets": ["missing"]}},
                "targets": {},
            })
        with pytest.raises(ConfigError):
            Policy({
                "users": {"u": {"targets": []}},
                "targets": {"t": {"audience": "a"}},
            })

    def test_authorize_paths(self):
        policy = Policy({
            "users": {"u": {"targets": ["t"]}},
            "targets": {"t": {"audience": "xrdp://t"}},
        })
        grant = policy.authorize("u", "t")
        assert grant["audience"] == "xrdp://t"
        assert grant["roles"] == ["desktop-user"]
        with pytest.raises(baf_issuance_service.PolicyDenied):
            policy.authorize("u", "other")
        with pytest.raises(baf_issuance_service.PolicyDenied):
            policy.authorize("nobody", "t")


class TestServiceConfig:
    def test_rejects_bad_configurations(self, lab, tmp_path):
        base = lab["config_file"].read_text()

        def variant(transform) -> Path:
            path = tmp_path / "config"
            path.write_text(transform(base))
            return path

        with pytest.raises(ConfigError, match="missing config keys"):
            ServiceConfig(variant(
                lambda text: text.replace("kid: lab-key-1\n", "")
            ))
        with pytest.raises(ConfigError, match="unknown config key"):
            ServiceConfig(variant(lambda text: text + "surprise: 1\n"))
        with pytest.raises(ConfigError, match="https"):
            ServiceConfig(variant(lambda text: text.replace(
                "issuer: https://", "issuer: http://"
            )))
        with pytest.raises(ConfigError, match="lifetime"):
            ServiceConfig(variant(lambda text: text.replace(
                "lifetime: 120", "lifetime: 10"
            )))
