import io
import json
import urllib.error

import pytest

from BAFRDP.core.broker_client import (
    MAX_ASSERTION,
    BrokerClient,
    BrokerClientConfig,
)
from BAFRDP.core.errors import (
    BrokerDeniedError,
    BrokerUnreachableError,
    ConfigurationError,
)


def config(**overrides):
    values = {
        "base_url": "https://broker.example.test",
        "ca_file": "/etc/uds/baf/broker-ca.pem",
        "client_cert": "/etc/uds/baf/uds-client.pem",
        "client_key": "/etc/uds/baf/uds-client.key",
    }
    values.update(overrides)
    return BrokerClientConfig(**values)


class TestConfig:
    def test_rejects_plain_http(self):
        with pytest.raises(ConfigurationError):
            config(base_url="http://broker.example.test")

    def test_rejects_missing_tls_material(self):
        for name in ("ca_file", "client_cert", "client_key"):
            with pytest.raises(ConfigurationError):
                config(**{name: ""})

    def test_rejects_out_of_range_timeout(self):
        for timeout in (0.5, 31):
            with pytest.raises(ConfigurationError):
                config(timeout_seconds=timeout)


class TestParseAssertion:
    def test_accepts_compact_jws(self):
        payload = json.dumps({"assertion": "eyJh.eyJi.c2ln"}).encode()
        assert BrokerClient._parse_assertion(payload) == b"eyJh.eyJi.c2ln"

    def test_rejects_non_jws_shapes(self):
        for assertion in ("", "no-dots", "a.b", "a.b.c.d", "a b.c.d", 5):
            payload = json.dumps({"assertion": assertion}).encode()
            with pytest.raises(BrokerDeniedError):
                BrokerClient._parse_assertion(payload)

    def test_rejects_invalid_json_and_oversize(self):
        with pytest.raises(BrokerDeniedError):
            BrokerClient._parse_assertion(b"not json")
        huge = json.dumps(
            {"assertion": "a" * MAX_ASSERTION + ".b.c"}
        ).encode()
        with pytest.raises(BrokerDeniedError):
            BrokerClient._parse_assertion(huge)


class TestIssue:
    @pytest.fixture
    def client(self, monkeypatch):
        instance = BrokerClient(config())
        monkeypatch.setattr(
            BrokerClient, "_ssl_context", lambda self: None
        )
        return instance

    def issue(self, client):
        return client.issue(
            subject="uds:1234",
            preferred_username="bafuser",
            target="baflab-vdi-01",
            broker_session_id="uds-abc",
        )

    def test_success_returns_assertion(self, client, monkeypatch):
        captured = {}

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout, context):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode())
            return Response(json.dumps({"assertion": "h.p.s"}).encode())

        monkeypatch.setattr(
            "urllib.request.urlopen", fake_urlopen
        )
        assert self.issue(client) == b"h.p.s"
        assert captured["url"].endswith("/v1/assertions")
        assert captured["body"]["preferred_username"] == "bafuser"
        assert captured["body"]["auth_method"] == ["broker"]

    def test_http_403_maps_to_denied(self, client, monkeypatch):
        def fake_urlopen(request, timeout, context):
            raise urllib.error.HTTPError(
                request.full_url, 403, "forbidden", {}, io.BytesIO()
            )

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        with pytest.raises(BrokerDeniedError):
            self.issue(client)

    def test_http_500_and_network_map_to_unreachable(
        self, client, monkeypatch
    ):
        def server_error(request, timeout, context):
            raise urllib.error.HTTPError(
                request.full_url, 500, "boom", {}, io.BytesIO()
            )

        monkeypatch.setattr("urllib.request.urlopen", server_error)
        with pytest.raises(BrokerUnreachableError):
            self.issue(client)

        def network_error(request, timeout, context):
            raise urllib.error.URLError("refused")

        monkeypatch.setattr("urllib.request.urlopen", network_error)
        with pytest.raises(BrokerUnreachableError):
            self.issue(client)

    def test_rejects_malformed_request_fields(self, client):
        with pytest.raises(ConfigurationError):
            client.issue(
                subject="uds:1234",
                preferred_username="has space",
                target="baflab-vdi-01",
                broker_session_id="uds-abc",
            )
