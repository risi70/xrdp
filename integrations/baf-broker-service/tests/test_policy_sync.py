"""Tests for uds_policy_sync.py and the service's policy hot-reload."""

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import baf_issuance_service
import uds_policy_sync
from certutil import make_cert

TOKEN = "tok-123"

ASSIGNMENTS = {
    "pool-a": [
        {"owner": "bafuser@keycloak", "friendly_name": "baflab-vdi-01"},
        {"owner": "bafother@keycloak", "friendly_name": "baflab-vdi-02"},
        {"owner": "bad user@keycloak", "friendly_name": "baflab-vdi-02"},
        {"owner": "", "friendly_name": "baflab-vdi-02"},
    ],
    "pool-b": [
        {"owner": "bafuser@keycloak", "name": "baflab-vdi-02"},
    ],
}


class FakeUdsHandler(BaseHTTPRequestHandler):
    def _json(self, status, document):
        body = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/uds/rest/auth":
            self._json(404, {})
            return
        length = int(self.headers.get("Content-Length") or 0)
        credentials = json.loads(self.rfile.read(length))
        if (credentials.get("username") != "baf-sync"
                or credentials.get("password") != "sync-secret"
                or credentials.get("auth") != "keycloak"):
            self._json(403, {"error": "invalid credentials"})
            return
        self._json(200, {"result": "ok", "token": TOKEN})

    def do_GET(self):
        if self.headers.get("X-Auth-Token") != TOKEN:
            self._json(403, {"error": "no token"})
            return
        if self.path == "/uds/rest/servicespools/overview":
            self._json(200, [
                {"id": "pool-a", "name": "Pool A"},
                {"id": "pool-b", "name": "Pool B"},
                {"name": "broken pool without id"},
            ])
        elif self.path.startswith("/uds/rest/servicespools/") \
                and self.path.endswith("/assignedservices/overview"):
            pool_id = self.path.split("/")[4]
            self._json(200, ASSIGNMENTS.get(pool_id, []))
        else:
            self._json(404, {})

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def fake_uds(tmp_path_factory):
    root = tmp_path_factory.mktemp("fake-uds")
    cert, key = make_cert(root, "uds", "localhost", san="DNS:localhost")
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeUdsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {
        "url": f"https://localhost:{server.server_address[1]}",
        "ca": cert,
    }
    server.shutdown()
    server.server_close()


@pytest.fixture
def sync_config(fake_uds, tmp_path):
    password = tmp_path / "password"
    password.write_text("sync-secret\n")
    policy_file = tmp_path / "policy.json"
    config = tmp_path / "sync.config"
    config.write_text(
        f"uds_url: {fake_uds['url']}\n"
        "auth_label: keycloak\n"
        "username: baf-sync\n"
        f"password_file: {password}\n"
        f"ca_file: {fake_uds['ca']}\n"
        f"policy_file: {policy_file}\n"
        "groups: /vdi/users\n"
    )
    return {"config": config, "policy_file": policy_file}


class TestSync:
    def test_sync_builds_expected_policy(self, sync_config):
        assert uds_policy_sync.main(
            ["--config", str(sync_config["config"])]
        ) == 0
        document = json.loads(sync_config["policy_file"].read_text())
        assert document["users"]["bafuser"]["targets"] == [
            "baflab-vdi-01", "baflab-vdi-02",
        ]
        assert document["users"]["bafother"]["targets"] == [
            "baflab-vdi-02",
        ]
        assert "bad user" not in document["users"]
        assert document["users"]["bafuser"]["groups"] == ["/vdi/users"]
        assert document["targets"]["baflab-vdi-01"]["audience"] == \
            "xrdp://baflab-vdi-01"
        # The result must satisfy the issuance service's own validator.
        policy = baf_issuance_service.Policy(document)
        assert policy.authorize("bafuser", "baflab-vdi-02")

    def test_dry_run_writes_nothing(self, sync_config, capsys):
        assert uds_policy_sync.main(
            ["--config", str(sync_config["config"]), "--dry-run"]
        ) == 0
        assert not sync_config["policy_file"].exists()
        assert "bafuser" in capsys.readouterr().out

    def test_empty_result_refuses_to_wipe_policy(
        self, sync_config, monkeypatch
    ):
        sync_config["policy_file"].write_text(json.dumps({
            "users": {"bafuser": {"targets": ["t"]}},
            "targets": {"t": {"audience": "xrdp://t"}},
        }))
        monkeypatch.setattr(
            uds_policy_sync, "build_policy",
            lambda config, client: {"users": {}, "targets": {}},
        )
        assert uds_policy_sync.main(
            ["--config", str(sync_config["config"])]
        ) == 1
        assert "bafuser" in sync_config["policy_file"].read_text()
        assert uds_policy_sync.main(
            ["--config", str(sync_config["config"]), "--allow-empty"]
        ) == 0
        assert json.loads(
            sync_config["policy_file"].read_text()
        )["users"] == {}

    def test_bad_credentials_fail(self, sync_config, tmp_path):
        bad_password = tmp_path / "bad-password"
        bad_password.write_text("wrong\n")
        text = sync_config["config"].read_text().replace(
            "password_file: ", "password_file_old: ", 1
        )
        # Rewrite config pointing at the wrong password.
        config = tmp_path / "bad.config"
        config.write_text(
            "\n".join(
                line for line in text.splitlines()
                if not line.startswith("password_file_old")
            ) + f"\npassword_file: {bad_password}\n"
        )
        assert uds_policy_sync.main(["--config", str(config)]) == 1

    def test_http_url_rejected(self, sync_config, tmp_path):
        config = tmp_path / "http.config"
        config.write_text(
            sync_config["config"].read_text().replace(
                "https://", "http://"
            )
        )
        with pytest.raises(uds_policy_sync.SyncError, match="https"):
            uds_policy_sync.SyncConfig(config)


class TestHotReload:
    @pytest.fixture
    def reload_lab(self, lab, tmp_path):
        """A dedicated service instance with a mutable policy file."""
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "users": {"bafuser": {"targets": ["baflab-vdi-01"]}},
            "targets": {
                "baflab-vdi-01": {"audience": "xrdp://baflab-vdi-01"},
            },
        }))
        config_text = lab["config_file"].read_text()
        config_path = tmp_path / "config"
        config_path.write_text(
            "\n".join(
                line for line in config_text.splitlines()
                if not line.startswith("policy_file:")
            ) + f"\npolicy_file: {policy_file}\n"
        )
        config = baf_issuance_service.ServiceConfig(config_path)
        server = baf_issuance_service.build_server(config)
        thread = threading.Thread(
            target=server.serve_forever, daemon=True
        )
        thread.start()
        base_url = f"https://localhost:{server.server_address[1]}"
        yield {"base_url": base_url, "policy_file": policy_file, **{
            key: lab[key] for key in
            ("server_cert", "client_cert", "client_key")
        }}
        server.shutdown()
        server.server_close()

    def _client(self, reload_lab):
        from BAFRDP.core.broker_client import (
            BrokerClient, BrokerClientConfig,
        )
        return BrokerClient(BrokerClientConfig(
            base_url=reload_lab["base_url"],
            ca_file=str(reload_lab["server_cert"]),
            client_cert=str(reload_lab["client_cert"]),
            client_key=str(reload_lab["client_key"]),
        ))

    def _issue(self, client, username):
        return client.issue(
            subject="uds:1",
            preferred_username=username,
            target="baflab-vdi-01",
            broker_session_id="uds-reload",
        )

    def test_policy_change_applies_without_restart(self, reload_lab):
        from BAFRDP.core.errors import BrokerDeniedError

        client = self._client(reload_lab)
        assert self._issue(client, "bafuser")
        with pytest.raises(BrokerDeniedError):
            self._issue(client, "newuser")

        document = json.loads(reload_lab["policy_file"].read_text())
        document["users"]["newuser"] = {"targets": ["baflab-vdi-01"]}
        reload_lab["policy_file"].write_text(json.dumps(document))
        assert self._issue(client, "newuser")

    def test_corrupt_policy_keeps_last_good(self, reload_lab):
        client = self._client(reload_lab)
        assert self._issue(client, "bafuser")
        reload_lab["policy_file"].write_text("{ not json")
        # Last-good policy stays in force: existing grants keep working.
        assert self._issue(client, "bafuser")
