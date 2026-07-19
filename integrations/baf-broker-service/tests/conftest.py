"""Fixtures: ephemeral TLS material and a live issuance service.

The happy-path consumer is the OpenUDS plugin's own ``BrokerClient``,
imported from ``integrations/openuds-baf`` (which needs the fake uds
API installed first), so these tests prove the two components against
each other over real mutual TLS.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SERVICE_ROOT = HERE.parents[0]
INTEGRATIONS = SERVICE_ROOT.parents[0]
REPO_ROOT = INTEGRATIONS.parents[0]

for path in (
    str(SERVICE_ROOT),
    str(INTEGRATIONS / "openuds-baf"),
    str(INTEGRATIONS / "openuds-baf" / "tests"),
    str(REPO_ROOT / "broker-auth" / "reference-issuer"),
):
    if path not in sys.path:
        sys.path.insert(0, path)

import udsfakes  # noqa: E402

udsfakes.install_fake_uds()

import baf_issuance_service  # noqa: E402
from broker_issuer import write_keypair  # noqa: E402
from certutil import make_cert  # noqa: E402

logging.getLogger("baf-issuanced").setLevel(logging.CRITICAL)


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    """TLS material, signing key, policy, config, and a live server."""
    root = tmp_path_factory.mktemp("issuance-lab")
    server_cert, server_key = make_cert(
        root, "server", "localhost", san="DNS:localhost"
    )
    client_cert, client_key = make_cert(root, "client", "uds-server")
    other_cert, other_key = make_cert(root, "other", "other-frontend")
    outsider_cert, outsider_key = make_cert(root, "outsider", "uds-server")

    # Both lab front-end certs are trusted at the TLS layer; only the
    # CN "uds-server" is allowed by configuration. The outsider cert is
    # NOT in the bundle and must fail the TLS handshake.
    client_ca = root / "clients-ca.pem"
    client_ca.write_bytes(
        client_cert.read_bytes() + other_cert.read_bytes()
    )

    signing_key = root / "baf-signing.key"
    signing_pub = root / "baf-signing.pub"
    write_keypair(signing_key, signing_pub, 2048)

    policy = root / "policy.json"
    policy.write_text(json.dumps({
        "users": {
            "bafuser": {
                "targets": ["baflab-vdi-01"],
                "roles": ["desktop-user"],
                "groups": ["/vdi/users"],
            },
        },
        "targets": {
            "baflab-vdi-01": {"audience": "xrdp://baflab-vdi-01"},
            "baflab-vdi-02": {"audience": "xrdp://baflab-vdi-02"},
        },
    }))

    config_file = root / "config"
    config_file.write_text(
        "listen_address: 127.0.0.1\n"
        "listen_port: 0\n"
        f"tls_cert: {server_cert}\n"
        f"tls_key: {server_key}\n"
        f"client_ca: {client_ca}\n"
        "allowed_client_cn: uds-server\n"
        "issuer: https://broker.lab.test/baf\n"
        "kid: lab-key-1\n"
        f"private_key: {signing_key}\n"
        f"policy_file: {policy}\n"
        "lifetime: 120\n"
        "rate_limit_per_minute: 120\n"
    )

    config = baf_issuance_service.ServiceConfig(config_file)
    server = baf_issuance_service.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    yield {
        "base_url": f"https://localhost:{port}",
        "server_cert": server_cert,
        "client_cert": client_cert, "client_key": client_key,
        "other_cert": other_cert, "other_key": other_key,
        "outsider_cert": outsider_cert, "outsider_key": outsider_key,
        "signing_pub": signing_pub,
        "config_file": config_file,
        "root": root,
    }
    server.shutdown()
    server.server_close()
