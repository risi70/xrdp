"""Exercises baf-pki-setup.sh end-to-end with real openssl."""

import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "baf-pki-setup.sh"

CONFIG = """\
BROKER_FQDN=broker.lab.test
UDS_FQDN=uds.lab.test
KEYCLOAK_FQDN=keycloak.lab.test
VDI_HOSTS="baflab-vdi-01 baflab-vdi-02"
CLIENT_CN=uds-server
KID=baf-signing-key-01
"""


def run(*args):
    return subprocess.run(
        [str(SCRIPT), *args], capture_output=True, text=True, check=True
    )


def openssl(*args) -> str:
    return subprocess.run(
        ["openssl", *args], capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture(scope="module")
def issued(tmp_path_factory):
    root = tmp_path_factory.mktemp("pki")
    config = root / "pki.conf"
    config.write_text(CONFIG)
    ca = root / "ca"
    out = root / "bundles"
    run("init-ca", "--out", str(ca))
    run("issue", "--ca", str(ca), "--config", str(config),
        "--out", str(out))
    return {"ca": ca, "out": out}


class TestLabIssue:
    def test_ca_hierarchy_verifies(self, issued):
        ca = issued["ca"]
        for name in ("tls", "client"):
            openssl(
                "verify", "-CAfile", str(ca / "root-ca.pem"),
                str(ca / f"{name}-ca.pem"),
            )

    def test_server_cert_chains_and_has_san(self, issued):
        ca, out = issued["ca"], issued["out"]
        openssl(
            "verify", "-CAfile", str(ca / "root-ca.pem"),
            "-untrusted", str(ca / "tls-ca.pem"),
            str(out / "broker" / "server.pem"),
        )
        text = openssl(
            "x509", "-in", str(out / "broker" / "server.pem"),
            "-noout", "-text",
        )
        assert "DNS:broker.lab.test" in text
        assert "TLS Web Server Authentication" in text

    def test_client_cert_from_client_ca_with_clientauth(self, issued):
        ca, out = issued["ca"], issued["out"]
        cert = out / "uds" / "uds-client.pem"
        openssl(
            "verify", "-CAfile", str(ca / "root-ca.pem"),
            "-untrusted", str(ca / "client-ca.pem"), str(cert),
        )
        text = openssl("x509", "-in", str(cert), "-noout", "-text")
        assert "TLS Web Client Authentication" in text
        assert "CN = uds-server" in openssl(
            "x509", "-in", str(cert), "-noout", "-subject"
        )
        # Must NOT chain through the TLS issuing CA: the client CA is
        # the issuance service's authorization boundary.
        with pytest.raises(subprocess.CalledProcessError):
            openssl(
                "verify", "-CAfile", str(ca / "root-ca.pem"),
                "-untrusted", str(ca / "tls-ca.pem"),
                "-partial_chain", "-CAfile", str(ca / "tls-ca.pem"),
                str(cert),
            )

    def test_signing_key_pair_matches_and_kid_recorded(self, issued):
        broker = issued["out"] / "broker"
        derived = openssl(
            "pkey", "-in", str(broker / "baf-signing.key"), "-pubout"
        )
        assert derived == (broker / "baf-signing.pub").read_text()
        assert (broker / "baf-signing.kid").read_text().strip() == \
            "baf-signing-key-01"

    def test_vdi_bundles_complete(self, issued):
        for host in ("baflab-vdi-01", "baflab-vdi-02"):
            bundle = issued["out"] / f"vdi-{host}"
            for name in ("cert.pem", "key.pem", "baf-broker-public.pem",
                         "authorized_keys.snippet", "README"):
                assert (bundle / name).exists(), f"{host}: {name}"
            snippet = (bundle / "authorized_keys.snippet").read_text()
            assert snippet.startswith(
                f'command="baf-uds-register --target {host} '
            )
            assert ",restrict ssh-ed25519 " in snippet
            text = openssl(
                "x509", "-in", str(bundle / "cert.pem"), "-noout", "-text"
            )
            assert f"DNS:{host}" in text

    def test_trust_anchor_equals_signing_public_key(self, issued):
        out = issued["out"]
        anchor = out / "vdi-baflab-vdi-01" / "baf-broker-public.pem"
        assert anchor.read_bytes() == \
            (out / "broker" / "baf-signing.pub").read_bytes()

    def test_ca_bundles_distributed(self, issued):
        out = issued["out"]
        assert (out / "broker" / "clients-ca.pem").exists()
        assert (out / "uds" / "broker-ca.pem").exists()
        assert (out / "trust" / "root-ca.pem").exists()

    def test_private_keys_are_0600_or_tighter(self, issued):
        for key in issued["out"].rglob("*.key"):
            mode = stat.S_IMODE(key.stat().st_mode)
            assert mode & 0o077 == 0, f"{key} is mode {oct(mode)}"
        registrar = issued["out"] / "uds" / "registrar_ed25519"
        assert stat.S_IMODE(registrar.stat().st_mode) & 0o077 == 0


class TestCsrMode:
    def test_csr_mode_emits_csrs_and_no_ca(self, tmp_path):
        config = tmp_path / "pki.conf"
        config.write_text(CONFIG)
        out = tmp_path / "csr-out"
        run("csr", "--config", str(config), "--out", str(out))
        for csr in (
            out / "broker" / "server.csr",
            out / "uds" / "uds-client.csr",
            out / "vdi-baflab-vdi-01" / "cert.csr",
        ):
            assert csr.exists()
            openssl("req", "-in", str(csr), "-noout", "-verify")
        assert not (out / "trust").joinpath("root-ca.pem").exists()
        assert (out / "broker" / "baf-signing.key").exists()
        assert (out / "uds" / "registrar_ed25519").exists()

    def test_missing_config_value_fails(self, tmp_path):
        config = tmp_path / "pki.conf"
        config.write_text("BROKER_FQDN=broker.lab.test\n")
        with pytest.raises(subprocess.CalledProcessError) as excinfo:
            run("csr", "--config", str(config),
                "--out", str(tmp_path / "out"))
        assert "config must set" in excinfo.value.stderr
