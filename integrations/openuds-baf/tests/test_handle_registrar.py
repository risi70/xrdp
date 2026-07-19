import json
import os
import socket
import stat
import struct
import threading

import pytest

from BAFRDP.core import handle_socket
from BAFRDP.core.errors import (
    ConfigurationError,
    RegistrationError,
    TargetError,
)
from BAFRDP.core.handle_registrar import (
    SocketHandleRegistrar,
    SSHHandleRegistrar,
    validate_host,
    validate_target,
    validate_ttl,
)

HANDLE = "h" * 64


class TestValidators:
    def test_hosts(self):
        assert validate_host("203.0.113.10") == "203.0.113.10"
        assert validate_host("vdi-01.lab.example") == "vdi-01.lab.example"
        for bad in ("-oProxyCommand=x", "a b", "", "host;rm", None):
            with pytest.raises(TargetError):
                validate_host(bad)

    def test_targets_and_ttl(self):
        assert validate_target("baflab-vdi-01") == "baflab-vdi-01"
        for bad in ("", "with space", "x" * 256, None):
            with pytest.raises(TargetError):
                validate_target(bad)
        assert validate_ttl(90) == 90
        for bad in (0, 121, "90"):
            with pytest.raises(ConfigurationError):
                validate_ttl(bad)


@pytest.fixture
def fake_ssh(tmp_path):
    """A stand-in ssh binary that validates stdin and prints JSON."""
    script = tmp_path / "ssh"
    reply = json.dumps({"handle": HANDLE, "target": "baflab-vdi-01"})
    script.write_text(
        "#!/bin/sh\n"
        "assertion=$(cat)\n"
        "[ -n \"$assertion\" ] || { echo 'empty assertion' >&2; exit 1; }\n"
        f"printf '%s\\n' '{reply}'\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def registrar(tmp_path, **overrides):
    identity = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    identity.touch()
    known_hosts.touch()
    values = {
        "identity_file": str(identity),
        "known_hosts_file": str(known_hosts),
    }
    values.update(overrides)
    return SSHHandleRegistrar(**values)


class TestSSHRegistrar:
    def test_success(self, tmp_path, fake_ssh):
        subject = registrar(tmp_path, ssh_binary=str(fake_ssh))
        handle = subject.register(
            b"a.b.c", "203.0.113.10", "baflab-vdi-01", 90
        )
        assert handle == HANDLE

    def test_target_mismatch_rejected(self, tmp_path, fake_ssh):
        subject = registrar(tmp_path, ssh_binary=str(fake_ssh))
        with pytest.raises(RegistrationError):
            subject.register(b"a.b.c", "203.0.113.10", "other-target", 90)

    def test_nonzero_exit_fails_closed(self, tmp_path):
        failing = tmp_path / "ssh-fail"
        failing.write_text("#!/bin/sh\necho 'denied' >&2\nexit 255\n")
        failing.chmod(failing.stat().st_mode | stat.S_IEXEC)
        subject = registrar(tmp_path, ssh_binary=str(failing))
        with pytest.raises(RegistrationError, match="255"):
            subject.register(b"a.b.c", "203.0.113.10", "baflab-vdi-01", 90)

    def test_rejects_bad_configuration(self, tmp_path):
        with pytest.raises(ConfigurationError):
            registrar(tmp_path, user="Bad User")
        with pytest.raises(ConfigurationError):
            registrar(tmp_path, identity_file="")

    def test_rejects_oversized_assertion(self, tmp_path, fake_ssh):
        subject = registrar(tmp_path, ssh_binary=str(fake_ssh))
        with pytest.raises(RegistrationError):
            subject.register(
                b"x" * (handle_socket.MAX_ASSERTION + 1),
                "203.0.113.10", "baflab-vdi-01", 90,
            )


@pytest.fixture
def handle_service(tmp_path):
    """One-shot SEQPACKET server speaking the Handle wire protocol."""
    path = str(tmp_path / "baf-handle.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(path)
    server.listen(1)
    received = {}

    def serve():
        connection, _ = server.accept()
        with connection:
            request = connection.recv(handle_socket.MSG_SIZE)
            received["request"] = request
            packed = struct.pack(
                handle_socket._FMT,
                handle_socket.MAGIC, handle_socket.VERSION,
                handle_socket.OP_STORE, 0, 0, 0, 0,
                HANDLE.encode(), b"baflab-vdi-01", b"",
            )
            connection.send(packed + b"\x00" * handle_socket._PAD)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield path, received
    server.close()
    if os.path.exists(path):
        os.unlink(path)


class TestSocketRegistrar:
    def test_success(self, handle_service):
        path, received = handle_service
        subject = SocketHandleRegistrar(socket_path=path)
        handle = subject.register(b"a.b.c", "ignored", "baflab-vdi-01", 90)
        assert handle == HANDLE
        assert len(received["request"]) == handle_socket.MSG_SIZE

    def test_unavailable_socket_fails_closed(self, tmp_path):
        subject = SocketHandleRegistrar(
            socket_path=str(tmp_path / "missing.sock")
        )
        with pytest.raises(RegistrationError):
            subject.register(b"a.b.c", "ignored", "baflab-vdi-01", 90)
