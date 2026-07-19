"""Register broker-issued assertions with a VDI host's Handle service.

Two production backends:

``SSHHandleRegistrar``
    Runs ``baf-uds-register`` on the VDI host over SSH with a dedicated
    key. The assertion travels on stdin, never on the command line. The
    account on the VDI host should be restricted with a forced command
    (see the plugin README) and must have group access to the Handle
    socket only.

``SocketHandleRegistrar``
    Speaks the SEQPACKET protocol directly to a local or securely
    forwarded Handle socket, for brokers co-located with the VDI host.

Both return the single-use handle text and fail closed on any anomaly.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass

from . import handle_socket
from .errors import ConfigurationError, RegistrationError, TargetError

HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{64}$")
_TARGET_RE = re.compile(r"^[\x21-\x7e]{1,255}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*$"
)
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def validate_target(target: str) -> str:
    if not isinstance(target, str) or not _TARGET_RE.match(target):
        raise TargetError("target must be 1-255 printable characters")
    return target


def validate_host(host: str) -> str:
    """Accept a hostname or IP literal; reject anything argv-unsafe."""
    if isinstance(host, str):
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if _HOSTNAME_RE.match(host) and not host.startswith("-"):
            return host
    raise TargetError("host must be a hostname or IP literal")


def validate_ttl(ttl_seconds: int) -> int:
    if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 120:
        raise ConfigurationError("handle TTL must be between 1 and 120")
    return ttl_seconds


def validate_handle(handle: str) -> str:
    if not isinstance(handle, str) or not HANDLE_RE.match(handle):
        raise RegistrationError("registration returned a malformed handle")
    return handle


@dataclass(frozen=True)
class SSHHandleRegistrar:
    """Register via ``ssh <host> baf-uds-register`` with stdin transport."""

    identity_file: str
    known_hosts_file: str
    user: str = "baf-register"
    port: int = 22
    command: str = "baf-uds-register"
    connect_timeout: int = 5
    ssh_binary: str = "ssh"

    def __post_init__(self) -> None:
        if not self.identity_file or not self.known_hosts_file:
            raise ConfigurationError(
                "SSH registrar needs an identity file and a known_hosts file"
            )
        if not _USER_RE.match(self.user):
            raise ConfigurationError("SSH user name is not acceptable")
        if not 1 <= int(self.port) <= 65535:
            raise ConfigurationError("SSH port is out of range")

    def register(
        self, assertion: bytes, host: str, target: str, ttl_seconds: int
    ) -> str:
        validate_host(host)
        validate_target(target)
        validate_ttl(ttl_seconds)
        if not assertion or len(assertion) > handle_socket.MAX_ASSERTION:
            raise RegistrationError("assertion is empty or oversized")

        argv = [
            self.ssh_binary,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts_file}",
            "-o", f"ConnectTimeout={int(self.connect_timeout)}",
            "-o", "IdentitiesOnly=yes",
            "-i", self.identity_file,
            "-p", str(int(self.port)),
            "-l", self.user,
            "--",
            host,
            # The forced command on the VDI host should pin this exact
            # invocation; the arguments are also passed for auditability.
            self.command,
            "--target", target,
            "--ttl", str(ttl_seconds),
            "--format", "json",
        ]
        try:
            completed = subprocess.run(
                argv,
                input=assertion,
                capture_output=True,
                timeout=self.connect_timeout + 10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RegistrationError(
                f"registration transport failed: {exc.__class__.__name__}"
            ) from exc
        if completed.returncode != 0:
            # stderr from baf-uds-register never contains the assertion or
            # the handle; keep only its first line for diagnostics.
            first_line = completed.stderr.decode(
                "utf-8", "replace"
            ).splitlines()[:1]
            raise RegistrationError(
                f"registration exited {completed.returncode}: "
                f"{first_line[0] if first_line else 'no diagnostics'}"
            )
        return self._parse_reply(completed.stdout, target)

    @staticmethod
    def _parse_reply(stdout: bytes, target: str) -> str:
        try:
            reply = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistrationError("registration reply is not JSON") from exc
        if not isinstance(reply, dict) or reply.get("target") != target:
            raise RegistrationError("registration reply target mismatch")
        return validate_handle(reply.get("handle"))


@dataclass(frozen=True)
class SocketHandleRegistrar:
    """Register through a local or securely forwarded Handle socket."""

    socket_path: str
    timeout_ms: int = 2000

    def __post_init__(self) -> None:
        if not self.socket_path:
            raise ConfigurationError("handle socket path is required")

    def register(
        self, assertion: bytes, host: str, target: str, ttl_seconds: int
    ) -> str:
        del host  # co-located: the socket already selects the VDI host
        validate_target(target)
        validate_ttl(ttl_seconds)
        try:
            handle = handle_socket.store(
                self.socket_path,
                assertion,
                target,
                ttl_seconds,
                timeout_ms=self.timeout_ms,
            )
        except (OSError, handle_socket.HandleError) as exc:
            raise RegistrationError(f"handle service: {exc}") from exc
        return validate_handle(handle)
