"""Compose client-side RDP launch material for a registered handle.

Only the single-use handle ever reaches the client: either as an
``msts=`` routing-token cookie (pre-MCS Handle channel) or as the
password-shaped one-time credential (Mode C). The BAF assertion itself
never leaves the server side. Both channels work with stock RDP clients;
no plugin, DVC, or custom client is required.
"""

from __future__ import annotations

from .errors import ConfigurationError, TargetError
from .handle_registrar import HANDLE_RE, validate_host

CHANNEL_ROUTING_TOKEN = "routing-token"
CHANNEL_ONE_TIME_CREDENTIAL = "one-time-credential"
CHANNELS = (CHANNEL_ROUTING_TOKEN, CHANNEL_ONE_TIME_CREDENTIAL)


def validate_channel(channel: str) -> str:
    if channel not in CHANNELS:
        raise ConfigurationError(f"unknown ingress channel: {channel!r}")
    return channel


def routing_token_cookie(handle: str) -> str:
    """RDP routing-token line carried in load-balance-info."""
    if not HANDLE_RE.match(handle):
        raise TargetError("refusing to embed a malformed handle")
    return f"Cookie: msts={handle}"


def rdp_file_lines(
    *,
    address: str,
    port: int,
    username: str,
    channel: str,
    handle: str,
) -> list[str]:
    """Lines to merge into a generated .rdp document.

    For the routing-token channel this adds ``loadbalanceinfo``; for the
    one-time credential channel the caller passes the handle through the
    transport's password parameter instead and no extra line is needed.
    """
    validate_host(address)
    if not 1 <= int(port) <= 65535:
        raise ConfigurationError("RDP port is out of range")
    if not username:
        raise TargetError("username is required")
    lines = [
        f"full address:s:{address}:{int(port)}",
        f"username:s:{username}",
        # CredSSP/NLA is not part of the BAF boundary; the Handle channels
        # authenticate at the XRDP layer.
        "enablecredsspsupport:i:0",
    ]
    if validate_channel(channel) == CHANNEL_ROUTING_TOKEN:
        lines.append(f"loadbalanceinfo:s:{routing_token_cookie(handle)}")
    return lines


def xfreerdp_arguments(
    *,
    address: str,
    port: int,
    username: str,
    channel: str,
    handle: str,
) -> list[str]:
    """Arguments to append to an xfreerdp invocation for this channel.

    The one-time credential intentionally rides the standard ``/p:``
    option: it is a random single-use server-side reference, not a
    password or an assertion.
    """
    validate_host(address)
    if not 1 <= int(port) <= 65535:
        raise ConfigurationError("RDP port is out of range")
    if not username:
        raise TargetError("username is required")
    arguments = [f"/v:{address}:{int(port)}", f"/u:{username}", "/sec:tls"]
    if validate_channel(channel) == CHANNEL_ROUTING_TOKEN:
        arguments.append(
            f"/load-balance-info:{routing_token_cookie(handle)}"
        )
    else:
        if not HANDLE_RE.match(handle):
            raise TargetError("refusing to embed a malformed handle")
        arguments.append(f"/p:{handle}")
    return arguments
