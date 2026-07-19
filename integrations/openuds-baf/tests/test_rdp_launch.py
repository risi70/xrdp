import pytest

from BAFRDP.core import rdp_launch
from BAFRDP.core.errors import ConfigurationError, TargetError

HANDLE = "h" * 64


def test_routing_token_cookie():
    assert rdp_launch.routing_token_cookie(HANDLE) == \
        f"Cookie: msts={HANDLE}"
    with pytest.raises(TargetError):
        rdp_launch.routing_token_cookie("short")


def test_channel_validation():
    for channel in rdp_launch.CHANNELS:
        assert rdp_launch.validate_channel(channel) == channel
    with pytest.raises(ConfigurationError):
        rdp_launch.validate_channel("password")


def test_rdp_file_lines_routing_token():
    lines = rdp_launch.rdp_file_lines(
        address="203.0.113.10", port=3389, username="bafuser",
        channel=rdp_launch.CHANNEL_ROUTING_TOKEN, handle=HANDLE,
    )
    assert f"loadbalanceinfo:s:Cookie: msts={HANDLE}" in lines
    assert "enablecredsspsupport:i:0" in lines


def test_rdp_file_lines_one_time_credential_has_no_cookie():
    lines = rdp_launch.rdp_file_lines(
        address="203.0.113.10", port=3389, username="bafuser",
        channel=rdp_launch.CHANNEL_ONE_TIME_CREDENTIAL, handle=HANDLE,
    )
    assert not any("loadbalanceinfo" in line for line in lines)


def test_xfreerdp_arguments_by_channel():
    routed = rdp_launch.xfreerdp_arguments(
        address="vdi-01.lab", port=3389, username="bafuser",
        channel=rdp_launch.CHANNEL_ROUTING_TOKEN, handle=HANDLE,
    )
    assert f"/load-balance-info:Cookie: msts={HANDLE}" in routed
    credential = rdp_launch.xfreerdp_arguments(
        address="vdi-01.lab", port=3389, username="bafuser",
        channel=rdp_launch.CHANNEL_ONE_TIME_CREDENTIAL, handle=HANDLE,
    )
    assert f"/p:{HANDLE}" in credential


def test_rejects_bad_inputs():
    with pytest.raises(TargetError):
        rdp_launch.rdp_file_lines(
            address="bad host", port=3389, username="u",
            channel=rdp_launch.CHANNEL_ROUTING_TOKEN, handle=HANDLE,
        )
    with pytest.raises(ConfigurationError):
        rdp_launch.xfreerdp_arguments(
            address="vdi-01.lab", port=0, username="u",
            channel=rdp_launch.CHANNEL_ROUTING_TOKEN, handle=HANDLE,
        )
