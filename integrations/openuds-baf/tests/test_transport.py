"""Transport wiring tests against the fake OpenUDS API from conftest."""

import pytest

import udsfakes
from BAFRDP.core.errors import BrokerDeniedError
from BAFRDP.transport import BAFRDPTransport, USER_MESSAGES

HANDLE = "h" * 64


class StubUserService:
    def get_name(self):
        return "baflab-vdi-01"


class StubUser:
    name = "bafuser"
    uuid = "1234"


@pytest.fixture
def transport(monkeypatch):
    instance = BAFRDPTransport()

    class StubBroker:
        def issue(self, **kwargs):
            StubBroker.request = kwargs
            return b"a.b.c"

    class StubRegistrar:
        def register(self, assertion, host, target, ttl):
            StubRegistrar.request = {
                "assertion": assertion, "host": host,
                "target": target, "ttl": ttl,
            }
            return HANDLE

    monkeypatch.setattr(
        BAFRDPTransport, "_broker_client", lambda self: StubBroker()
    )
    monkeypatch.setattr(
        BAFRDPTransport, "_registrar", lambda self: StubRegistrar()
    )
    instance.stub_broker = StubBroker
    instance.stub_registrar = StubRegistrar
    return instance


def launch(transport, channel):
    transport.baf_channel.value = channel
    return transport.get_transport_script(
        StubUserService(), None, "203.0.113.10", "linux",
        StubUser(), "portal-password", None,
    )


def test_one_time_credential_forces_handle_as_password(transport):
    launch(transport, "one-time-credential")
    call = udsfakes.FakeRDPTransport.last_call
    assert call["password"] == HANDLE
    request = transport.stub_broker.request
    assert request["preferred_username"] == "bafuser"
    assert request["subject"] == "uds:1234"
    assert request["target"] == "baflab-vdi-01"
    registration = transport.stub_registrar.request
    assert registration["host"] == "203.0.113.10"
    assert registration["assertion"] == b"a.b.c"


def test_portal_password_never_reaches_the_client(transport):
    launch(transport, "one-time-credential")
    assert udsfakes.FakeRDPTransport.last_call["password"] != \
        "portal-password"


def test_routing_token_patches_script_parameters(transport):
    result = launch(transport, "routing-token")
    assert udsfakes.FakeRDPTransport.last_call["password"] == ""
    assert f"loadbalanceinfo:s:Cookie: msts={HANDLE}" \
        in result.parameters["as_file"]
    assert f"/load-balance-info:Cookie: msts={HANDLE}" \
        in result.parameters["as_new_xfreerdp_params"]


def test_broker_denial_maps_to_localized_transport_error(
    transport, monkeypatch
):
    class DenyingBroker:
        def issue(self, **kwargs):
            raise BrokerDeniedError("policy refused")

    monkeypatch.setattr(
        BAFRDPTransport, "_broker_client", lambda self: DenyingBroker()
    )
    with pytest.raises(udsfakes.FakeTransportError) as excinfo:
        launch(transport, "one-time-credential")
    assert str(excinfo.value) == USER_MESSAGES["broker_denied"]


def test_fixed_target_overrides_machine_name(transport):
    transport.baf_target.value = "fixed-target"
    launch(transport, "one-time-credential")
    assert transport.stub_broker.request["target"] == "fixed-target"


def test_camelcase_entry_point_delegates(transport):
    transport.getUDSTransportScript(
        StubUserService(), None, "203.0.113.10", "linux",
        StubUser(), "portal-password", None,
    )
    assert udsfakes.FakeRDPTransport.last_call["password"] == HANDLE


def test_metadata_present_for_both_loader_generations():
    assert BAFRDPTransport.type_type == "BAFRDPTransport"
    assert BAFRDPTransport.typeType == "BAFRDPTransport"
    assert BAFRDPTransport.type_name == BAFRDPTransport.typeName
