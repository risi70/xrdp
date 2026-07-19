"""A minimal fake OpenUDS 4.x API surface for tests.

``install_fake_uds()`` must run before ``BAFRDP`` is imported so the
plugin's compat layer resolves against a stable, known shape.
"""

from __future__ import annotations

import sys
import types

class FakeField:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.value = kwargs.get("default", "")


class FakeGui:
    TextField = FakeField
    ChoiceField = FakeField
    NumericField = FakeField


class FakeTransportScript:
    def __init__(self, parameters):
        self.parameters = parameters


class FakeRDPTransport:
    """Stands in for the stock OpenUDS RDP transport."""

    last_call = None

    def get_transport_script(
        self, userservice, transport, ip, os, user, password, request
    ):
        FakeRDPTransport.last_call = {
            "ip": ip, "user": user, "password": password,
        }
        return FakeTransportScript({
            "as_file": "full address:s:203.0.113.10:3389",
            "as_new_xfreerdp_params": ["/v:203.0.113.10:3389"],
        })


class FakeTransportError(Exception):
    pass


def _module(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


def install_fake_uds() -> None:
    uds = _module("uds")
    core = _module("uds.core")
    ui = _module("uds.core.ui")
    ui.gui = FakeGui
    exceptions = _module("uds.core.exceptions")
    services = _module("uds.core.exceptions.services")
    services.TransportError = FakeTransportError
    transports = _module("uds.transports")
    rdp = _module("uds.transports.RDP")
    rdp_transport = _module("uds.transports.RDP.transport")
    rdp_transport.RDPTransport = FakeRDPTransport
    uds.core = core
    core.ui = ui
    core.exceptions = exceptions
    exceptions.services = services
    uds.transports = transports
    transports.RDP = rdp
    rdp.transport = rdp_transport
