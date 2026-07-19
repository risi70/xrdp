"""Version compatibility layer for the OpenUDS / UDS Enterprise API.

The plugin supports OpenUDS 4.x (snake_case core API) and the 3.6 LTS
line (camelCase). Everything version-dependent is resolved here once so
``transport.py`` stays readable. Resolution is strict: if the running
server exposes neither known shape, the plugin refuses to load rather
than guessing (fail closed).
"""

from __future__ import annotations

import importlib
from typing import Any, Callable

# Candidate module paths for the stock RDP transport we extend, newest
# first. UDS Enterprise ships the same tree as OpenUDS for these modules.
_RDP_TRANSPORT_CANDIDATES = (
    ("uds.transports.RDP.transport", "RDPTransport"),
    ("uds.transports.RDP.rdptransport", "RDPTransport"),
    ("uds.transports.RDP.rdp", "RDPTransport"),
)


def gettext_tools() -> tuple[Callable[[str], str], Callable[[str], str]]:
    """Return (gettext_noop, gettext) from Django, or identity fallbacks.

    The identity fallback only triggers outside a Django runtime (unit
    tests); inside OpenUDS Django is always importable.
    """
    try:
        from django.utils.translation import gettext, gettext_noop
        return gettext_noop, gettext
    except Exception:  # pragma: no cover - exercised only without Django
        return (lambda text: text), (lambda text: text)


def load_gui() -> Any:
    """Return the OpenUDS form-field factory module (``gui``)."""
    return importlib.import_module("uds.core.ui").gui


def load_rdp_transport_base() -> type:
    """Locate the stock RDP transport class to subclass."""
    for module_name, class_name in _RDP_TRANSPORT_CANDIDATES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        base = getattr(module, class_name, None)
        if isinstance(base, type):
            return base
    raise ImportError(
        "BAFRDP: no known OpenUDS RDP transport implementation found; "
        "supported are OpenUDS 4.x and 3.6"
    )


def make_field(gui: Any, kind: str, **kwargs: Any) -> Any:
    """Create a gui field across the 4.x/3.x keyword drift.

    4.x uses ``default=``/``readonly=``; 3.x uses ``defvalue=``/
    ``rdonly=``. Values are passed with 4.x names and translated on
    TypeError.
    """
    factory = getattr(gui, kind)
    try:
        return factory(**kwargs)
    except TypeError:
        renames = {"default": "defvalue", "readonly": "rdonly"}
        translated = {renames.get(key, key): value
                      for key, value in kwargs.items()}
        if "defvalue" in translated:
            translated["defvalue"] = str(translated["defvalue"])
        return factory(**translated)


def field_value(field: Any) -> str:
    """Read a gui field's current value across versions."""
    for attribute in ("value", "num", "isTrue"):
        if hasattr(field, attribute):
            value = getattr(field, attribute)
            return value() if callable(value) else value
    raise AttributeError("unsupported gui field object")


def script_parameters(transport_script: Any) -> dict:
    """Return the mutable parameter dict of a TransportScript result."""
    for attribute in ("parameters", "params"):
        parameters = getattr(transport_script, attribute, None)
        if isinstance(parameters, dict):
            return parameters
    if isinstance(transport_script, tuple) and len(transport_script) >= 3 \
            and isinstance(transport_script[2], dict):
        return transport_script[2]
    raise TypeError("unsupported TransportScript result shape")
