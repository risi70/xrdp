"""BAF RDP transport for OpenUDS / UDS Enterprise.

Extends the stock RDP transport so the signed stock client scripts, OS
support, and RDP option handling are reused unchanged. What this class
adds, server-side and per launch:

1. request a BAF assertion for the portal-authenticated user and the
   selected machine from the trusted broker (mutual TLS);
2. register the assertion with the machine's Handle service, obtaining a
   single-use handle (SSH or co-located socket backend);
3. hand the client only the handle — as the one-time credential in the
   password parameter (default; works with every stock client path) or
   as an ``msts=`` routing-token cookie merged into the generated RDP
   material.

The assertion never reaches the client, a log, a URL, or a command
line. Failures deny the launch with a localized, non-technical portal
message; details go to the server log without secret material.
"""

from __future__ import annotations

import logging
import uuid

from . import _compat
from .core import rdp_launch
from .core.broker_client import BrokerClient, BrokerClientConfig
from .core.errors import BafTransportError, ConfigurationError
from .core.handle_registrar import (
    SocketHandleRegistrar,
    SSHHandleRegistrar,
    validate_target,
)

logger = logging.getLogger(__name__)

_noop, _ = _compat.gettext_tools()

gui = _compat.load_gui()
_RDPTransportBase = _compat.load_rdp_transport_base()

# Portal-facing error messages, one per stable error code. msgids are
# collected into the shipped locale catalogs.
USER_MESSAGES = {
    "configuration_invalid": _noop(
        "The desktop service is not configured correctly. "
        "Please contact your administrator."
    ),
    "broker_unreachable": _noop(
        "The sign-on service is temporarily unavailable. "
        "Please try again in a moment."
    ),
    "broker_denied": _noop(
        "You are not authorized to open this desktop."
    ),
    "registration_failed": _noop(
        "The desktop could not be prepared for your session. "
        "Please try again or contact your administrator."
    ),
    "target_invalid": _noop(
        "The requested desktop is not available."
    ),
    "internal_error": _noop(
        "An unexpected error occurred while starting your desktop."
    ),
}

_TAB_BAF = _noop("BAF Broker")


class BAFRDPTransport(_RDPTransportBase):
    """RDP over the XRDP Broker Authentication Framework."""

    # Both attribute spellings are populated so the 3.x and 4.x loaders
    # find the metadata they expect.
    type_name = typeName = _noop("RDP (BAF broker)")
    type_type = typeType = "BAFRDPTransport"
    type_description = typeDescription = _noop(
        "RDP protected by the XRDP Broker Authentication Framework: "
        "single-use handles issued by a trusted broker replace passwords."
    )

    baf_broker_url = _compat.make_field(
        gui, "TextField",
        label=_noop("Broker issuance URL"),
        tooltip=_noop(
            "HTTPS endpoint of the trusted BAF broker issuance API"
        ),
        default="",
        order=110, tab=_TAB_BAF, required=True,
    )
    baf_broker_ca = _compat.make_field(
        gui, "TextField",
        label=_noop("Broker CA bundle"),
        tooltip=_noop(
            "Path to the CA bundle that authenticates the broker"
        ),
        default="/etc/uds/baf/broker-ca.pem",
        order=111, tab=_TAB_BAF, required=True,
    )
    baf_client_cert = _compat.make_field(
        gui, "TextField",
        label=_noop("Client certificate"),
        tooltip=_noop(
            "Path to this server's mutual-TLS client certificate"
        ),
        default="/etc/uds/baf/uds-client.pem",
        order=112, tab=_TAB_BAF, required=True,
    )
    baf_client_key = _compat.make_field(
        gui, "TextField",
        label=_noop("Client private key"),
        tooltip=_noop(
            "Path to this server's mutual-TLS private key"
        ),
        default="/etc/uds/baf/uds-client.key",
        order=113, tab=_TAB_BAF, required=True,
    )
    baf_registrar = _compat.make_field(
        gui, "ChoiceField",
        label=_noop("Handle registration backend"),
        tooltip=_noop(
            "How the assertion is registered with the desktop host"
        ),
        choices=[
            {"id": "ssh", "text": _noop("SSH to the desktop host")},
            {"id": "socket", "text": _noop("Local or forwarded socket")},
        ],
        default="ssh",
        order=120, tab=_TAB_BAF, required=True,
    )
    baf_ssh_identity = _compat.make_field(
        gui, "TextField",
        label=_noop("SSH identity file"),
        tooltip=_noop(
            "Dedicated private key for the registration account; "
            "pair it with a forced command on the desktop host"
        ),
        default="/etc/uds/baf/registrar_ed25519",
        order=121, tab=_TAB_BAF,
    )
    baf_ssh_known_hosts = _compat.make_field(
        gui, "TextField",
        label=_noop("SSH known_hosts file"),
        tooltip=_noop("Pinned host keys of the desktop hosts"),
        default="/etc/uds/baf/known_hosts",
        order=122, tab=_TAB_BAF,
    )
    baf_ssh_user = _compat.make_field(
        gui, "TextField",
        label=_noop("SSH user"),
        tooltip=_noop("Registration account on the desktop host"),
        default="baf-register",
        order=123, tab=_TAB_BAF,
    )
    baf_handle_socket = _compat.make_field(
        gui, "TextField",
        label=_noop("Handle socket path"),
        tooltip=_noop(
            "Handle service socket for the socket backend"
        ),
        default="/run/xrdp/baf-handle.sock",
        order=124, tab=_TAB_BAF,
    )
    baf_channel = _compat.make_field(
        gui, "ChoiceField",
        label=_noop("Ingress channel"),
        tooltip=_noop(
            "How the single-use handle reaches the desktop host"
        ),
        choices=[
            {
                "id": rdp_launch.CHANNEL_ONE_TIME_CREDENTIAL,
                "text": _noop("One-time credential (password field)"),
            },
            {
                "id": rdp_launch.CHANNEL_ROUTING_TOKEN,
                "text": _noop("Routing token (load-balance-info)"),
            },
        ],
        default=rdp_launch.CHANNEL_ONE_TIME_CREDENTIAL,
        order=130, tab=_TAB_BAF, required=True,
    )
    baf_handle_ttl = _compat.make_field(
        gui, "NumericField",
        label=_noop("Handle lifetime (seconds)"),
        tooltip=_noop(
            "Validity window of the single-use handle (1-120)"
        ),
        default=90,
        order=131, tab=_TAB_BAF,
    )
    baf_target = _compat.make_field(
        gui, "TextField",
        label=_noop("Fixed BAF target"),
        tooltip=_noop(
            "Optional fixed target identifier; when empty the machine "
            "name of the assigned desktop is used"
        ),
        default="",
        order=132, tab=_TAB_BAF,
    )

    # -- configuration -> validated collaborators --------------------------

    def _broker_client(self) -> BrokerClient:
        return BrokerClient(BrokerClientConfig(
            base_url=str(_compat.field_value(self.baf_broker_url)).strip(),
            ca_file=str(_compat.field_value(self.baf_broker_ca)).strip(),
            client_cert=str(
                _compat.field_value(self.baf_client_cert)
            ).strip(),
            client_key=str(_compat.field_value(self.baf_client_key)).strip(),
        ))

    def _registrar(self):
        backend = str(_compat.field_value(self.baf_registrar))
        if backend == "ssh":
            return SSHHandleRegistrar(
                identity_file=str(
                    _compat.field_value(self.baf_ssh_identity)
                ).strip(),
                known_hosts_file=str(
                    _compat.field_value(self.baf_ssh_known_hosts)
                ).strip(),
                user=str(_compat.field_value(self.baf_ssh_user)).strip(),
            )
        if backend == "socket":
            return SocketHandleRegistrar(
                socket_path=str(
                    _compat.field_value(self.baf_handle_socket)
                ).strip(),
            )
        raise ConfigurationError(f"unknown registrar backend: {backend!r}")

    def _resolve_target(self, userservice) -> str:
        fixed = str(_compat.field_value(self.baf_target)).strip()
        if fixed:
            return validate_target(fixed)
        for accessor in ("get_name", "getName", "friendly_name", "name"):
            candidate = getattr(userservice, accessor, None)
            if candidate is None:
                continue
            value = candidate() if callable(candidate) else candidate
            if value:
                return validate_target(str(value))
        raise ConfigurationError("cannot determine the BAF target name")

    @staticmethod
    def _portal_identity(user) -> tuple[str, str]:
        """Return (subject, preferred_username) for the portal user."""
        name = getattr(user, "name", None) or getattr(user, "login", None)
        if callable(name):
            name = name()
        if not name:
            raise ConfigurationError("portal user has no usable login name")
        unique = getattr(user, "uuid", None)
        if callable(unique):
            unique = unique()
        return (f"uds:{unique or name}", str(name))

    # -- launch pipeline ---------------------------------------------------

    def _obtain_handle(self, userservice, user, ip: str) -> tuple[str, str]:
        """Issue and register; return (handle, channel). Fails closed."""
        target = self._resolve_target(userservice)
        subject, username = self._portal_identity(user)
        channel = rdp_launch.validate_channel(
            str(_compat.field_value(self.baf_channel))
        )
        ttl = int(_compat.field_value(self.baf_handle_ttl))
        assertion = self._broker_client().issue(
            subject=subject,
            preferred_username=username,
            target=target,
            broker_session_id=f"uds-{uuid.uuid4().hex}",
        )
        try:
            handle = self._registrar().register(assertion, ip, target, ttl)
        finally:
            del assertion
        logger.info(
            "BAFRDP: prepared %s launch for user %r target %r",
            channel, username, target,
        )
        return handle, channel

    def get_transport_script(
        self, userservice, transport, ip, os, user, password, request
    ):
        try:
            handle, channel = self._obtain_handle(userservice, user, ip)
        except BafTransportError as exc:
            logger.warning(
                "BAFRDP launch denied (%s): %s", exc.code, exc.detail
            )
            raise self._deny(exc.code) from exc

        if channel == rdp_launch.CHANNEL_ONE_TIME_CREDENTIAL:
            # The handle rides the standard password parameter through the
            # stock, signed transport script. It is a random single-use
            # server-side reference, not a password or an assertion.
            return self._parent_script(
                userservice, transport, ip, os, user, handle, request
            )

        result = self._parent_script(
            userservice, transport, ip, os, user, "", request
        )
        parameters = _compat.script_parameters(result)
        cookie = rdp_launch.routing_token_cookie(handle)
        if isinstance(parameters.get("as_file"), str):
            parameters["as_file"] += f"\nloadbalanceinfo:s:{cookie}"
        for key in ("as_new_xfreerdp_params", "as_rdesktop_params"):
            if isinstance(parameters.get(key), list):
                parameters[key].append(f"/load-balance-info:{cookie}")
        return result

    # 3.x loaders look up the camelCase spelling.
    def getUDSTransportScript(  # noqa: N802 - OpenUDS 3.x API name
        self, userService, transport, ip, os, user, password, request
    ):
        return self.get_transport_script(
            userService, transport, ip, os, user, password, request
        )

    def _parent_script(
        self, userservice, transport, ip, os, user, password, request
    ):
        parent = getattr(
            super(), "get_transport_script", None
        ) or getattr(super(), "getUDSTransportScript")
        return parent(
            userservice, transport, ip, os, user, password, request
        )

    @staticmethod
    def _deny(code: str) -> Exception:
        message = _(USER_MESSAGES.get(code, USER_MESSAGES["internal_error"]))
        try:
            from uds.core.exceptions.services import (
                TransportError,  # OpenUDS 4.x
            )
            return TransportError(message)
        except ImportError:
            pass
        try:
            from uds.core.services.exceptions import TransportError  # 3.x
            return TransportError(message)
        except ImportError:  # pragma: no cover - last resort
            return BafTransportError(message)
