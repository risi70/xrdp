"""Coded errors for the BAF OpenUDS transport.

Every failure carries a stable machine code so the transport layer can map it
to a localized portal message while logging only non-secret detail. Raw
tokens, assertions, and handles must never appear in ``detail``.
"""

from __future__ import annotations


class BafTransportError(RuntimeError):
    """Base error; ``code`` selects the localized portal message."""

    code = "internal_error"

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or self.code)
        self.detail = detail


class ConfigurationError(BafTransportError):
    """The transport is misconfigured; fail closed before any network I/O."""

    code = "configuration_invalid"


class BrokerUnreachableError(BafTransportError):
    """The broker issuance service could not be reached in time."""

    code = "broker_unreachable"


class BrokerDeniedError(BafTransportError):
    """The broker refused to issue an assertion for this user/target."""

    code = "broker_denied"


class RegistrationError(BafTransportError):
    """Handle registration with the target VDI host failed."""

    code = "registration_failed"


class TargetError(BafTransportError):
    """The requested target identifier or address is not acceptable."""

    code = "target_invalid"
