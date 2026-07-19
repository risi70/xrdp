"""Mutual-TLS client for the trusted broker's BAF assertion issuance API.

The broker owns the BAF signing key and all issuance policy; this client only
requests an assertion for an already portal-authenticated user and returns it
opaquely. The assertion is credential-grade material: it is kept in memory,
never logged, and never placed on a command line or in a URL.

API contract (documented in the plugin README):

    POST {base_url}/v1/assertions
    Content-Type: application/json
    {
      "subject": "...", "preferred_username": "...", "target": "...",
      "broker_session_id": "...", "auth_method": ["broker"],
      "assurance_level": "mfa", "device_trust": "unknown"
    }

    200 -> {"assertion": "<compact JWS>"}
    403 -> issuance denied by broker policy
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Sequence

from .errors import (
    BrokerDeniedError,
    BrokerUnreachableError,
    ConfigurationError,
)

MAX_ASSERTION = 16384          # matches BAF_HANDLE_MAX_ASSERTION
MAX_RESPONSE = 64 * 1024
_JWS_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_FIELD_RE = re.compile(r"^[\x21-\x7e]{1,255}$")   # printable, no spaces


def _require_field(value: str, name: str) -> str:
    if not isinstance(value, str) or not _FIELD_RE.match(value):
        raise ConfigurationError(f"{name} must be 1-255 printable characters")
    return value


@dataclass(frozen=True)
class BrokerClientConfig:
    """Validated connection settings for the broker issuance endpoint."""

    base_url: str
    ca_file: str
    client_cert: str
    client_key: str
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://"):
            raise ConfigurationError("broker base URL must use https")
        if not (1.0 <= float(self.timeout_seconds) <= 30.0):
            raise ConfigurationError(
                "broker timeout must be between 1 and 30 seconds"
            )
        for name in ("ca_file", "client_cert", "client_key"):
            if not getattr(self, name):
                raise ConfigurationError(f"broker {name} is required")


class BrokerClient:
    """Issue BAF assertions over mutually authenticated HTTPS."""

    def __init__(self, config: BrokerClientConfig) -> None:
        self._config = config

    def _ssl_context(self) -> ssl.SSLContext:
        try:
            context = ssl.create_default_context(
                cafile=self._config.ca_file
            )
            context.load_cert_chain(
                self._config.client_cert, self._config.client_key
            )
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(
                f"broker TLS material unusable: {exc.__class__.__name__}"
            ) from exc
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def issue(
        self,
        *,
        subject: str,
        preferred_username: str,
        target: str,
        broker_session_id: str,
        auth_method: Sequence[str] = ("broker",),
        assurance_level: str = "mfa",
        device_trust: str = "unknown",
    ) -> bytes:
        """Request an assertion; return it as bytes. Fails closed."""
        body = json.dumps({
            "subject": _require_field(subject, "subject"),
            "preferred_username": _require_field(
                preferred_username, "preferred_username"
            ),
            "target": _require_field(target, "target"),
            "broker_session_id": _require_field(
                broker_session_id, "broker_session_id"
            ),
            "auth_method": [
                _require_field(item, "auth_method") for item in auth_method
            ],
            "assurance_level": _require_field(
                assurance_level, "assurance_level"
            ),
            "device_trust": _require_field(device_trust, "device_trust"),
        }).encode("utf-8")

        request = urllib.request.Request(
            self._config.base_url.rstrip("/") + "/v1/assertions",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._config.timeout_seconds,
                context=self._ssl_context(),
            ) as response:
                payload = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            # 4xx means the broker evaluated and refused; anything else is
            # an availability problem. Never include the response body.
            if 400 <= exc.code < 500:
                raise BrokerDeniedError(
                    f"broker refused issuance (HTTP {exc.code})"
                ) from exc
            raise BrokerUnreachableError(
                f"broker error (HTTP {exc.code})"
            ) from exc
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            raise BrokerUnreachableError(
                f"broker unreachable: {exc.__class__.__name__}"
            ) from exc

        return self._parse_assertion(payload)

    @staticmethod
    def _parse_assertion(payload: bytes) -> bytes:
        if len(payload) > MAX_RESPONSE:
            raise BrokerDeniedError("broker response exceeds size limit")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerDeniedError("broker response is not valid JSON") \
                from exc
        assertion = document.get("assertion") \
            if isinstance(document, dict) else None
        if not isinstance(assertion, str) or not _JWS_RE.match(assertion):
            raise BrokerDeniedError("broker response lacks a usable assertion")
        encoded = assertion.encode("ascii")
        if len(encoded) > MAX_ASSERTION:
            raise BrokerDeniedError("assertion exceeds the BAF size limit")
        return encoded
