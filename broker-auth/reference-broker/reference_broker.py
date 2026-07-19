#!/usr/bin/env python3
"""Broker-neutral reference broker for BAF interoperability tests.

This module is intentionally outside XRDP core code. It models the minimum
interface an external broker needs in order to issue target-bound BAF
assertions and launch a standard RDSAAD-style RDP connection.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import jwt

_REFERENCE_ISSUER = Path(__file__).resolve().parents[1] / "reference-issuer"
import sys

if str(_REFERENCE_ISSUER) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_ISSUER))

from broker_issuer import build_claims, sign_claims


class BrokerError(ValueError):
    """The reference broker rejected the requested operation."""


@dataclass(frozen=True)
class BrokerTarget:
    """A broker-neutral desktop target."""

    name: str
    address: str
    audience: str


@dataclass(frozen=True)
class BrokerUser:
    """A broker-authenticated user known to the reference broker."""

    subject: str
    username: str
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ("desktop-user",)
    local_uid: int | None = None
    pam_allowed: bool = True


@dataclass(frozen=True)
class AuthContext:
    """Canonical authentication context supplied by a broker adapter."""

    auth_method: tuple[str, ...] = ("broker",)
    assurance_level: str = "mfa"
    device_trust: str = "unknown"

    def to_issuer_context(self) -> dict[str, Any]:
        return {
            "amr": list(self.auth_method),
            "acr": self.assurance_level,
            "device_trust": self.device_trust,
        }


@dataclass
class LocalAuthorizationPolicy:
    """Small deterministic stand-in for NSS/SSSD and PAM contract tests.

    XRDP production authorization still happens in sesexec. This policy exists
    only so broker conformance tests can prove that an adapter cannot turn a
    broker-only assertion into a session-ready result without local identity and
    PAM approval.
    """

    users: dict[str, BrokerUser]
    reject_uid0: bool = True

    def authorize(self, username: str) -> BrokerUser:
        user = self.users.get(username)
        if user is None:
            raise BrokerError("unknown local user")
        if not user.username or "/" in user.username or "\x00" in user.username:
            raise BrokerError("unsafe local username")
        if self.reject_uid0 and user.local_uid == 0:
            raise BrokerError("uid 0 is not allowed")
        if not user.pam_allowed:
            raise BrokerError("PAM account denied")
        return user


@dataclass
class ReplayLedger:
    """Single-use JTI ledger for reference broker conformance tests."""

    reserved: set[str] = field(default_factory=set)

    def reserve(self, issuer: str, jti: str) -> None:
        key = f"{issuer}\0{jti}"
        if key in self.reserved:
            raise BrokerError("replayed assertion")
        self.reserved.add(key)


@dataclass
class ReferenceBroker:
    """Broker-neutral reference implementation.

    Required interface:

    - create_session_assertion()
    - list_targets()
    - assign_target()
    - launch_connection()
    - revoke_session()
    """

    issuer: str
    key_id: str
    private_key: bytes
    default_audience: str
    targets: dict[str, BrokerTarget]
    users: dict[str, BrokerUser]
    policy: LocalAuthorizationPolicy
    lifetime: int = 300
    _assignments: dict[tuple[str, str], str] = field(default_factory=dict)
    _sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)

    def list_targets(self, user: str) -> list[BrokerTarget]:
        self.policy.authorize(user)
        return sorted(self.targets.values(), key=lambda target: target.name)

    def assign_target(self, user: str, target: str) -> str:
        self.policy.authorize(user)
        if target not in self.targets:
            raise BrokerError("unknown target")
        broker_session_id = str(uuid.uuid4())
        self._assignments[(user, target)] = broker_session_id
        return broker_session_id

    def create_session_assertion(
        self,
        user: str,
        target: str,
        broker_session_id: str,
        auth_context: AuthContext | Mapping[str, Any],
        *,
        now: int | None = None,
        jti: str | None = None,
        audience: str | Sequence[str] | None = None,
    ) -> str:
        broker_user = self.policy.authorize(user)
        broker_target = self._target(target)
        expected_session = self._assignments.get((user, target))
        if expected_session != broker_session_id:
            raise BrokerError("target is not assigned to this broker session")

        context = (
            auth_context.to_issuer_context()
            if isinstance(auth_context, AuthContext)
            else dict(auth_context)
        )
        claims = build_claims(
            issuer=self.issuer,
            audience=audience or broker_target.audience or self.default_audience,
            subject=broker_user.subject,
            preferred_username=broker_user.username,
            groups=broker_user.groups,
            roles=broker_user.roles,
            target=broker_target.name,
            session_id=broker_session_id,
            auth_context=context,
            now=now,
            lifetime=self.lifetime,
            jti=jti,
        )
        token = sign_claims(claims, self.private_key, key_id=self.key_id)
        self._sessions[broker_session_id] = {
            "user": user,
            "target": target,
            "jti": claims["jti"],
            "exp": claims["exp"],
        }
        return token

    def launch_connection(
        self,
        user: str,
        target: str,
        *,
        auth_context: AuthContext | Mapping[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        broker_session_id = self.assign_target(user, target)
        assertion = self.create_session_assertion(
            user,
            target,
            broker_session_id,
            auth_context or AuthContext(),
            now=now,
        )
        return {
            "protocol": "RDSAAD",
            "server": self._target(target).address,
            "target": target,
            "broker_session_id": broker_session_id,
            "authentication_request": build_rdsaad_authentication_request(
                assertion
            ),
        }

    def revoke_session(self, broker_session_id: str) -> None:
        self._revoked.add(broker_session_id)
        self._sessions.pop(broker_session_id, None)

    def _target(self, name: str) -> BrokerTarget:
        target = self.targets.get(name)
        if target is None:
            raise BrokerError("unknown target")
        return target


def build_rdsaad_authentication_request(assertion: str) -> bytes:
    """Build the JSON Authentication Request body used by the RDSAAD parser."""
    if not assertion:
        raise BrokerError("missing assertion")
    payload = {"rdp_assertion": assertion}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_unsigned_claims(assertion: str) -> dict[str, Any]:
    """Decode claims for tests without treating them as trusted."""
    return jwt.decode(assertion, options={"verify_signature": False})
