#!/usr/bin/env python3
"""UDS simulator adapter for the broker-neutral BAF reference broker.

The adapter translates UDS-like objects into broker-neutral users and targets.
It is intentionally not imported by XRDP core code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

REFERENCE_BROKER = Path(__file__).resolve().parents[1]
if str(REFERENCE_BROKER) not in sys.path:
    sys.path.insert(0, str(REFERENCE_BROKER))

from reference_broker import AuthContext, BrokerTarget, BrokerUser


@dataclass(frozen=True)
class UdsUser:
    id: str
    login: str
    local_username: str
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ("desktop-user",)
    uid: int | None = None
    pam_allowed: bool = True


@dataclass(frozen=True)
class UdsResource:
    id: str
    name: str
    address: str
    audience: str


@dataclass(frozen=True)
class UdsSession:
    id: str
    user_id: str
    resource_id: str
    assurance_level: str = "mfa"
    auth_methods: tuple[str, ...] = ("broker",)


class UdsSimulatorAdapter:
    """Translate UDS-like entities into broker-neutral BAF concepts."""

    def __init__(
        self,
        users: dict[str, UdsUser],
        resources: dict[str, UdsResource],
        sessions: dict[str, UdsSession],
    ) -> None:
        self.users = dict(users)
        self.resources = dict(resources)
        self.sessions = dict(sessions)

    def broker_users(self) -> dict[str, BrokerUser]:
        result: dict[str, BrokerUser] = {}
        for user in self.users.values():
            result[user.local_username] = BrokerUser(
                subject=user.id,
                username=user.local_username,
                groups=user.groups,
                roles=user.roles,
                local_uid=user.uid,
                pam_allowed=user.pam_allowed,
            )
        return result

    def broker_targets(self) -> dict[str, BrokerTarget]:
        result: dict[str, BrokerTarget] = {}
        for resource in self.resources.values():
            result[resource.name] = BrokerTarget(
                name=resource.name,
                address=resource.address,
                audience=resource.audience,
            )
        return result

    def resolve_session(self, session_id: str) -> tuple[str, str, AuthContext]:
        session = self.sessions.get(session_id)
        if session is None:
            raise KeyError("unknown UDS session")
        user = self.users[session.user_id]
        resource = self.resources[session.resource_id]
        return (
            user.local_username,
            resource.name,
            AuthContext(
                auth_method=session.auth_methods,
                assurance_level=session.assurance_level,
                device_trust="unknown",
            ),
        )
