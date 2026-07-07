#!/usr/bin/env python3
"""UDS adapter skeleton for Phase 5.

This file documents the production adapter shape without binding XRDP core to a
specific UDS API. The simulator in uds_adapter.py provides deterministic tests.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UdsBrokerRecord:
    user_id: str
    local_username: str
    service_or_pool: str
    assigned_vm: str
    session_id: str
    auth_methods: tuple[str, ...]
    assurance_level: str


def map_uds_record(record: UdsBrokerRecord) -> dict[str, object]:
    """Map a UDS broker record to broker-neutral BAF input fields."""
    if not record.local_username:
        raise ValueError("missing local username mapping")
    return {
        "sub": record.user_id,
        "preferred_username": record.local_username,
        "policy_context": record.service_or_pool,
        "target": record.assigned_vm,
        "broker_session_id": record.session_id,
        "auth_method": list(record.auth_methods),
        "assurance_level": record.assurance_level,
    }
