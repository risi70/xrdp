#!/usr/bin/env python3

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROVIDER = (
    ROOT / "sesman" / "libsesman" / "auth_provider_jwt.c"
).read_text(encoding="utf-8")
REPLAY = (
    ROOT / "sesman" / "libsesman" / "replay_cache.c"
).read_text(encoding="utf-8")
TRANSPORT = (
    ROOT / "sesman" / "libsesman" / "baf_transport.c"
).read_text(encoding="utf-8")
PROTOCOL = "\n".join(
    (ROOT / path).read_text(encoding="utf-8")
    for path in ("libipm/scp.c", "libipm/eicp.c")
)

for logging_call in ("LOG(", "printf(", "fprintf(", "syslog("):
    assert logging_call not in PROVIDER
    assert logging_call not in REPLAY
    assert logging_call not in TRANSPORT

for forbidden in (
    "getpwnam",
    "getpwuid",
    "pam_",
    "session_start",
    "SSSD",
    "LDAP",
    "FreeIPA",
    "Active Directory",
    "Keycloak",
    "trusted = true",
):
    assert forbidden not in PROVIDER
    assert forbidden not in TRANSPORT

assert "assertion" not in REPLAY.lower()
assert "libipm_msg_out_erase" in PROTOCOL
assert "LIBIPM_E_MSG_IN_ERASE_AFTER_USE" in PROTOCOL
assert "password" not in TRANSPORT.lower()
