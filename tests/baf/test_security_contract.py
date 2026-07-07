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
REPLAY_SERVICE = (
    ROOT / "sesman" / "libsesman" / "replay_cache_service.c"
).read_text(encoding="utf-8")
REPLAY_HEADER = (
    ROOT / "sesman" / "libsesman" / "replay_service_protocol.h"
).read_text(encoding="utf-8")
HANDLE_SERVICE = (
    ROOT / "sesman" / "libsesman" / "baf_handle_service.c"
).read_text(encoding="utf-8")
HANDLE_TEST = (ROOT / "tests" / "baf" / "test_handle_service.c").read_text(
    encoding="utf-8")
RDSAAD = (ROOT / "common" / "rdsaad.c").read_text(encoding="utf-8")
RDSAAD_TEST = (ROOT / "tests" / "baf" / "test_rdsaad_ingress.c").read_text(
    encoding="utf-8")

XRDP_ISO = (ROOT / "libxrdp" / "xrdp_iso.c").read_text(encoding="utf-8")
XRDP_SEC = (ROOT / "libxrdp" / "xrdp_sec.c").read_text(encoding="utf-8")
XRDP_RDP = (ROOT / "libxrdp" / "xrdp_rdp.c").read_text(encoding="utf-8")
SCP_PROCESS = (ROOT / "sesman" / "scp_process.c").read_text(encoding="utf-8")
EICP_SERVER = (ROOT / "sesman" / "sesexec" / "eicp_server.c").read_text(
    encoding="utf-8")
LOGIN_INFO_H = (ROOT / "sesman" / "sesexec" / "login_info.h").read_text(
    encoding="utf-8")
BAF_ARCH = (ROOT / "BAF-ARCHITECTURE.md").read_text(encoding="utf-8")
RDSAAD_FOUNDATION = (
    ROOT / "broker-auth" / "RDSAAD-INTEGRATION-FOUNDATION.md"
).read_text(encoding="utf-8")

for logging_call in ("LOG(", "printf(", "fprintf(", "syslog("):
    assert logging_call not in PROVIDER
    assert logging_call not in REPLAY
    assert logging_call not in TRANSPORT
    assert logging_call not in HANDLE_SERVICE
for logging_call in ("LOG(", "fprintf(", "syslog("):
    assert logging_call not in RDSAAD

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
assert "assertion" not in REPLAY_SERVICE.lower()
assert "token" not in REPLAY_SERVICE.lower()
assert "assertion" not in REPLAY_HEADER.lower()
assert "token" not in REPLAY_HEADER.lower()
assert "SOCK_SEQPACKET" in REPLAY_SERVICE
assert "require_service_replay" in PROVIDER
assert "AF_INET" not in HANDLE_SERVICE
assert "SOCK_STREAM" not in HANDLE_SERVICE
assert "SOCK_SEQPACKET" in HANDLE_SERVICE
assert "bind(" in HANDLE_SERVICE
assert "chmod(p,0660)" in HANDLE_SERVICE
assert "LOG(" not in HANDLE_SERVICE
assert "printf(" not in HANDLE_SERVICE
assert "fprintf(" not in HANDLE_SERVICE
assert "BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED" in HANDLE_TEST
assert "pam_" not in HANDLE_TEST
assert "session_start" not in HANDLE_TEST
assert "rdp_assertion" in RDSAAD
assert "ts_nonce" in RDSAAD
assert "authentication_result" in RDSAAD
assert "password" not in RDSAAD.lower()
assert "baf_handle" not in RDSAAD
assert "getpwnam" not in RDSAAD and "getpwuid" not in RDSAAD
assert "pam_" not in RDSAAD and "session_start" not in RDSAAD
assert "BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED" in RDSAAD_TEST
assert "pam_" not in RDSAAD_TEST and "session_start" not in RDSAAD_TEST
IDENTITY = (
    ROOT / "sesman" / "libsesman" / "baf_identity.c"
).read_text(encoding="utf-8")
PAM = (ROOT / "sesman" / "libsesman" / "verify_user_pam.c").read_text(
    encoding="utf-8")
AUTHORIZATION = (
    ROOT / "sesman" / "libsesman" / "baf_authorization.c"
).read_text(encoding="utf-8")

assert "getpwnam_r" in IDENTITY and "getpwuid_r" in IDENTITY
assert "auth_prevalidated_broker" not in IDENTITY
assert "auth_prevalidated_broker" in AUTHORIZATION
assert "getpwnam" not in AUTHORIZATION and "getpwuid" not in AUTHORIZATION
for forbidden in ("pam_", "session_start", "Keycloak", "trusted = true"):
    assert forbidden not in IDENTITY
for source in (PROVIDER, TRANSPORT):
    assert "getpwnam" not in source
    assert "getpwuid" not in source
    assert "pam_" not in source
    assert "session_start" not in source
assert "auth_prevalidated_broker" in PAM
assert "pam_acct_mgmt" in PAM
assert "pam_open_session" in PAM and "pam_close_session" in PAM
assert "assertion" not in PAM.lower()

assert "broker_auth_config_valid" in XRDP_ISO
assert "PROTOCOL_RDSAAD" in XRDP_ISO
assert "Selected RDSAAD security" in XRDP_ISO
assert "xrdp_sec_rdsaad_exchange" in XRDP_SEC
assert "xrdp_sec_rdsaad_exchange(self)" in XRDP_SEC
assert "RDSAAD_HRESULT_S_OK" not in XRDP_SEC
assert "Authentication Result success is " in XRDP_SEC and "withheld" in XRDP_SEC
assert "xrdp_mcs_incoming(self->mcs_layer)" in XRDP_SEC
assert XRDP_SEC.find("xrdp_sec_rdsaad_exchange(self)") < XRDP_SEC.find("xrdp_mcs_incoming(self->mcs_layer)")
assert "broker_auth_rdsaad_enabled" in XRDP_RDP
assert "broker_auth_trust_anchor" in XRDP_RDP
assert "broker_auth_expected_audience" in XRDP_RDP
assert "broker_auth_local_target" in XRDP_RDP
assert "broker_auth_replay_backend" in XRDP_RDP
assert "broker_auth_replay_socket" in XRDP_RDP
assert "broker_auth_allow_session_start" in XRDP_RDP
assert "rdp_assertion" not in XRDP_ISO

assert "RDSAAD Authentication Request parsed" in XRDP_SEC
assert "RDSAAD_HRESULT_E_ACCESSDENIED" in XRDP_SEC
assert "return 1;" in XRDP_SEC[XRDP_SEC.find("xrdp_sec_rdsaad_exchange"):XRDP_SEC.find("hex_str_to_bin")]
assert "session-ready handoff" in BAF_ARCH
assert "Full live RDSAAD activation remains deferred" in BAF_ARCH
assert "does not emit `S_OK`" in BAF_ARCH
assert "controlled failure" in RDSAAD_FOUNDATION
assert "login_info` currently represents classic SYS login and UDS login only" in RDSAAD_FOUNDATION
assert "Neither abstraction exists yet" in RDSAAD_FOUNDATION
assert "E_SCP_SYS_LOGIN_REQUEST" in SCP_PROCESS
assert "E_SCP_UDS_LOGIN_REQUEST" in SCP_PROCESS
assert "E_EICP_SYS_LOGIN_REQUEST" in EICP_SERVER
assert "E_EICP_UDS_LOGIN_REQUEST" in EICP_SERVER
assert "login_info_sys_login_user" in LOGIN_INFO_H
assert "login_info_uds_login_user" in LOGIN_INFO_H
assert "password" not in RDSAAD_FOUNDATION.lower().split("## 7. sesman/sesexec handoff", 1)[1].split("## 8.", 1)[0] or "does not use username or password fields" in RDSAAD_FOUNDATION
