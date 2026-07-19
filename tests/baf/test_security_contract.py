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
BAF_RUNTIME_CONFIG = (
    ROOT / "sesman" / "libsesman" / "baf_runtime_config.c"
).read_text(encoding="utf-8")
BAF_RUNTIME_CONFIG_H = (
    ROOT / "sesman" / "libsesman" / "baf_runtime_config.h"
).read_text(encoding="utf-8")
SESMAN_CONFIG = (ROOT / "sesman" / "libsesman" / "sesman_config.c").read_text(
    encoding="utf-8")

XRDP_ISO = (ROOT / "libxrdp" / "xrdp_iso.c").read_text(encoding="utf-8")
XRDP_SEC = (ROOT / "libxrdp" / "xrdp_sec.c").read_text(encoding="utf-8")
XRDP_RDP = (ROOT / "libxrdp" / "xrdp_rdp.c").read_text(encoding="utf-8")
SCP_PROCESS = (ROOT / "sesman" / "scp_process.c").read_text(encoding="utf-8")
SCP_LIST_H = (ROOT / "sesman" / "scp_list.h").read_text(encoding="utf-8")
EICP_SERVER = (ROOT / "sesman" / "sesexec" / "eicp_server.c").read_text(
    encoding="utf-8")
LOGIN_INFO_H = (ROOT / "sesman" / "sesexec" / "login_info.h").read_text(
    encoding="utf-8")
BAF_ARCH = (ROOT / "BAF-ARCHITECTURE.md").read_text(encoding="utf-8")
RDSAAD_FOUNDATION = (
    ROOT / "broker-auth" / "RDSAAD-INTEGRATION-FOUNDATION.md"
).read_text(encoding="utf-8")
RDSAAD_PREMCS_BRIDGE = (
    ROOT / "broker-auth" / "RDSAAD-PREMCS-BRIDGE.md"
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
assert "chmod(p, 0660)" in HANDLE_SERVICE
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

assert "xrdp_client_info" not in BAF_RUNTIME_CONFIG
assert "xrdp_client_info" not in SESMAN_CONFIG
assert "broker_auth_enabled = 0" in BAF_RUNTIME_CONFIG
assert "broker_auth_rdsaad_enabled = 0" in BAF_RUNTIME_CONFIG
assert "reject_uid0 = 1" in BAF_RUNTIME_CONFIG
assert "allow_session_start = 0" in BAF_RUNTIME_CONFIG
assert "BAF_RUNTIME_DEFAULT_REPLAY_BACKEND \"service\"" in BAF_RUNTIME_CONFIG_H
assert "BAF_RUNTIME_DEFAULT_ALLOWED_ALGORITHMS \"RS256\"" in BAF_RUNTIME_CONFIG_H
assert "baf_runtime_config_validate_live" in BAF_RUNTIME_CONFIG
assert "config->replay_backend" in BAF_RUNTIME_CONFIG
assert "BAF_RUNTIME_CONFIG_DISABLED" in BAF_RUNTIME_CONFIG
assert "SESMAN_CFG_BROKER_AUTH" in SESMAN_CONFIG
assert "config_read_broker_auth" in SESMAN_CONFIG

assert "broker_auth_config_valid" in XRDP_ISO
assert "PROTOCOL_RDSAAD" in XRDP_ISO
assert "Selected RDSAAD security" in XRDP_ISO
assert "xrdp_sec_rdsaad_exchange" in XRDP_SEC
assert "xrdp_sec_rdsaad_exchange(self)" in XRDP_SEC
assert "XRDP_CALLBACK_RDSAAD_PREAUTH" in XRDP_SEC
assert "response.status == XRDP_RDSAAD_PREAUTH_AUTHORIZED" in XRDP_SEC
assert "result = RDSAAD_HRESULT_S_OK" in XRDP_SEC
assert XRDP_SEC.find("response.status == XRDP_RDSAAD_PREAUTH_AUTHORIZED") < XRDP_SEC.find("result = RDSAAD_HRESULT_S_OK")
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

assert "RDSAAD_HRESULT_E_ACCESSDENIED" in XRDP_SEC
rdsaad_exchange = XRDP_SEC[XRDP_SEC.find("xrdp_sec_rdsaad_exchange"):XRDP_SEC.find("hex_str_to_bin")]
assert "return result == RDSAAD_HRESULT_S_OK ? 0 : 1;" in rdsaad_exchange
assert "xrdp_session` owner callback" in RDSAAD_PREMCS_BRIDGE
assert "AllowSessionStart` defaults to `false`" in RDSAAD_PREMCS_BRIDGE
assert "Client-provided" in RDSAAD_PREMCS_BRIDGE and "not trusted validation" in RDSAAD_PREMCS_BRIDGE
assert "E_SLI_LOGIN_BAF" in SCP_LIST_H
assert "login_info_baf_preauth_user" in LOGIN_INFO_H
assert "E_SCP_SYS_LOGIN_REQUEST" in SCP_PROCESS
assert "E_SCP_UDS_LOGIN_REQUEST" in SCP_PROCESS
assert "E_EICP_SYS_LOGIN_REQUEST" in EICP_SERVER
assert "E_EICP_UDS_LOGIN_REQUEST" in EICP_SERVER
assert "login_info_sys_login_user" in LOGIN_INFO_H
assert "login_info_uds_login_user" in LOGIN_INFO_H
assert "password" not in RDSAAD_FOUNDATION.lower().split("## 7. sesman/sesexec handoff", 1)[1].split("## 8.", 1)[0] or "does not use username or password fields" in RDSAAD_FOUNDATION

REFERENCE_BROKER_DIR = ROOT / "broker-auth" / "reference-broker"
REFERENCE_BROKER = (REFERENCE_BROKER_DIR / "reference_broker.py").read_text(
    encoding="utf-8")
UDS_ADAPTER = (
    REFERENCE_BROKER_DIR / "uds-adapter" / "uds_adapter.py"
).read_text(encoding="utf-8")
KEYCLOAK_ADAPTER = (
    REFERENCE_BROKER_DIR / "keycloak_auth.py"
).read_text(encoding="utf-8")
REFERENCE_BROKER_TEST = (
    ROOT / "tests" / "baf" / "test_reference_broker_contract.py"
).read_text(encoding="utf-8")

assert "class ReferenceBroker" in REFERENCE_BROKER
assert "create_session_assertion" in REFERENCE_BROKER
assert "launch_connection" in REFERENCE_BROKER
assert "rdp_assertion" in REFERENCE_BROKER
assert "password" not in REFERENCE_BROKER.lower()
for logging_call in ("LOG(", "printf(", "fprintf(", "syslog("):
    assert logging_call not in REFERENCE_BROKER
    assert logging_call not in UDS_ADAPTER
assert "UdsSimulatorAdapter" in UDS_ADAPTER
for core_path in ("libxrdp", "xrdp", "sesman", "libipm"):
    for source in (ROOT / core_path).rglob("*.[ch]"):
        text = source.read_text(encoding="utf-8")
        assert "uds_adapter" not in text
        assert "keycloak_auth" not in text
        assert "reference_broker" not in text
assert 'audience=self.audience' in KEYCLOAK_ADAPTER
assert '"verify_aud": True' in KEYCLOAK_ADAPTER
assert "KeycloakBrokerAdapter" in KEYCLOAK_ADAPTER
assert "password_login" not in KEYCLOAK_ADAPTER
assert "custom IGEL" not in REFERENCE_BROKER
assert "FreeRDP plugin" not in REFERENCE_BROKER
assert "dynamic virtual channel" not in REFERENCE_BROKER
assert "test_uds_adapter_isolated_to_reference_broker" in REFERENCE_BROKER_TEST
assert "test_xrdp_core_does_not_import_reference_adapter" in REFERENCE_BROKER_TEST

ISSUE_ASSERTION = (
    REFERENCE_BROKER_DIR / "issue_assertion.py"
).read_text(encoding="utf-8")
GATEWAY_DIR = ROOT / "broker-auth" / "gateway"
GATEWAY_DOCS = "\n".join(
    path.read_text(encoding="utf-8")
    for path in (
        GATEWAY_DIR / "README.md",
        GATEWAY_DIR / "protocol.md",
        GATEWAY_DIR / "freeRDP-assertion-injection.md",
    )
)
PHASE5 = (ROOT / "broker-auth" / "PHASE5.md").read_text(encoding="utf-8")
MODE_A = (ROOT / "broker-auth" / "MODE-A-NATIVE-RDSAAD.md").read_text(
    encoding="utf-8")
MODE_B = (ROOT / "broker-auth" / "MODE-B-GATEWAY-RDSAAD.md").read_text(
    encoding="utf-8")

assert "sign_claims" in ISSUE_ASSERTION
assert "RS256" not in ISSUE_ASSERTION or "algorithm" not in ISSUE_ASSERTION
for logging_call in ("LOG(", "printf(", "fprintf(", "syslog("):
    assert logging_call not in ISSUE_ASSERTION
assert "print(" not in ISSUE_ASSERTION
assert "sys.stdout.write(token)" in ISSUE_ASSERTION
assert "rdp_assertion" in MODE_A
assert "rdp_assertion" in MODE_B
assert "Mode A: BAF-aware RDSAAD client" in PHASE5
assert "Mode B: broker gateway RDSAAD" in PHASE5
assert "optional MS-RDPBCGR-compatible envelope" in PHASE5
assert "CredSSP/NLA" in PHASE5
assert "LoadBalanceInfo" in PHASE5
assert "must not log raw assertions" in MODE_B
assert "must not require a custom IGEL client" in MODE_B
assert "username/password assertion overloading" in GATEWAY_DOCS
assert "never log raw assertions" in GATEWAY_DOCS
for core_path in ("libxrdp", "xrdp", "sesman", "libipm", "common"):
    for source in (ROOT / core_path).rglob("*.[ch]"):
        text = source.read_text(encoding="utf-8")
        assert "broker-auth/gateway" not in text
        assert "UdsBrokerRecord" not in text
        assert "Mode B - Broker Gateway" not in text
