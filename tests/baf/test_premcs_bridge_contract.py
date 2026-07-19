#!/usr/bin/env python3

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

LIBXRDPINC = (ROOT / "libxrdp" / "libxrdpinc.h").read_text(encoding="utf-8")
XRDP_SEC = (ROOT / "libxrdp" / "xrdp_sec.c").read_text(encoding="utf-8")
XRDP_WM = (ROOT / "xrdp" / "xrdp_wm.c").read_text(encoding="utf-8")
XRDP_PROCESS = (ROOT / "xrdp" / "xrdp_process.c").read_text(encoding="utf-8")
XRDP_MM = (ROOT / "xrdp" / "xrdp_mm.c").read_text(encoding="utf-8")
XRDP_TYPES = (ROOT / "xrdp" / "xrdp_types.h").read_text(encoding="utf-8")
SCP_H = (ROOT / "libipm" / "scp.h").read_text(encoding="utf-8")
SCP_C = (ROOT / "libipm" / "scp.c").read_text(encoding="utf-8")
EICP_H = (ROOT / "libipm" / "eicp.h").read_text(encoding="utf-8")
EICP_C = (ROOT / "libipm" / "eicp.c").read_text(encoding="utf-8")
SCP_PROCESS = (ROOT / "sesman" / "scp_process.c").read_text(encoding="utf-8")
SCP_LIST = (ROOT / "sesman" / "scp_list.h").read_text(encoding="utf-8")
EICP_PROCESS = (ROOT / "sesman" / "eicp_process.c").read_text(encoding="utf-8")
EICP_SERVER = (ROOT / "sesman" / "sesexec" / "eicp_server.c").read_text(encoding="utf-8")
LOGIN_INFO_C = (ROOT / "sesman" / "sesexec" / "login_info.c").read_text(encoding="utf-8")
LOGIN_INFO_H = (ROOT / "sesman" / "sesexec" / "login_info.h").read_text(encoding="utf-8")
RUNTIME_CONFIG = (ROOT / "sesman" / "libsesman" / "baf_runtime_config.c").read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    marker = f"\n{name}("
    start = source.find(marker)
    if start < 0:
        marker = f"\n{name} ("
        start = source.find(marker)
    assert start >= 0, name
    brace = source.find("{", start)
    assert brace >= 0, name
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(name)


# libxrdp exposes a structured owner callback and does not authorize locally.
assert "XRDP_CALLBACK_RDSAAD_PREAUTH" in LIBXRDPINC
assert "struct xrdp_rdsaad_preauth_request" in LIBXRDPINC
assert "struct xrdp_rdsaad_preauth_response" in LIBXRDPINC
for forbidden in ("pam_", "getpwnam", "getpwuid", "session_start"):
    assert forbidden not in XRDP_SEC

rdsaad_exchange = function_body(XRDP_SEC, "xrdp_sec_rdsaad_exchange")
assert "session->callback" in rdsaad_exchange
assert "XRDP_CALLBACK_RDSAAD_PREAUTH" in rdsaad_exchange
assert "secure_erase_bytes(assertion" in rdsaad_exchange
assert "response.status == XRDP_RDSAAD_PREAUTH_AUTHORIZED" in rdsaad_exchange
assert rdsaad_exchange.find("response.status == XRDP_RDSAAD_PREAUTH_AUTHORIZED") < rdsaad_exchange.find("result = RDSAAD_HRESULT_S_OK")
assert "return result == RDSAAD_HRESULT_S_OK ? 0 : 1;" in rdsaad_exchange

# xrdp handles the callback before xrdp_wm exists, then binds the authenticated
# sesman transport to this process only.
callback_body = function_body(XRDP_WM, "callback")
assert callback_body.find("XRDP_CALLBACK_RDSAAD_PREAUTH") < callback_body.find("wm =")
assert "baf_preauth_sesman_trans" in XRDP_TYPES
assert "baf_preauth_authorized" in XRDP_TYPES
process_preauth = function_body(XRDP_PROCESS, "xrdp_process_rdsaad_preauth")
assert "scp_send_broker_login_request_v1" in process_preauth
assert "E_SCP_LOGIN_RESPONSE" in process_preauth
assert "self->baf_preauth_sesman_trans = sesman_trans" in process_preauth
assert "secure_erase_bytes((char *)correlation_id" in process_preauth
assert "password" not in process_preauth.lower()

# xrdp_mm adopts the preauthenticated transport after MCS creates xrdp_mm;
# it does not send a SYS password login for this path.
assert "baf_preauth_authorized" in XRDP_MM
assert "self->connect_state = MMCS_CREATE_SESSION" in XRDP_MM
assert "self->wm->pro_layer->baf_preauth_sesman_trans = NULL" in XRDP_MM

# Existing broker SCP/EICP request codecs are assertion-bearing and password-free.
for source in (SCP_H, EICP_H):
    assert "broker_login_request_v1" in source
    for name in ("send_broker_login_request_v1", "get_broker_login_request_v1"):
        start = source.find(name)
        assert start >= 0, name
        end = source.find(");", start)
        assert end > start, name
        assert "password" not in source[start:end].lower()
for source in (SCP_C, EICP_C):
    assert "broker_login_request_v1" in source
    for name in ("scp_send_broker_login_request_v1",
                 "scp_get_broker_login_request_v1",
                 "eicp_send_broker_login_request_v1",
                 "eicp_get_broker_login_request_v1"):
        if name in source:
            assert "password" not in function_body(source, name).lower()
assert "E_SCP_BROKER_LOGIN_REQUEST_V1" in SCP_C
assert "E_EICP_BROKER_LOGIN_REQUEST_V1" in EICP_C
assert "wire_length == 0" in SCP_C and "wire_length > *assertion_length" in SCP_C
assert "wire_length == 0" in EICP_C and "wire_length > *assertion_length" in EICP_C
assert "libipm_msg_out_erase" in SCP_C and "libipm_msg_out_erase" in EICP_C
assert "LIBIPM_E_MSG_IN_ERASE_AFTER_USE" in SCP_C
assert "LIBIPM_E_MSG_IN_ERASE_AFTER_USE" in EICP_C

# sesman dispatches broker preauth only through trusted live config and forwards
# to sesexec. Classic SYS/UDS cases remain present.
assert "E_SLI_LOGIN_BAF" in SCP_LIST
scp_broker = function_body(SCP_PROCESS, "process_broker_login_request")
assert "baf_runtime_config_validate_live(&g_cfg->baf)" in scp_broker
assert "eicp_send_broker_login_request_v1" in scp_broker
assert "secure_erase_bytes((char *)assertion" in scp_broker
assert "password" not in scp_broker.lower()
assert "case E_SCP_SYS_LOGIN_REQUEST" in SCP_PROCESS
assert "case E_SCP_UDS_LOGIN_REQUEST" in SCP_PROCESS
assert "case E_SCP_BROKER_LOGIN_REQUEST_V1" in SCP_PROCESS

# sesman records successful broker authorization distinctly.
assert "broker_login_in_progress" in EICP_PROCESS
assert "E_SLI_LOGIN_BAF" in EICP_PROCESS

# sesexec dispatches broker preauth and creates login_info only through the BAF
# live authorization chain.
assert "case E_EICP_SYS_LOGIN_REQUEST" in EICP_SERVER
assert "case E_EICP_UDS_LOGIN_REQUEST" in EICP_SERVER
assert "case E_EICP_BROKER_LOGIN_REQUEST_V1" in EICP_SERVER
assert "login_info_baf_preauth_user" in EICP_SERVER
assert "login_info_baf_preauth_user" in LOGIN_INFO_H
baf_login = function_body(LOGIN_INFO_C, "login_info_baf_preauth_user")
for required in (
    "baf_runtime_config_validate_live(&g_cfg->baf)",
    "baf_authorize_assertion",
    "scp_send_login_response",
):
    assert required in baf_login
assert "pam_authenticate" not in baf_login
assert "password" not in baf_login.lower()
assert "result->auth_info = auth_info" in baf_login
assert "result->username = username" in baf_login

# The shared BAF authorization core keeps the complete fail-closed chain.
baf_core = function_body(LOGIN_INFO_C, "baf_authorize_assertion")
for required in (
    "replay_cache_service_create",
    "replay_cache_is_service",
    "baf_validator_config_create",
    "baf_transport_validate",
    "BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED",
    "baf_identity_bind_and_authorize",
    "access_login_allowed",
    "require_nonce_binding",
):
    assert required in baf_core
assert "pam_authenticate" not in baf_core

# Broker-RDP Handle consumes one-time handles exclusively: no password fallback, no raw
# assertion retention, authfail logging for fail2ban.
resolve = function_body(LOGIN_INFO_C, "modec_resolve_handle")
assert "baf_handle_resolve_and_consume" in resolve
mode_c = function_body(LOGIN_INFO_C, "mode_c_authenticate")
for required in (
    "modec_resolve_handle",
    "baf_authorize_assertion",
    "baf_handle_assertion_free",
    "log_authfail_message",
):
    assert required in mode_c
assert "auth_userpass" not in mode_c
auth_conn = function_body(LOGIN_INFO_C,
                          "authenticate_and_authorize_connection")
assert "password_is_otc_handle" in auth_conn
assert "baf_runtime_config_validate_mode_c" in auth_conn
assert "baf_runtime_config_validate_mode_c" in RUNTIME_CONFIG
assert "mode_c_otc_enabled = 0" in RUNTIME_CONFIG

# Broker-RDP Handle routing-token ingress: strict handle capture in the ISO layer,
# fail-closed pre-MCS authorization, kind-gated dispatch through sesman.
XRDP_ISO = (ROOT / "libxrdp" / "xrdp_iso.c").read_text(encoding="utf-8")
capture = function_body(XRDP_ISO, "xrdp_iso_capture_broker_handle")
assert "broker_auth_modec_ingress_enabled" in capture
assert "Cookie: msts=" in capture
modec_sec = function_body(XRDP_SEC, "xrdp_sec_modec_preauth")
assert "XRDP_BROKER_CREDENTIAL_HANDLE" in modec_sec
assert "secure_erase_bytes(iso->broker_handle" in modec_sec
assert "XRDP_RDSAAD_PREAUTH_AUTHORIZED" in modec_sec
assert "credential_kind == SCP_BROKER_CREDENTIAL_HANDLE" in SCP_PROCESS
baf_login = function_body(LOGIN_INFO_C, "login_info_baf_preauth_user")
assert "SCP_BROKER_CREDENTIAL_HANDLE" in baf_login
assert "baf_runtime_config_validate_mode_c" in baf_login
assert "modec_resolve_handle" in baf_login

# Live config is a separate gate and remains disabled by default.
assert "allow_session_start = 0" in RUNTIME_CONFIG
assert "baf_runtime_config_validate_live" in RUNTIME_CONFIG
assert "return config->allow_session_start" in RUNTIME_CONFIG
