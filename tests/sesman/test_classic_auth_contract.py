#!/usr/bin/env python3
"""Source contract checks for the Phase 1 authentication boundary."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAM_SOURCE = ROOT / "sesman" / "libsesman" / "verify_user_pam.c"
LOGIN_SOURCE = ROOT / "sesman" / "sesexec" / "login_info.c"
AUTH_HEADER = ROOT / "sesman" / "libsesman" / "sesman_auth.h"

def function_body(source: str, name: str) -> str:
    match = re.search(rf"\n{name}\([^{{]*\)\n\{{", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"function {name} not found")
    start = match.end()
    depth = 1
    pos = start
    while depth and pos < len(source):
        depth += source[pos] == "{"
        depth -= source[pos] == "}"
        pos += 1
    if depth:
        raise AssertionError(f"function {name} is unterminated")
    return source[start : pos - 1]

def main() -> int:
    pam = PAM_SOURCE.read_text(encoding="utf-8")
    login = LOGIN_SOURCE.read_text(encoding="utf-8")
    auth_header = AUTH_HEADER.read_text(encoding="utf-8")
    userpass = function_body(pam, "auth_userpass")
    common = function_body(pam, "common_pam_login")
    session = function_body(pam, "auth_start_session_private")
    assert re.search(
        r"common_pam_login\(auth_info,\s*user,\s*pass,\s*client_ip,\s*1\)",
        userpass,
    ), "classic auth_userpass must require PAM authentication"
    assert "pam_authenticate(" in common
    assert "pam_acct_mgmt(" in common
    assert "pam_setcred(" in session
    assert "pam_open_session(" in session
    combined = login + auth_header
    for marker in ("auth_prevalidated", "prevalidated_broker",
                   "is_locally_validated", "trusted=true"):
        assert marker not in combined, f"prohibited Phase 1 bypass: {marker}"
    return 0

if __name__ == "__main__":
    sys.exit(main())
