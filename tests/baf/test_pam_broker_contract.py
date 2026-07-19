#!/usr/bin/env python3
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "sesman/libsesman/verify_user_pam.c").read_text()
classic = re.search(r"auth_userpass\(.*?\n\}", source, re.S).group(0)
broker = re.search(r"auth_prevalidated_broker\(.*?\n\}", source, re.S).group(0)
common = re.search(r"common_pam_login\(.*?\n\}", source, re.S).group(0)
start = re.search(r"auth_start_session_private\(.*?\n\}", source, re.S).group(0)
stop = re.search(r"auth_stop_session\(.*?\n\}", source, re.S).group(0)
assert "common_pam_login(auth_info, user, pass, client_ip, 1)" in classic
assert "common_pam_login(auth_info, user, NULL, client_ip, 0)" in broker
assert "if (authentication_required)" in common
assert "pam_authenticate" in common
assert common.index("if (authentication_required)") < common.index("pam_authenticate")
assert "pam_acct_mgmt" in common
assert "pam_setcred" in start and "pam_open_session" in start
assert "pam_close_session" in stop and "PAM_DELETE_CRED" in stop
assert "pam_authenticate" not in broker
assert "session_start" not in broker
