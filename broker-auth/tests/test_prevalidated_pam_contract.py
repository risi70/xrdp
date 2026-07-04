#!/usr/bin/env python3
"""Regression checks for the PAM prevalidated-auth call contract."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAM_SOURCE = ROOT / "sesman" / "libsesman" / "verify_user_pam.c"
LOGIN_SOURCE = ROOT / "sesman" / "sesexec" / "login_info.c"


def function_body(source: str, function_name: str) -> str:
    match = re.search(
        rf"\n{re.escape(function_name)}\([^{{]*\)\n\{{",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"function {function_name} not found")

    start = match.end()
    depth = 1
    position = start
    while depth and position < len(source):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
        position += 1
    if depth:
        raise AssertionError(f"function {function_name} is unterminated")
    return source[start : position - 1]


class PrevalidatedPamContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pam_source = PAM_SOURCE.read_text(encoding="utf-8")
        cls.login_source = LOGIN_SOURCE.read_text(encoding="utf-8")

    def test_classic_login_still_requires_pam_authentication(self):
        body = function_body(self.pam_source, "auth_userpass")
        self.assertRegex(
            body,
            r"common_pam_login\(auth_info,\s*user,\s*pass,\s*"
            r"client_ip,\s*1\)",
        )

    def test_prevalidated_login_skips_only_authentication_phase(self):
        body = function_body(self.pam_source, "auth_prevalidated")
        self.assertRegex(
            body,
            r"common_pam_login\(auth_info,\s*user,\s*NULL,\s*"
            r"client_ip,\s*0\)",
        )

    def test_pam_account_and_session_phases_remain(self):
        common = function_body(self.pam_source, "common_pam_login")
        session = function_body(
            self.pam_source, "auth_start_session_private"
        )
        self.assertIn("pam_authenticate(", common)
        self.assertIn("pam_acct_mgmt(", common)
        self.assertIn("pam_setcred(", session)
        self.assertIn("pam_open_session(", session)

    def test_bypass_requires_locally_validated_broker_context(self):
        body = function_body(
            self.login_source, "login_info_prevalidated_broker_user"
        )
        self.assertIn("provider->is_locally_validated(context)", body)
        self.assertIn("auth_prevalidated(username, client_ip", body)


if __name__ == "__main__":
    unittest.main()
