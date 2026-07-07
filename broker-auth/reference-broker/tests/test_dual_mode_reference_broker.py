#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker" / "uds-adapter"))
sys.path.insert(0, str(ROOT / "broker-auth" / "conformance"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-issuer"))

from adapter_skeleton import UdsBrokerRecord, map_uds_record
from broker_issuer import generate_rsa_keypair
from reference_broker import build_rdsaad_authentication_request
from verifier import ConformanceError, verify_assertion


class DualModeReferenceBrokerTests(unittest.TestCase):
    def test_issue_assertion_cli_outputs_valid_rs256_baf_token(self):
        private_key, public_key = generate_rsa_keypair()
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "issuer.pem"
            key_path.write_bytes(private_key)
            token = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "broker-auth" / "reference-broker" / "issue_assertion.py"),
                    "--private-key",
                    str(key_path),
                    "--kid",
                    "reference-key",
                    "--issuer",
                    "https://broker.example.test",
                    "--audience",
                    "xrdp-sesman",
                    "--target",
                    "ubuntu-vdi-01",
                    "--subject",
                    "user-alice",
                    "--preferred-username",
                    "alice",
                    "--broker-session-id",
                    "session-123",
                    "--auth-method",
                    "smartcard",
                    "--assurance-level",
                    "mfa",
                    "--jti",
                    "jti-dual-mode-0001",
                ],
                text=True,
            ).strip()
        claims = verify_assertion(
            token,
            public_key,
            issuer="https://broker.example.test",
            audience="xrdp-sesman",
            target="ubuntu-vdi-01",
            leeway=10,
        )
        self.assertEqual(claims["preferred_username"], "alice")
        self.assertEqual(claims["auth_method"], ["smartcard"])

    def test_wrong_audience_and_target_rejected(self):
        private_key, public_key = generate_rsa_keypair()
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "issuer.pem"
            key_path.write_bytes(private_key)
            token = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "broker-auth" / "reference-broker" / "issue_assertion.py"),
                    "--private-key",
                    str(key_path),
                    "--kid",
                    "reference-key",
                    "--issuer",
                    "https://broker.example.test",
                    "--audience",
                    "wrong-audience",
                    "--target",
                    "wrong-target",
                    "--subject",
                    "user-alice",
                    "--preferred-username",
                    "alice",
                    "--broker-session-id",
                    "session-123",
                    "--jti",
                    "jti-dual-mode-0002",
                ],
                text=True,
            ).strip()
        with self.assertRaises(ConformanceError):
            verify_assertion(
                token,
                public_key,
                issuer="https://broker.example.test",
                audience="xrdp-sesman",
                target="ubuntu-vdi-01",
                leeway=10,
            )

    def test_mode_a_and_mode_b_share_rdsaad_request_body(self):
        request = build_rdsaad_authentication_request("header.payload.sig")
        self.assertEqual(request, b'{"rdp_assertion":"header.payload.sig"}')
        self.assertNotIn(b"password", request.lower())

    def test_uds_skeleton_mapping_has_no_unix_authority(self):
        mapped = map_uds_record(
            UdsBrokerRecord(
                user_id="uds-user-1",
                local_username="alice",
                service_or_pool="ubuntu-pool",
                assigned_vm="ubuntu-vdi-01",
                session_id="uds-session-1",
                auth_methods=("smartcard",),
                assurance_level="mfa",
            )
        )
        self.assertEqual(mapped["sub"], "uds-user-1")
        self.assertEqual(mapped["preferred_username"], "alice")
        self.assertEqual(mapped["target"], "ubuntu-vdi-01")
        self.assertNotIn("uid", mapped)
        self.assertNotIn("gid", mapped)
        self.assertNotIn("unix_groups", mapped)


if __name__ == "__main__":
    unittest.main()
