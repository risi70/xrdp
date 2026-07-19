#!/usr/bin/env python3

from pathlib import Path
import sys
import time
import unittest

import jwt

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-broker" / "uds-adapter"))
sys.path.insert(0, str(ROOT / "broker-auth" / "conformance"))
sys.path.insert(0, str(ROOT / "broker-auth" / "reference-issuer"))

from broker_issuer import generate_rsa_keypair
from reference_broker import (
    AuthContext,
    BrokerError,
    BrokerTarget,
    BrokerUser,
    LocalAuthorizationPolicy,
    ReferenceBroker,
    ReplayLedger,
    build_rdsaad_authentication_request,
    decode_unsigned_claims,
)
from uds_adapter import UdsResource, UdsSession, UdsSimulatorAdapter, UdsUser
from verifier import ConformanceError, verify_assertion


class ReferenceBrokerContractTests(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = generate_rsa_keypair()
        self.users = {
            "alice": BrokerUser(
                subject="user-alice",
                username="alice",
                groups=("desktop-users",),
                local_uid=1000,
            ),
            "root": BrokerUser(
                subject="user-root",
                username="root",
                local_uid=0,
            ),
            "denied": BrokerUser(
                subject="user-denied",
                username="denied",
                local_uid=1001,
                pam_allowed=False,
            ),
            "bad/name": BrokerUser(
                subject="user-bad",
                username="bad/name",
                local_uid=1002,
            ),
        }
        self.targets = {
            "ubuntu-vdi-01": BrokerTarget(
                name="ubuntu-vdi-01",
                address="ubuntu-vdi-01.example.test",
                audience="xrdp-sesman",
            )
        }
        self.broker = ReferenceBroker(
            issuer="https://broker.example.test",
            key_id="reference-key",
            private_key=self.private_key,
            default_audience="xrdp-sesman",
            targets=self.targets,
            users=self.users,
            policy=LocalAuthorizationPolicy(self.users),
            lifetime=300,
        )

    def issue(self, now=None, **kwargs):
        session_id = self.broker.assign_target("alice", "ubuntu-vdi-01")
        return self.broker.create_session_assertion(
            "alice",
            "ubuntu-vdi-01",
            session_id,
            AuthContext(auth_method=("pwd", "otp"), assurance_level="mfa"),
            now=int(time.time()) if now is None else now,
            **kwargs,
        )

    def test_reference_broker_issues_valid_baf_assertion(self):
        token = self.issue(jti="jti-reference-0001")
        claims = verify_assertion(
            token,
            self.public_key,
            issuer="https://broker.example.test",
            audience="xrdp-sesman",
            target="ubuntu-vdi-01",
            leeway=10,
        )
        self.assertEqual(claims["preferred_username"], "alice")
        self.assertEqual(claims["broker_session_id"], next(iter(self.broker._sessions)))
        self.assertEqual(claims["auth_method"], ["pwd", "otp"])
        self.assertEqual(claims["assurance_level"], "mfa")

    def test_wrong_audience_rejected(self):
        token = self.issue(jti="jti-reference-0002", audience="other-service")
        with self.assertRaises(ConformanceError):
            verify_assertion(
                token,
                self.public_key,
                issuer="https://broker.example.test",
                audience="xrdp-sesman",
                target="ubuntu-vdi-01",
                leeway=10,
            )

    def test_wrong_target_rejected(self):
        token = self.issue(jti="jti-reference-0003")
        with self.assertRaises(ConformanceError):
            verify_assertion(
                token,
                self.public_key,
                issuer="https://broker.example.test",
                audience="xrdp-sesman",
                target="other-target",
                leeway=10,
            )

    def test_expired_assertion_rejected(self):
        token = self.issue(jti="jti-reference-0004", now=1_700_000_000)
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                issuer="https://broker.example.test",
                audience="xrdp-sesman",
            )

    def test_replayed_assertion_rejected_by_ledger(self):
        token = self.issue(jti="jti-reference-0005")
        claims = decode_unsigned_claims(token)
        replay = ReplayLedger()
        replay.reserve(claims["iss"], claims["jti"])
        with self.assertRaises(BrokerError):
            replay.reserve(claims["iss"], claims["jti"])

    def test_local_authorization_rejects_unknown_unsafe_uid0_and_pam_denial(self):
        for username in ("unknown", "bad/name", "root", "denied"):
            with self.subTest(username=username):
                with self.assertRaises(BrokerError):
                    self.broker.list_targets(username)

    def test_launch_connection_builds_rdsaad_authentication_request(self):
        launch = self.broker.launch_connection(
            "alice",
            "ubuntu-vdi-01",
            auth_context=AuthContext(("smartcard",), "loa-high"),
            now=int(time.time()),
        )
        self.assertEqual(launch["protocol"], "RDSAAD")
        self.assertEqual(launch["server"], "ubuntu-vdi-01.example.test")
        body = launch["authentication_request"]
        self.assertIsInstance(body, bytes)
        self.assertIn(b"rdp_assertion", body)
        self.assertNotIn(b"password", body.lower())
        with self.assertRaises(BrokerError):
            build_rdsaad_authentication_request("")

    def test_uds_adapter_isolated_to_reference_broker(self):
        adapter = UdsSimulatorAdapter(
            users={
                "uds-user-1": UdsUser(
                    id="uds-user-1",
                    login="alice@example.test",
                    local_username="alice",
                    groups=("desktop-users",),
                    uid=1000,
                )
            },
            resources={
                "resource-1": UdsResource(
                    id="resource-1",
                    name="ubuntu-vdi-01",
                    address="ubuntu-vdi-01.example.test",
                    audience="xrdp-sesman",
                )
            },
            sessions={
                "uds-session-1": UdsSession(
                    id="uds-session-1",
                    user_id="uds-user-1",
                    resource_id="resource-1",
                    auth_methods=("smartcard",),
                )
            },
        )
        users = adapter.broker_users()
        targets = adapter.broker_targets()
        user, target, context = adapter.resolve_session("uds-session-1")
        self.assertEqual(user, "alice")
        self.assertEqual(target, "ubuntu-vdi-01")
        self.assertEqual(context.auth_method, ("smartcard",))
        self.assertIn("alice", users)
        self.assertIn("ubuntu-vdi-01", targets)

    def test_xrdp_core_does_not_import_reference_adapter(self):
        core_paths = [
            ROOT / "libxrdp",
            ROOT / "xrdp",
            ROOT / "sesman",
            ROOT / "libipm",
        ]
        for path in core_paths:
            for source in path.rglob("*.[ch]"):
                text = source.read_text(encoding="utf-8")
                self.assertNotIn("uds_adapter", text, source)
                self.assertNotIn("reference_broker", text, source)


if __name__ == "__main__":
    unittest.main()
