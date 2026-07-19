#!/usr/bin/env python3

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
GATEWAY = ROOT / "broker-auth" / "gateway"


class GatewayContractTests(unittest.TestCase):
    def test_gateway_docs_require_rdsaad_and_forbid_overloading(self):
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                GATEWAY / "README.md",
                GATEWAY / "protocol.md",
                GATEWAY / "freeRDP-assertion-injection.md",
            )
        )
        self.assertIn("RDSAAD", text)
        self.assertIn("rdp_assertion", text)
        self.assertIn("no username/password assertion overloading", text)
        self.assertIn("never log raw assertions", text)
        self.assertIn("fail closed", text)

    def test_gateway_config_disables_unsafe_fallbacks(self):
        config = (GATEWAY / "config.example.yaml").read_text(encoding="utf-8")
        self.assertIn("require_rdsaad: true", config)
        self.assertIn("log_raw_assertions: false", config)
        self.assertIn(
            "allow_username_password_assertion_fallback: false", config
        )

    def test_gateway_is_outside_xrdp_core(self):
        for core_path in ("libxrdp", "xrdp", "sesman", "sesexec", "libipm", "common"):
            path = ROOT / core_path
            if not path.exists():
                continue
            for source in path.rglob("*.[ch]"):
                text = source.read_text(encoding="utf-8")
                self.assertNotIn("broker-auth/gateway", text, source)
                self.assertNotIn("Gateway RDSAAD", text, source)


if __name__ == "__main__":
    unittest.main()
