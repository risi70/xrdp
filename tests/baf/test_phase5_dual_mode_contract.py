#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


PHASE5 = read("broker-auth/archive/PHASE5.md")
MODE_A = read("broker-auth/archive/MODE-A-NATIVE-RDSAAD.md")
MODE_B = read("broker-auth/archive/MODE-B-GATEWAY-RDSAAD.md")
BROKER_PROTOCOL = read("broker-auth/reference-broker/protocol.md")
GATEWAY_PROTOCOL = read("broker-auth/gateway/protocol.md")
UDS_MAPPING = read("broker-auth/reference-broker/uds-adapter/mapping.md")


assert "Mode A: native RDSAAD client" in PHASE5
assert "Mode B: broker gateway RDSAAD" in PHASE5
assert "RDSAAD remains the common XRDP-side ingress" in PHASE5
assert "UDS is a reference broker, not a core dependency" in PHASE5
assert "preferred fallback" in PHASE5
for mechanism in (
    "CredSSP/NLA",
    "smartcard redirection",
    "WebAuthn redirection",
    "LoadBalanceInfo",
):
    assert mechanism in PHASE5

assert "enablerdsaadauth" in MODE_A
assert "public IGEL / RD Core documentation" in MODE_A
assert "rdp_assertion" in MODE_A
assert "must be proven with actual client interoperability" in MODE_A
assert "RDSAAD remains the XRDP-side ingress for Mode A" in MODE_A

assert "gateway performs RDSAAD/BAF toward XRDP" in MODE_B
assert "must not log raw assertions" in MODE_B
assert "must not require a custom IGEL client" in MODE_B
assert "RDSAAD remains the XRDP-side ingress for Mode B" in MODE_B

for text in (BROKER_PROTOCOL, GATEWAY_PROTOCOL):
    assert "username/password" in text
    assert "rdp_assertion" in text
    assert "SCP/EICP" not in text or "not SCP/EICP" in text

assert "UDS groups become Unix groups" in UDS_MAPPING
assert "NSS/SSSD" in UDS_MAPPING
assert "UID/GID" in UDS_MAPPING

for core_path in ("libxrdp", "xrdp", "sesman", "libipm", "common"):
    for source in (ROOT / core_path).rglob("*.[ch]"):
        text = source.read_text(encoding="utf-8")
        assert "Mode A - Native RDSAAD" not in text
        assert "Mode B - Broker Gateway" not in text
        assert "UdsBrokerRecord" not in text

for script in (
    "broker-auth/reference-broker/tests/test_dual_mode_reference_broker.py",
    "broker-auth/gateway/tests/test_gateway_contract.py",
):
    subprocess.run([sys.executable, str(ROOT / script)], check=True)
