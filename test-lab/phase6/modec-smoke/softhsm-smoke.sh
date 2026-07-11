#!/usr/bin/env bash
#
# SoftHSM2 smart-card lifecycle smoke test -- Phase 6 VM only.
#
# Higher-fidelity variant of smartcard-smoke.sh: the virtual smart card is a
# real PKCS#11 token (SoftHSM2) provisioned from the bafuser card p12, so the
# private key operation goes through the token and never touches key bytes in
# the login process. It then simulates the physical card lifecycle:
#
#   1. card inserted   -> token signs the broker challenge -> assertion ->
#                         handle -> xfreerdp Mode C -> desktop session
#   2. card removed     -> the token slot disappears; signing fails closed ->
#                         the broker issues no assertion and no handle (denied)
#   3. card reinserted  -> the same token returns -> session again
#
# Removal/reinsertion is simulated by moving the SoftHSM2 token directory out
# of and back into the configured tokendir (the same credential returns).
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root on the VDI VM" >&2; exit 2; }

ROOT="${XRDP_SRC:-/home/rick/Soft/xrdp}"
USER_NAME="${LAB_TEST_USER:-bafuser}"
ISSUER="${BAF_ISSUER:-https://openuds-broker.xrdp-baf.test/baf}"
AUDIENCE="${BAF_AUDIENCE:-xrdp://ubuntu-vdi-01}"
TARGET="${BAF_TARGET:-ubuntu-vdi-01}"
KID="${BAF_KID:-lab-key-1}"
REPLAY_SOCK="${BAF_REPLAY_SOCKET:-/run/xrdp-baf/replay.sock}"
HANDLE_SOCK="${BAF_HANDLE_SOCKET:-/run/xrdp-baf/handle.sock}"
TRUST_PUB="/etc/xrdp/baf/reference-broker.pub"
TRUST_PRIV="/etc/xrdp/baf/reference-broker.key"
SESMAN_INI="${SESMAN_INI:-/etc/xrdp/sesman.ini}"
XRDP_INI="${XRDP_INI:-/etc/xrdp/xrdp.ini}"
HANDLED_BIN="$(command -v xrdp-baf-handled || echo /usr/local/sbin/xrdp-baf-handled)"
REPLAYD_BIN="$(command -v xrdp-baf-replayd || echo /usr/local/sbin/xrdp-baf-replayd)"
SC_DIR="/etc/xrdp/baf/sc"
CARD_PIN="${SC_CARD_PIN:-123456}"
SO_PIN="${SC_SO_PIN:-654321}"
TOKEN_LABEL="${SC_TOKEN_LABEL:-bafuser-card}"
PKCS11_MODULE="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)"
MODEC="$ROOT/test-lab/phase6/modec-smoke"
BROKER="$ROOT/broker-auth/reference-broker"
TOOL="$MODEC/baf_handle_tool"
HSM_DIR="$SC_DIR/hsm"
TOKENS="$HSM_DIR/tokens"
export SOFTHSM2_CONF="$HSM_DIR/softhsm2.conf"

WORK="$(mktemp -d)"; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
            # ensure the card is left inserted
            [ -d "$TOKENS.removed" ] && mv "$TOKENS.removed" "$TOKENS" 2>/dev/null || true
            rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "HSM SMOKE FAIL: $*" >&2; exit 1; }

getent passwd "$USER_NAME" >/dev/null || fail "test user $USER_NAME not in NSS"
[ -n "$PKCS11_MODULE" ] || fail "SoftHSM2 PKCS#11 module not found (install softhsm2)"
command -v pkcs11-tool softhsm2-util >/dev/null || fail "install opensc + softhsm2"

# --- build helper + broker key + card material (reuse smartcard assets) ---
if [ ! -x "$TOOL" ]; then
    "$ROOT/libtool" --mode=link --tag=CC gcc \
        -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
        -o "$TOOL" "$MODEC/baf_handle_tool.c" \
        "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto
fi
mkdir -p /etc/xrdp/baf /run/xrdp-baf "$SC_DIR"
if [ ! -f "$TRUST_PRIV" ]; then
    python3 - "$TRUST_PRIV" "$TRUST_PUB" "$ROOT" <<'PY'
import sys
priv, pub, root = sys.argv[1:4]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import write_keypair
from pathlib import Path
write_keypair(Path(priv), Path(pub), 2048)
PY
fi
if [ ! -f "$SC_DIR/ca.pem" ] || [ ! -f "$SC_DIR/$USER_NAME-card.p12" ]; then
    python3 "$MODEC/make-smartcard.py" ca --out-cert "$SC_DIR/ca.pem" \
        --out-key "$SC_DIR/ca.key" >/dev/null
    python3 "$MODEC/make-smartcard.py" user --ca-cert "$SC_DIR/ca.pem" \
        --ca-key "$SC_DIR/ca.key" --cn "$USER_NAME" \
        --email "$USER_NAME@xrdp-baf.test" \
        --out-p12 "$SC_DIR/$USER_NAME-card.p12" --pin "$CARD_PIN" >/dev/null
fi
CARD_P12="$SC_DIR/$USER_NAME-card.p12"
CARD_CERT="$SC_DIR/$USER_NAME-card.pem"

# --- provision the SoftHSM2 token from the card p12 -----------------------
if [ ! -d "$TOKENS" ] || [ -z "$(ls -A "$TOKENS" 2>/dev/null)" ]; then
    echo "== provisioning SoftHSM2 token '$TOKEN_LABEL' from the card p12 =="
    rm -rf "$HSM_DIR"; mkdir -p "$TOKENS"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
        "$TOKENS" > "$SOFTHSM2_CONF"
    python3 - "$CARD_P12" "$CARD_PIN" "$WORK/key.pem" "$CARD_CERT" <<'PY'
import sys
from cryptography.hazmat.primitives.serialization import (
    pkcs12, Encoding, PrivateFormat, NoEncryption)
p12, pin, keyout, certout = sys.argv[1:5]
key, cert, _ = pkcs12.load_key_and_certificates(open(p12, "rb").read(),
                                                 pin.encode())
open(keyout, "wb").write(key.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
open(certout, "wb").write(cert.public_bytes(Encoding.PEM))
PY
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --pin "$CARD_PIN" --so-pin "$SO_PIN" >/dev/null
    softhsm2-util --import "$WORK/key.pem" --token "$TOKEN_LABEL" \
        --label "$USER_NAME" --id 01 --pin "$CARD_PIN" >/dev/null
    shred -u "$WORK/key.pem" 2>/dev/null || rm -f "$WORK/key.pem"
fi

# --- configure Mode C + start daemons ------------------------------------
python3 - "$SESMAN_INI" "$ISSUER" "$AUDIENCE" "$TARGET" "$KID" \
        "$TRUST_PUB" "$REPLAY_SOCK" "$HANDLE_SOCK" <<'PY'
import re, sys
ini, issuer, aud, target, kid, trust, replay, handle = sys.argv[1:9]
section = f"""[BrokerAuth]
BrokerAuthEnabled=true
RDSAADEnabled=false
Provider=jwt
Issuer={issuer}
KeyId={kid}
AllowedAlgorithms=RS256
TrustAnchor={trust}
ExpectedAudience={aud}
LocalTarget={target}
MaxAssertionSize=16384
ReplayBackend=service
ReplaySocket={replay}
RejectUid0=true
AllowSessionStart=true
ModeCOneTimeCredential=true
HandleSocket={handle}
RequireNonceBinding=false
"""
text = re.sub(r"(?ms)^\[BrokerAuth\].*?(?=^\[|\Z)", "", open(ini).read())
open(ini, "w").write((text if text.endswith("\n") else text + "\n") + "\n" + section)
PY
grep -q '^broker_auth_enabled' "$XRDP_INI" || \
    sed -i '/^\[Globals\]/a broker_auth_enabled=true\nbroker_auth_modec_ingress_enabled=true' "$XRDP_INI"
grep -qE '^enable_dynamic_resizing' "$XRDP_INI" || \
    sed -i '/^\[Xorg\]/a enable_dynamic_resizing=false' "$XRDP_INI"

echo "== starting replay and handle services =="
rm -f "$REPLAY_SOCK" "$HANDLE_SOCK"
"$REPLAYD_BIN" -s "$REPLAY_SOCK" & PIDS+=($!)
"$HANDLED_BIN" -s "$HANDLE_SOCK" & PIDS+=($!)
for _ in $(seq 1 100); do
    [ -S "$REPLAY_SOCK" ] && [ -S "$HANDLE_SOCK" ] && break; sleep 0.05
done
[ -S "$REPLAY_SOCK" ] && [ -S "$HANDLE_SOCK" ] || fail "daemons did not start"
chmod 660 "$REPLAY_SOCK" "$HANDLE_SOCK" 2>/dev/null || true
systemctl restart xrdp xrdp-sesman 2>/dev/null || service xrdp restart || true
sleep 2

# --- card lifecycle helpers ----------------------------------------------
remove_card() { mv "$TOKENS" "$TOKENS.removed"; }
insert_card() { mv "$TOKENS.removed" "$TOKENS"; }
card_present() { pkcs11-tool --module "$PKCS11_MODULE" --list-token-slots 2>/dev/null \
                 | grep -q "token label.*$TOKEN_LABEL"; }

# SoftHSM2-backed smart-card login -> broker auth -> assertion -> handle.
hsm_handle() {
    python3 "$BROKER/smartcard_login.py" \
        --pkcs11-module "$PKCS11_MODULE" --token-label "$TOKEN_LABEL" \
        --card-cert "$CARD_CERT" --pin "$CARD_PIN" --ca "$SC_DIR/ca.pem" \
        --issuer-key "$TRUST_PRIV" --issuer "$ISSUER" --audience "$AUDIENCE" \
        --target "$TARGET" --kid "$KID" \
        > "$WORK/assertion.jwt" 2>"$WORK/sc.err" || return 1
    "$TOOL" store -s "$HANDLE_SOCK" -t "$TARGET" -l 90 < "$WORK/assertion.jwt"
}

session_started() {
    for _ in $(seq 1 30); do
        pgrep -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' \
            >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
kill_session() { pkill -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' \
                 2>/dev/null || true; sleep 1; }
connect() {
    timeout 30 xvfb-run -a -s "-screen 0 1280x1024x24" \
        xfreerdp /v:127.0.0.1 /cert:ignore /sec:tls /gdi:sw /bpp:24 \
        -gfx +glyph-cache /w:1024 /h:768 "$@" \
        >"$WORK/xfreerdp.log" 2>&1 &
    PIDS+=($!)
}

echo "== STEP 1: card INSERTED -> SoftHSM2 sign -> session =="
card_present || fail "token not present at start"
kill_session
H="$(hsm_handle)" || { cat "$WORK/sc.err" >&2; fail "auth failed with card inserted"; }
echo "  handle=$H"
connect "/u:$USER_NAME" "/load-balance-info:Cookie: msts=$H"
session_started && echo "  ok: session started from SoftHSM2 card" \
    || fail "no session with card inserted (see $WORK/xfreerdp.log)"
kill_session

echo "== STEP 2: card REMOVED -> signing fails closed -> auth denied =="
remove_card
card_present && fail "token still present after removal"
if hsm_handle >/dev/null 2>&1; then
    fail "broker issued a handle with the card removed"
fi
echo "  ok: card removed -> $(grep -o 'smart-card[^\"]*' "$WORK/sc.err" | head -1 || echo 'PKCS#11 signing failed'); no assertion, no handle"

echo "== STEP 3: card REINSERTED -> session again =="
insert_card
card_present || fail "token not present after reinsertion"
kill_session
H="$(hsm_handle)" || { cat "$WORK/sc.err" >&2; fail "auth failed after reinsertion"; }
echo "  handle=$H"
connect "/u:$USER_NAME" "/load-balance-info:Cookie: msts=$H"
session_started && echo "  ok: session started again after reinsertion" \
    || fail "no session after reinsertion (see $WORK/xfreerdp.log)"
kill_session

echo
echo "HSM SMOKE PASS: SoftHSM2 card insert -> remove(deny) -> reinsert lifecycle verified"
