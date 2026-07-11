#!/usr/bin/env bash
#
# Smart-card -> broker -> Mode C session smoke test -- Phase 6 VM only.
#
# Runs ON the Ubuntu VDI VM (as root). A virtual smart card (a PIN-protected
# p12 credential) authenticates to the reference broker by certificate
# challenge-response; the broker validates the certificate chain to a trusted
# CA, maps the certificate identity to the local user, mints a BAF assertion,
# and registers it with the trusted handle service. The resulting one-time
# handle then rides the proven Mode C path (routing token and one-time
# credential) to a real desktop session for the NSS-resolved user.
#
# xrdp has no server-side NLA/CredSSP, so the smart card authenticates to the
# broker (northbound), not to the RDP connection. The headless card->broker
# ->handle proof is run anywhere by run-smartcard-proof.sh.
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
MODEC="$ROOT/test-lab/phase6/modec-smoke"
BROKER="$ROOT/broker-auth/reference-broker"
TOOL="$MODEC/baf_handle_tool"

WORK="$(mktemp -d)"; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
            rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "SC SMOKE FAIL: $*" >&2; exit 1; }

getent passwd "$USER_NAME" >/dev/null || fail "test user $USER_NAME not in NSS"

# --- build the registration helper if needed -----------------------------
if [ ! -x "$TOOL" ]; then
    echo "== building baf_handle_tool =="
    "$ROOT/libtool" --mode=link --tag=CC gcc \
        -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
        -o "$TOOL" "$MODEC/baf_handle_tool.c" \
        "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto
fi

# --- trusted broker issuer key (assertion signing + validator anchor) ----
mkdir -p /etc/xrdp/baf /run/xrdp-baf "$SC_DIR"
if [ ! -f "$TRUST_PRIV" ]; then
    echo "== generating broker issuer key pair =="
    python3 - "$TRUST_PRIV" "$TRUST_PUB" "$ROOT" <<'PY'
import sys
priv, pub, root = sys.argv[1:4]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import write_keypair
from pathlib import Path
write_keypair(Path(priv), Path(pub), 2048)
PY
fi

# --- smart-card CA + user card (the virtual smart card) -------------------
if [ ! -f "$SC_DIR/ca.pem" ] || [ ! -f "$SC_DIR/$USER_NAME-card.p12" ]; then
    echo "== provisioning smart-card CA and card for $USER_NAME =="
    python3 "$MODEC/make-smartcard.py" ca \
        --out-cert "$SC_DIR/ca.pem" --out-key "$SC_DIR/ca.key" >/dev/null
    python3 "$MODEC/make-smartcard.py" user \
        --ca-cert "$SC_DIR/ca.pem" --ca-key "$SC_DIR/ca.key" \
        --cn "$USER_NAME" --email "$USER_NAME@xrdp-baf.test" \
        --out-p12 "$SC_DIR/$USER_NAME-card.p12" --pin "$CARD_PIN" >/dev/null
    chmod 600 "$SC_DIR"/*.key "$SC_DIR"/*.p12
fi
CARD_P12="$SC_DIR/$USER_NAME-card.p12"

# --- configure Mode C in sesman.ini and xrdp.ini -------------------------
echo "== configuring $SESMAN_INI [BrokerAuth] for Mode C =="
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

echo "== enabling Mode C routing-token ingress in $XRDP_INI =="
grep -q '^broker_auth_enabled' "$XRDP_INI" || \
    sed -i '/^\[Globals\]/a broker_auth_enabled=true\nbroker_auth_modec_ingress_enabled=true' "$XRDP_INI"
grep -qE '^enable_dynamic_resizing' "$XRDP_INI" || \
    sed -i '/^\[Xorg\]/a enable_dynamic_resizing=false' "$XRDP_INI"

# --- start trusted daemons -----------------------------------------------
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

# Smart-card login -> broker auth -> assertion -> handle.
sc_handle() {
    python3 "$BROKER/smartcard_login.py" --p12 "$CARD_P12" --pin "$CARD_PIN" \
        --ca "$SC_DIR/ca.pem" --issuer-key "$TRUST_PRIV" --issuer "$ISSUER" \
        --audience "$AUDIENCE" --target "$TARGET" --kid "$KID" \
        > "$WORK/assertion.jwt" 2>"$WORK/sc.err" \
        || { cat "$WORK/sc.err" >&2; return 1; }
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

echo "== CHANNEL 1: smart card -> routing-token session =="
kill_session
H1="$(sc_handle)" || fail "smart-card broker auth failed (channel 1)"
echo "  handle=$H1"
connect "/u:$USER_NAME" "/load-balance-info:Cookie: msts=$H1"
session_started && echo "  ok: session started from smart card via routing token" \
    || fail "no session for channel 1 (see $WORK/xfreerdp.log)"
kill_session

echo "== CHANNEL 2: smart card -> one-time-credential session =="
H2="$(sc_handle)" || fail "smart-card broker auth failed (channel 2)"
echo "  handle=$H2"
connect "/u:$USER_NAME" "/p:$H2"
session_started && echo "  ok: session started from smart card via one-time credential" \
    || fail "no session for channel 2 (see $WORK/xfreerdp.log)"
kill_session

echo
echo "SC SMOKE PASS: smart card -> broker -> Mode C session succeeded on this VM"
