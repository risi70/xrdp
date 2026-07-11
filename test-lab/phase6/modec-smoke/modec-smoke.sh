#!/usr/bin/env bash
#
# Mode C RDP-level smoke test (SD-009 Wave 1) -- Phase 6 VM only.
#
# Runs ON the Ubuntu VDI VM (as root) with the xrdp build from this tree
# installed and a real local test user. It drives an actual xfreerdp client
# against the live xrdp/sesman, exercising both Mode C ingress channels:
#
#   Channel 1  routing token   : xfreerdp /load-balance-info:"Cookie: msts=<handle>"
#                                (no credential fields; pre-MCS authorization)
#   Channel 2  one-time cred    : xfreerdp /u:<user> /p:<handle>
#                                (handle-shaped password consumed by Mode C)
#
# For each channel it mints a fresh assertion with the reference issuer,
# registers it with the trusted handle service to obtain a single-use handle,
# connects, and asserts that a real desktop session starts for the
# NSS-resolved user. This is the half of the smoke test that needs root,
# PAM, NSS, an X server and TLS; the headless crypto/handle/replay proof is
# run anywhere by run-local-proof.sh.
#
# It is deliberately self-contained: it configures the [BrokerAuth] Mode C
# settings and xrdp.ini keys itself, so it can run before the C6 broker
# integration exists. Lab use only.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root on the VDI VM" >&2; exit 2; }

# --- lab parameters (override via environment) ---------------------------
ROOT="${XRDP_SRC:-/home/rick/Soft/xrdp}"
USER_NAME="${LAB_TEST_USER:-bafuser}"
ISSUER="${BAF_ISSUER:-https://openuds-broker.xrdp-baf.test/baf}"
AUDIENCE="${BAF_AUDIENCE:-xrdp://ubuntu-vdi-01}"
TARGET="${BAF_TARGET:-ubuntu-vdi-01}"
KID="${BAF_KID:-lab-key-1}"
REPLAY_SOCK="${BAF_REPLAY_SOCKET:-/run/xrdp-baf/replay.sock}"
HANDLE_SOCK="${BAF_HANDLE_SOCKET:-/run/xrdp-baf/handle.sock}"
TRUST_PUB="/etc/xrdp/baf/reference-broker.pub"
TRUST_PRIV="/etc/xrdp/baf/reference-broker.key"   # lab issuer key; never ship
SESMAN_INI="${SESMAN_INI:-/etc/xrdp/sesman.ini}"
XRDP_INI="${XRDP_INI:-/etc/xrdp/xrdp.ini}"
HANDLED_BIN="$(command -v xrdp-baf-handled || echo /usr/local/sbin/xrdp-baf-handled)"
REPLAYD_BIN="$(command -v xrdp-baf-replayd || echo /usr/local/sbin/xrdp-baf-replayd)"
TOOL="$ROOT/test-lab/phase6/modec-smoke/baf_handle_tool"

WORK="$(mktemp -d)"; PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

getent passwd "$USER_NAME" >/dev/null || fail "test user $USER_NAME not in NSS"

# --- build the registration helper if needed -----------------------------
if [ ! -x "$TOOL" ]; then
    echo "== building baf_handle_tool =="
    "$ROOT/libtool" --mode=link --tag=CC gcc \
        -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
        -o "$TOOL" "$ROOT/test-lab/phase6/modec-smoke/baf_handle_tool.c" \
        "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto
fi

# --- trusted lab issuer key + trust anchor -------------------------------
mkdir -p /etc/xrdp/baf /run/xrdp-baf
if [ ! -f "$TRUST_PRIV" ]; then
    echo "== generating lab issuer key pair =="
    python3 - "$TRUST_PRIV" "$TRUST_PUB" "$ROOT" <<'PY'
import sys
priv_path, pub_path, root = sys.argv[1:4]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import write_keypair
from pathlib import Path
write_keypair(Path(priv_path), Path(pub_path), 2048)
PY
fi

# --- configure Mode C in sesman.ini and xrdp.ini -------------------------
# Replace any existing [BrokerAuth] section with a Mode C-enabled one.
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
text = open(ini).read()
text = re.sub(r"(?ms)^\[BrokerAuth\].*?(?=^\[|\Z)", "", text)
if not text.endswith("\n"):
    text += "\n"
open(ini, "w").write(text + "\n" + section)
PY

echo "== enabling Mode C routing-token ingress in $XRDP_INI [Globals] =="
grep -q '^broker_auth_enabled' "$XRDP_INI" || \
    sed -i '/^\[Globals\]/a broker_auth_enabled=true\nbroker_auth_modec_ingress_enabled=true' "$XRDP_INI"
# Disable the dynamic-resize monitor DVC: a headless RDP client declines that
# channel, and xrdp treats the decline as fatal. It is a per-session-module
# value, so set it in the Xorg module section the lab session uses.
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

mint_handle() { # -> prints handle on stdout
    python3 - "$WORK" "$ISSUER" "$AUDIENCE" "$TARGET" "$KID" "$USER_NAME" \
            "$TRUST_PRIV" "$ROOT" <<'PY' > "$WORK/assertion.jwt"
import sys, uuid
work, issuer, aud, target, kid, user, priv, root = sys.argv[1:9]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import build_claims, sign_claims
claims = build_claims(
    issuer=issuer, audience=aud, subject="u-" + user,
    preferred_username=user, groups=["vdi"], roles=["desktop-user"],
    target=target, session_id="sess-" + uuid.uuid4().hex,
    auth_context={"amr": ["pwd"], "acr": "urn:lab:aal2",
                  "device_trust": "unknown"},
    lifetime=120)
sys.stdout.write(sign_claims(claims, open(priv, "rb").read(), key_id=kid))
PY
    "$TOOL" store -s "$HANDLE_SOCK" -t "$TARGET" -l 90 < "$WORK/assertion.jwt"
}

session_started() { # wait up to ~15s for a desktop session for the user
    for _ in $(seq 1 30); do
        if pgrep -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' \
                >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

kill_session() { pkill -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' \
                 2>/dev/null || true; sleep 1; }

connect() { # args passed to xfreerdp; runs bounded, backgrounded
    # The VDI VM is headless: give the client a virtual X display, force TLS,
    # software GDI, and disable the dynamic-resolution/monitor DVC that xrdp
    # cannot negotiate against a headless client.
    timeout 30 xvfb-run -a -s "-screen 0 1280x1024x24" \
        xfreerdp /v:127.0.0.1 /cert:ignore /sec:tls /gdi:sw /bpp:24 \
        -gfx +glyph-cache /w:1024 /h:768 "$@" \
        >"$WORK/xfreerdp.log" 2>&1 &
    PIDS+=($!)
}

echo "== CHANNEL 1: routing-token ingress =="
kill_session
H1="$(mint_handle)"; echo "  handle=$H1"
connect "/u:$USER_NAME" "/load-balance-info:Cookie: msts=$H1"
session_started && echo "  ok: session started via routing token" \
    || fail "no session for channel 1 (see $WORK/xfreerdp.log)"
kill_session

echo "== CHANNEL 2: one-time credential ingress =="
H2="$(mint_handle)"; echo "  handle=$H2"
connect "/u:$USER_NAME" "/p:$H2"
session_started && echo "  ok: session started via one-time credential" \
    || fail "no session for channel 2 (see $WORK/xfreerdp.log)"
kill_session

echo
echo "SMOKE PASS: Mode C RDP-level smoke test succeeded on this VM"
