#!/usr/bin/env bash
#
# Record a video of the client display during a Broker-RDP Handle session -- VM only.
#
# The "client" is xfreerdp rendering the remote desktop into a virtual X
# display (Xvfb). This script drives a normal Broker-RDP Handle connection (broker
# assertion -> one-time handle -> routing token) and records the client's
# Xvfb framebuffer with ffmpeg x11grab, producing an mp4 of exactly what the
# RDP client sees: the login transition and the authenticated xfce desktop.
#
# Output: $OUT (default /tmp/modec-client-session.mp4).
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
TRUST_PRIV="/etc/xrdp/baf/reference-broker.key"
HANDLED_BIN="$(command -v xrdp-baf-handled || echo /usr/local/sbin/xrdp-baf-handled)"
REPLAYD_BIN="$(command -v xrdp-baf-replayd || echo /usr/local/sbin/xrdp-baf-replayd)"
MODEC="$ROOT/test-lab/phase6/modec-smoke"
TOOL="$MODEC/baf_handle_tool"
DISPLAY_NUM="${CAP_DISPLAY:-:99}"
GEOM="${CAP_GEOM:-1280x1024}"
DURATION="${CAP_SECONDS:-22}"
OUT="${CAP_OUT:-/tmp/modec-client-session.mp4}"

WORK="$(mktemp -d)"; PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    pkill -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' 2>/dev/null || true
    kill "${XVFB_PID:-0}" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "CAPTURE FAIL: $*" >&2; exit 1; }

command -v ffmpeg Xvfb xfreerdp >/dev/null || fail "need ffmpeg, Xvfb, xfreerdp"
[ -x "$TOOL" ] || "$ROOT/libtool" --mode=link --tag=CC gcc \
    -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
    -o "$TOOL" "$MODEC/baf_handle_tool.c" \
    "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto

# --- daemons + a fresh Broker-RDP Handle (Broker-RDP Handle config already installed) ----
rm -f "$REPLAY_SOCK" "$HANDLE_SOCK"
"$REPLAYD_BIN" -s "$REPLAY_SOCK" & PIDS+=($!)
"$HANDLED_BIN" -s "$HANDLE_SOCK" & PIDS+=($!)
for _ in $(seq 1 100); do
    [ -S "$REPLAY_SOCK" ] && [ -S "$HANDLE_SOCK" ] && break; sleep 0.05
done
[ -S "$REPLAY_SOCK" ] && [ -S "$HANDLE_SOCK" ] || fail "daemons did not start"
chmod 660 "$REPLAY_SOCK" "$HANDLE_SOCK" 2>/dev/null || true
systemctl restart xrdp xrdp-sesman 2>/dev/null || true
sleep 2

python3 - "$WORK" "$ISSUER" "$AUDIENCE" "$TARGET" "$KID" "$USER_NAME" \
        "$TRUST_PRIV" "$ROOT" <<'PY' > "$WORK/assertion.jwt"
import sys, uuid
work, issuer, aud, target, kid, user, priv, root = sys.argv[1:9]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import build_claims, sign_claims
claims = build_claims(
    issuer=issuer, audience=aud, subject="u-" + user, preferred_username=user,
    groups=["vdi"], roles=["desktop-user"], target=target,
    session_id="cap-" + uuid.uuid4().hex,
    auth_context={"amr": ["pwd"], "acr": "urn:lab:aal2",
                  "device_trust": "unknown"}, lifetime=120)
sys.stdout.write(sign_claims(claims, open(priv, "rb").read(), key_id=kid))
PY
HANDLE="$("$TOOL" store -s "$HANDLE_SOCK" -t "$TARGET" -l 90 < "$WORK/assertion.jwt")"
echo "handle=$HANDLE"

# --- start the client display and record it ------------------------------
pkill -u "$USER_NAME" -f 'xorgxrdp|Xorg|xrdp-chansrv|startwm' 2>/dev/null || true
Xvfb "$DISPLAY_NUM" -screen 0 "${GEOM}x24" -nolisten tcp & XVFB_PID=$!
for _ in $(seq 1 100); do
    [ -S "/tmp/.X11-unix/X${DISPLAY_NUM#:}" ] && break; sleep 0.05
done

echo "== recording ${DURATION}s of the client display =="
ffmpeg -y -hide_banner -loglevel error -f x11grab -video_size "$GEOM" \
    -framerate 12 -i "$DISPLAY_NUM" -t "$DURATION" -pix_fmt yuv420p \
    -movflags +faststart "$OUT" & FFMPEG_PID=$!
PIDS+=($FFMPEG_PID)

sleep 1
DISPLAY="$DISPLAY_NUM" timeout "$((DURATION + 6))" xfreerdp /v:127.0.0.1 \
    /cert:ignore /sec:tls /gdi:sw /bpp:24 ${CAP_FLAGS:--gfx +glyph-cache} \
    /w:"${GEOM%x*}" /h:"${GEOM#*x}" /u:"$USER_NAME" \
    "/load-balance-info:Cookie: msts=$HANDLE" \
    > "$WORK/xfreerdp.log" 2>&1 & PIDS+=($!)

# Grab the server session desktop mid-recording (while the session is alive).
(
    sleep "${CAP_SERVER_AT:-14}"
    xl=$(ps -eo args | grep -E "Xorg :[0-9]+ -auth" | grep -v grep | head -1)
    sd=$(echo "$xl" | grep -oE ":[0-9]+ " | head -1 | tr -d ' ')
    sa=$(echo "$xl" | grep -oE '\-auth [^ ]+' | awk '{print $2}')
    [ -n "$sd" ] && XAUTHORITY="$sa" ffmpeg -y -hide_banner -loglevel error \
        -f x11grab -video_size "$GEOM" -i "$sd" -frames:v 1 \
        /tmp/cap-server.png 2>/dev/null
) &

wait "$FFMPEG_PID" 2>/dev/null || true

# Diagnostics (Xvfb still up here; cleanup tears it down on exit).
DISPLAY="$DISPLAY_NUM" xwininfo -root -tree 2>/dev/null \
    > /tmp/cap-windows.txt || true
cp -f "$WORK/xfreerdp.log" /tmp/cap-xfreerdp.log 2>/dev/null || true
pgrep -au "$USER_NAME" -f 'Xorg|xfwm|xfdesktop|startwm|panel|xfce' \
    > /tmp/cap-session-procs.txt 2>/dev/null || true
# Screenshot the server session desktop (proves the full stack renders).
CAP_XL=$(ps -eo args | grep -E "Xorg :[0-9]+ -auth" | grep -v grep | head -1)
CAP_SD=$(echo "$CAP_XL" | grep -oE ":[0-9]+ " | head -1 | tr -d ' ')
CAP_SA=$(echo "$CAP_XL" | grep -oE '\-auth [^ ]+' | awk '{print $2}')
if [ -n "$CAP_SD" ]; then
    XAUTHORITY="$CAP_SA" ffmpeg -y -hide_banner -loglevel error -f x11grab \
        -video_size "$GEOM" -i "$CAP_SD" -frames:v 1 /tmp/cap-server.png \
        2>/dev/null || true
fi

[ -s "$OUT" ] || fail "no video produced (see $WORK/xfreerdp.log)"
echo "CAPTURE OK: $OUT ($(du -h "$OUT" | cut -f1), $(stat -c%s "$OUT") bytes)"
