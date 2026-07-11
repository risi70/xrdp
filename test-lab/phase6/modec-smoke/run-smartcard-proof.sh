#!/usr/bin/env bash
#
# Smart-card -> broker -> handle headless proof (card->broker->Mode C).
#
# Verifies the full smart-card broker authentication chain without an RDP
# client, X server, PAM or root:
#
#   virtual smart card (p12) --challenge/response PoP--> reference broker
#   --X.509 chain validation--> identity --> BAF assertion (nonce-bound)
#   --> real handle service (handle) --> resolve+consume --> BAF validator
#      (RequireNonceBinding, real replay service)
#
# Positive: a genuine card issued by the trusted CA authenticates and its
# minted assertion validates. Negatives: a card from an untrusted CA and an
# expired card are both rejected by the broker before any assertion exists.
#
# The handle->session half is covered on the VM by smartcard-smoke.sh.
#
# Prereqs: built tree (--enable-broker-auth), python3 with pyjwt +
# cryptography.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BROKER="$ROOT/broker-auth/reference-broker"
WORK="$(mktemp -d)"
REPLAY="$WORK/replay.sock"
HANDLE="$WORK/handle.sock"
ISSUER="https://openuds-broker.xrdp-baf.test/baf"
AUDIENCE="xrdp://ubuntu-vdi-01"
TARGET="ubuntu-vdi-01"
KID="lab-key-1"
PIN="123456"
PIDS=()

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
            wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "SC PROOF FAIL: $*" >&2; exit 1; }

echo "== building baf_handle_tool =="
"$ROOT/libtool" --mode=link --tag=CC gcc \
    -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
    -o "$WORK/baf_handle_tool" "$HERE/baf_handle_tool.c" \
    "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto
TOOL="$WORK/baf_handle_tool"

echo "== issuing broker signing key + smart-card CA and cards =="
python3 "$ROOT/broker-auth/reference-issuer/broker_issuer.py" keygen \
    --private-key "$WORK/issuer.key" --public-key "$WORK/issuer.pub" >/dev/null
python3 "$HERE/make-smartcard.py" ca --out-cert "$WORK/ca.pem" \
    --out-key "$WORK/ca.key" >/dev/null
# trusted card for bafuser
python3 "$HERE/make-smartcard.py" user --ca-cert "$WORK/ca.pem" \
    --ca-key "$WORK/ca.key" --cn bafuser --email bafuser@xrdp-baf.test \
    --out-p12 "$WORK/card.p12" --pin "$PIN" >/dev/null
# untrusted card (different CA)
python3 "$HERE/make-smartcard.py" ca --out-cert "$WORK/rogue-ca.pem" \
    --out-key "$WORK/rogue-ca.key" >/dev/null
python3 "$HERE/make-smartcard.py" user --ca-cert "$WORK/rogue-ca.pem" \
    --ca-key "$WORK/rogue-ca.key" --cn bafuser --email bafuser@xrdp-baf.test \
    --out-p12 "$WORK/rogue.p12" --pin "$PIN" >/dev/null
# expired card (issued by the trusted CA but past not-after)
python3 "$HERE/make-smartcard.py" user --ca-cert "$WORK/ca.pem" \
    --ca-key "$WORK/ca.key" --cn bafuser --email bafuser@xrdp-baf.test \
    --out-p12 "$WORK/expired.p12" --pin "$PIN" --not-after -1 >/dev/null

echo "== starting real daemons =="
"$ROOT/sesman/xrdp-baf-replayd" -s "$REPLAY" & PIDS+=($!)
"$ROOT/sesman/xrdp-baf-handled" -s "$HANDLE" & PIDS+=($!)
for _ in $(seq 1 100); do [ -S "$REPLAY" ] && [ -S "$HANDLE" ] && break; sleep 0.05; done
[ -S "$REPLAY" ] && [ -S "$HANDLE" ] || fail "daemons did not start"

sc_login() { # $1=p12  $2=nonce  -> assertion on stdout (exit reflects auth)
    python3 "$BROKER/smartcard_login.py" --p12 "$1" --pin "$PIN" \
        --ca "$WORK/ca.pem" --issuer-key "$WORK/issuer.key" \
        --issuer "$ISSUER" --audience "$AUDIENCE" --target "$TARGET" \
        --kid "$KID" --nonce "$2" 2>/dev/null
}
check() { # handle nonce
    "$TOOL" check -s "$HANDLE" -H "$1" -t "$TARGET" -k "$WORK/issuer.pub" \
        -i "$ISSUER" -a "$AUDIENCE" -K "$KID" -n "$2" -r "$REPLAY"
}

echo "== POSITIVE: trusted card authenticates -> assertion -> handle -> validate =="
NONCE="$(python3 -c 'import uuid;print(uuid.uuid4().hex)')"
sc_login "$WORK/card.p12" "$NONCE" > "$WORK/assertion.jwt" \
    || fail "trusted card should authenticate"
H="$($TOOL store -s "$HANDLE" -t "$TARGET" -l 90 < "$WORK/assertion.jwt")"
check "$H" "$NONCE" || fail "smart-card assertion should validate"

echo "== NEGATIVE 1: card from an untrusted CA is rejected =="
if sc_login "$WORK/rogue.p12" "$NONCE" >/dev/null 2>&1; then
    fail "untrusted-CA card was accepted"
fi
echo "  ok: untrusted-CA card rejected by broker (no assertion issued)"

echo "== NEGATIVE 2: expired card is rejected =="
if sc_login "$WORK/expired.p12" "$NONCE" >/dev/null 2>&1; then
    fail "expired card was accepted"
fi
echo "  ok: expired card rejected by broker (no assertion issued)"

echo
echo "SC PROOF PASS: smart-card -> broker -> handle -> validate (positive + 2 negatives)"
