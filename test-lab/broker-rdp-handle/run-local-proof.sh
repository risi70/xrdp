#!/usr/bin/env bash
#
# Broker-RDP Handle headless local proof.
#
# Exercises the Broker-RDP Handle credential path end-to-end with real, separate daemon
# processes and freshly-signed crypto, WITHOUT needing an RDP client, X
# server, PAM or root:
#
#   reference issuer -> fresh nonce-bound assertion
#   -> real xrdp-baf-replayd + xrdp-baf-handled daemons
#   -> register (handle) -> resolve+consume -> BAF validator (nonce-bound,
#      real replay service)
#
# Positive: a fresh nonce-bound assertion validates.
# Negatives: wrong nonce fails, a consumed handle cannot be reused, and a
# reused assertion (same jti behind a new handle) is rejected by the replay
# service.
#
# This is the runnable-anywhere half of the Broker-RDP Handle smoke test. The
# RDP-level channels are exercised on an integration VM by rdp-smoke.sh.
#
# Prereqs: the tree is built (--enable-broker-auth), python3 with the
# reference-issuer deps (pyjwt, cryptography).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
REPLAY="$WORK/replay.sock"
HANDLE="$WORK/handle.sock"
ISSUER="https://broker.lab.test"
AUDIENCE="xrdp-baf-lab"
TARGET="urn:baf:desktop:lab:pool:vdi01"
KID="lab-key-1"
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "== building baf_handle_tool =="
"$ROOT/libtool" --mode=link --tag=CC gcc \
    -I"$ROOT/common" -I"$ROOT/sesman/libsesman" -I"$ROOT" -DHAVE_CONFIG_H \
    -o "$WORK/baf_handle_tool" "$HERE/baf_handle_tool.c" \
    "$ROOT/sesman/libsesman/libsesman.la" -ljwt -ljansson -lssl -lcrypto
TOOL="$WORK/baf_handle_tool"

echo "== generating a lab RSA key pair =="
python3 - "$WORK" "$ROOT" <<'PY'
import sys
work, root = sys.argv[1:3]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import generate_rsa_keypair
priv, pub = generate_rsa_keypair(2048)
open(f"{work}/priv.pem", "wb").write(priv)
open(f"{work}/pub.pem", "wb").write(pub)
PY

# mint: writes a fresh assertion (new jti) with a fresh nonce, echoes the
# nonce. Each independent case mints its own so a prior reservation does not
# contaminate the next; the replay negative deliberately reuses one.
mint() {
    python3 - "$WORK" "$ISSUER" "$AUDIENCE" "$TARGET" "$KID" "$ROOT" <<'PY'
import sys, uuid
work, issuer, audience, target, kid, root = sys.argv[1:7]
sys.path.insert(0, f"{root}/broker-auth/reference-issuer")
from broker_issuer import build_claims, sign_claims
nonce = uuid.uuid4().hex
claims = build_claims(
    issuer=issuer, audience=audience, subject="u-1001",
    preferred_username="labuser", groups=["vdi"], roles=["desktop-user"],
    target=target, session_id="sess-" + uuid.uuid4().hex,
    auth_context={"amr": ["pwd", "otp"], "acr": "urn:lab:aal2",
                  "device_trust": "unknown"},
    lifetime=120)
claims["extensions"] = {"urn:baf:ts_nonce": nonce}
open(f"{work}/assertion.jwt", "w").write(
    sign_claims(claims, open(f"{work}/priv.pem", "rb").read(), key_id=kid))
print(nonce)
PY
}

echo "== starting real daemons =="
"$ROOT/sesman/xrdp-baf-replayd" -s "$REPLAY" & PIDS+=($!)
"$ROOT/sesman/xrdp-baf-handled" -s "$HANDLE" & PIDS+=($!)
for _ in $(seq 1 100); do
    [ -S "$REPLAY" ] && [ -S "$HANDLE" ] && break
    sleep 0.05
done
[ -S "$REPLAY" ] && [ -S "$HANDLE" ] || fail "daemons did not start"

check() { # handle nonce
    "$TOOL" check -s "$HANDLE" -H "$1" -t "$TARGET" -k "$WORK/pub.pem" \
        -i "$ISSUER" -a "$AUDIENCE" -K "$KID" -n "$2" -r "$REPLAY"
}
store() { "$TOOL" store -s "$HANDLE" -t "$TARGET" -l 90 < "$WORK/assertion.jwt"; }

echo "== POSITIVE: fresh nonce-bound assertion validates =="
NONCE="$(mint)"; H="$(store)"
check "$H" "$NONCE" || fail "positive nonce-bound validation failed"

echo "== NEGATIVE 1: wrong nonce is rejected =="
NONCE="$(mint)"; H="$(store)"
if check "$H" "wrong-nonce" >/dev/null 2>&1; then fail "wrong nonce accepted"; fi
echo "  ok: wrong nonce rejected"

echo "== NEGATIVE 2: a consumed handle cannot be reused =="
NONCE="$(mint)"; H="$(store)"
check "$H" "$NONCE" >/dev/null 2>&1 || fail "first use should succeed"
if check "$H" "$NONCE" >/dev/null 2>&1; then fail "handle reuse accepted"; fi
echo "  ok: single-use handle enforced"

echo "== NEGATIVE 3: replayed assertion (same jti) rejected by replay service =="
# Reuse the SAME minted assertion behind two fresh handles: the second
# validation must be rejected because the jti was already reserved.
NONCE="$(mint)"
H1="$(store)"; H2="$(store)"
check "$H1" "$NONCE" >/dev/null 2>&1 || fail "first assertion use should succeed"
if check "$H2" "$NONCE" >/dev/null 2>&1; then
    fail "reused assertion accepted despite prior reservation"
fi
echo "  ok: replay service rejected the reused assertion identity"

echo
echo "SMOKE PASS: Broker-RDP Handle headless proof succeeded (positive + 3 negatives)"
