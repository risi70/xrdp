#!/usr/bin/env bash
#
# Build and run the MS-RDPESC smart-card response-parser tests under
# AddressSanitizer/UBSan on a lab VM (or any reachable Ubuntu build host).
#
# Extends the lab to exercise the --enable-smartcard redirection code
# (sesman/chansrv/smartcard*.c). The tests decode client-controlled [MS-RDPESC]
# IOCTL responses; running them under ASan/UBSan turns the F1-F9 bounds-check
# fixes (the internal MS-RDPESC security review) into an enforced contract.
#
#   scripts/run-smartcard-tests.sh --host 192.168.126.20 [--user ansible]
#                                  [--fuzz-seconds 30]
#
# Requires: ssh/rsync to the host; the host needs the xrdp build toolchain.
# With --fuzz-seconds and clang available on the host, also runs a short
# libFuzzer smoke over the parsers.
set -euo pipefail

HOST=""
USER_NAME="ansible"
REMOTE_SRC="/opt/xrdp-src"
FUZZ_SECONDS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --remote-src) REMOTE_SRC="$2"; shift 2 ;;
    --fuzz-seconds) FUZZ_SECONDS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$HOST" ] || { echo "usage: $0 --host <ip> [--user u] [--fuzz-seconds N]" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$USER_NAME@$HOST"
SSH="ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=15"

echo "== syncing source to $TARGET:$REMOTE_SRC =="
"$HERE/sync-source.sh" "$HOST" "$REMOTE_SRC" >/dev/null

echo "== building + running smart-card parser tests under ASan/UBSan =="
# shellcheck disable=SC2087
$SSH "$TARGET" FUZZ_SECONDS="$FUZZ_SECONDS" REMOTE_SRC="$REMOTE_SRC" 'bash -s' <<'REMOTE'
set -euo pipefail
BUILD=/tmp/xrdp-scard-lab
rm -rf "$BUILD" && mkdir -p "$BUILD"
rsync -a --exclude packaging/deb/out --exclude ".git" \
  --exclude "Makefile" --exclude "Makefile.in" --exclude "config.status" \
  --exclude "config_ac.h" --exclude "*.o" --exclude "*.lo" \
  "$REMOTE_SRC/" "$BUILD/" 2>/dev/null
cd "$BUILD"
./bootstrap >/tmp/scard-lab-boot.log 2>&1
# Fuzzing needs a clang/libFuzzer-instrumented libcommon; when requested (and
# clang is present) build the whole thing with clang so the unit test and the
# fuzzer share one sanitizer runtime. Otherwise use the default gcc ASan build.
if [ "${FUZZ_SECONDS:-0}" -gt 0 ] && command -v clang >/dev/null 2>&1; then
  CONF_CC="CC=clang"
  CONF_CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=alignment -g -O1 -fno-omit-frame-pointer"
else
  CONF_CC=""
  CONF_CFLAGS="-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer"
fi
./configure --enable-broker-auth --enable-smartcard --disable-rfxcodec \
  $CONF_CC CFLAGS="$CONF_CFLAGS" >/tmp/scard-lab-conf.log 2>&1
make -C common >/tmp/scard-lab-common.log 2>&1
make -C tests/baf test_smartcard_scard >/tmp/scard-lab-build.log 2>&1

echo "---- unit + robustness vectors (ASan/UBSan) ----"
rc=0
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ./tests/baf/test_smartcard_scard 2>&1 | grep -vE "log reference is NULL" || rc=$?
[ "$rc" -eq 0 ] && echo "SMARTCARD TESTS: PASS" || { echo "SMARTCARD TESTS: FAIL (rc=$rc)"; exit 1; }

if [ "${FUZZ_SECONDS:-0}" -gt 0 ] && command -v clang >/dev/null 2>&1; then
  echo "---- libFuzzer run (${FUZZ_SECONDS}s) ----"
  # -fno-sanitize=alignment: parse.h's x86 fast-path macros do intentional
  # unaligned int access (byte-wise only under NEED_ALIGN); that pre-existing,
  # x86-benign UB is not the target here.
  clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize=alignment \
    -DXRDP_SOCKET_ROOT_PATH='"/tmp"' \
    -I"$BUILD" -I"$BUILD/common" -I"$BUILD/sesman/chansrv" \
    "$BUILD/tests/baf/fuzz/fuzz_smartcard_scard.c" \
    "$BUILD"/common/.libs/libcommon.a \
    -lssl -lcrypto -lpthread -o /tmp/fuzz_smartcard_scard 2>/tmp/scard-lab-fuzz-build.log \
    || { echo "fuzz build failed (see /tmp/scard-lab-fuzz-build.log)"; exit 0; }
  # Seed one valid [MS-RDPESC] response per parser selector + edges.
  CORP=/tmp/scard-fuzz-corpus; mkdir -p "$CORP" /tmp/scard-fuzz-art
  python3 - "$CORP" <<'PY'
import os, struct, sys
d=sys.argv[1]
u=lambda v: struct.pack("<I", v & 0xffffffff); Z=lambda n: bytes(n)
w=lambda n,b: open(os.path.join(d,n),"wb").write(bytes(b))
w("s0", b"\x00\x01"+Z(28)+u(8)+b"CTX01234")
w("s1", b"\x01\x01"+Z(20)+u(0)+Z(4)+u(1)+u(4)+b"9000")
w("s2", b"\x02\x01"+Z(28)+u(4)+b"9000")
w("s3", b"\x03\x01"+Z(36)+u(2)+u(8)+b"CARD0123")
w("s4", b"\x04\x01"+Z(28)+u(1)+u(0x22)+u(0x122)+u(4)+Z(36))
w("s5", b"\x05\x01"+Z(16)+Z(4)+u(0)+Z(4)+u(0)+u(2)+Z(32)+u(4))
w("s6", b"\x06\x01"+Z(16)+Z(12)+u(20)+"R1\0R2\0".encode("utf-16-le"))
PY
  ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
    /tmp/fuzz_smartcard_scard -fork=2 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
      -max_total_time="$FUZZ_SECONDS" -artifact_prefix=/tmp/scard-fuzz-art/ \
      "$CORP" 2>&1 | grep -iE "cov:.*crash:|SUMMARY" | tail -3
  nart=$(ls /tmp/scard-fuzz-art/crash-* /tmp/scard-fuzz-art/*-* 2>/dev/null | wc -l)
  echo "FUZZ ARTIFACTS (crashes/timeouts/ooms): $nart"
  [ "$nart" -eq 0 ] && echo "FUZZ: CLEAN" || echo "FUZZ: FINDINGS in /tmp/scard-fuzz-art/"
else
  echo "(fuzz run skipped: pass --fuzz-seconds N and install clang to enable)"
fi
REMOTE

echo "== smart-card lab tests complete =="
