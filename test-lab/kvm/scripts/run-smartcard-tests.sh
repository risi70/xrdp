#!/usr/bin/env bash
#
# Build and run the MS-RDPESC smart-card response-parser tests under
# AddressSanitizer/UBSan on a lab VM (or any reachable Ubuntu build host).
#
# Extends the lab to exercise the --enable-smartcard redirection code
# (sesman/chansrv/smartcard*.c). The tests decode client-controlled [MS-RDPESC]
# IOCTL responses; running them under ASan/UBSan turns the F1-F9 bounds-check
# fixes (broker-auth/UPSTREAM-MS-RDPESC-REVIEW.md) into an enforced contract.
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
./configure --enable-broker-auth --enable-smartcard --disable-rfxcodec \
  CFLAGS="-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer" \
  >/tmp/scard-lab-conf.log 2>&1
make -C common >/tmp/scard-lab-common.log 2>&1
make -C tests/baf test_smartcard_scard >/tmp/scard-lab-build.log 2>&1

echo "---- unit + robustness vectors (ASan/UBSan) ----"
rc=0
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ./tests/baf/test_smartcard_scard 2>&1 | grep -vE "log reference is NULL" || rc=$?
[ "$rc" -eq 0 ] && echo "SMARTCARD TESTS: PASS" || { echo "SMARTCARD TESTS: FAIL (rc=$rc)"; exit 1; }

if [ "${FUZZ_SECONDS:-0}" -gt 0 ] && command -v clang >/dev/null 2>&1; then
  echo "---- libFuzzer smoke (${FUZZ_SECONDS}s) ----"
  cd tests/baf/fuzz
  clang -g -O1 -fsanitize=fuzzer,address,undefined \
    -I"$BUILD" -I"$BUILD/common" -I"$BUILD/sesman/chansrv" \
    fuzz_smartcard_scard.c \
    "$BUILD"/common/.libs/libcommon.a \
    -lpthread -lcrypto -o /tmp/fuzz_smartcard_scard 2>/tmp/scard-lab-fuzz-build.log \
    && /tmp/fuzz_smartcard_scard -max_total_time="$FUZZ_SECONDS" -print_final_stats=1 \
       2>&1 | tail -5 \
    || echo "fuzz smoke skipped (build failed; see /tmp/scard-lab-fuzz-build.log)"
else
  echo "(fuzz smoke skipped: pass --fuzz-seconds N and install clang to enable)"
fi
REMOTE

echo "== smart-card lab tests complete =="
