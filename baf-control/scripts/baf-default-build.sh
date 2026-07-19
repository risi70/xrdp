#!/usr/bin/env bash
set -euo pipefail

make distclean || true
./bootstrap
./configure --disable-rfxcodec
make -j"$(nproc)"
make check
