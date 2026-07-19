#!/usr/bin/env bash
set -euo pipefail

./bootstrap
./configure --disable-rfxcodec --enable-broker-auth
make -j"$(nproc)"
make -C tests/baf check
python3 tests/baf/test_security_contract.py
python3 tests/baf/test_pam_broker_contract.py
