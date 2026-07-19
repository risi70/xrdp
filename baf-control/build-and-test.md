# Standard Build and Test

## Broker-auth build

```sh
./bootstrap
./configure --disable-rfxcodec --enable-broker-auth
make -j"$(nproc)"
make -C tests/baf check
python3 tests/baf/test_security_contract.py
python3 tests/baf/test_pam_broker_contract.py
```

## Default build

```sh
make distclean || true
./bootstrap
./configure --disable-rfxcodec
make -j"$(nproc)"
make check
```

## Known environment notes

- If NASM/YASM is missing, use `--disable-rfxcodec`.
- If `libcheck` is missing, document that broader non-BAF unit tests may be skipped and run all BAF-specific tests.
- Always report exact commands run and results.
