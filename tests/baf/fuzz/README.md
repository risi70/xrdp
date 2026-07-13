# BAF fuzzing scaffold

The compact-JWS and validator boundary is an optional Clang/libFuzzer target:

```sh
clang -fsanitize=fuzzer,address,undefined \
  -DENABLE_BROKER_AUTH=1 -DBAF_FUZZING=1 -I../../../sesman/libsesman \
  fuzz_baf_compact.c ../../../sesman/libsesman/auth_provider.c \
  ../../../sesman/libsesman/auth_provider_jwt.c \
  ../../../sesman/libsesman/replay_cache.c \
  $(pkg-config --cflags --libs libjwt jansson openssl) -lpthread \
  -o fuzz_baf_compact
```

## MS-RDPESC smart-card parser target

`fuzz_smartcard_scard.c` drives every `scard_function_*_return()` in
`sesman/chansrv/smartcard_pcsc.c` (the `--enable-smartcard` redirection code)
with attacker-controlled bytes and IOStatus, under ASan/UBSan. It complements
the deterministic vectors in `tests/baf/test_smartcard_scard.c` (F1-F9).

```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I../../.. -I../../../common -I../../../sesman/chansrv \
  fuzz_smartcard_scard.c ../../../common/.libs/libcommon.a \
  -lpthread -lcrypto -o fuzz_smartcard_scard
./fuzz_smartcard_scard -max_total_time=60
```

Or run it (and the deterministic vectors) on a lab VM via
`test-lab/kvm/scripts/run-smartcard-tests.sh --host <ip> --fuzz-seconds 60`.

Normal builds do not compile fuzz targets. Corpora must not contain production
assertions or keys.
