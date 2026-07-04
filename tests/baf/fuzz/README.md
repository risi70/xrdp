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

Normal builds do not compile fuzz targets. Corpora must not contain production
assertions or keys.
