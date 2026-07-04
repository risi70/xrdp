AM_CPPFLAGS = \
  -I$(top_builddir) \
  -I$(top_srcdir)/sesman/libsesman \
  $(BROKER_AUTH_CFLAGS) \
  -DTEST_PRIVATE_KEY=\"$(srcdir)/data/test-private.pem\" \
  -DTEST_PUBLIC_KEY=\"$(srcdir)/data/test-public.pem\"

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python3

if ENABLE_BROKER_AUTH
TESTS = test_replay_cache test_auth_provider_jwt test_security_contract.py
check_PROGRAMS = test_replay_cache test_auth_provider_jwt
test_replay_cache_SOURCES = test_replay_cache.c
test_replay_cache_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la
test_auth_provider_jwt_SOURCES = test_auth_provider_jwt.c
test_auth_provider_jwt_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
endif

EXTRA_DIST = \
  data/test-private.pem \
  data/test-public.pem \
  fuzz/fuzz_baf_compact.c \
  fuzz/README.md \
  test_security_contract.py
