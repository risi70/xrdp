AM_CPPFLAGS = \
  -I$(top_builddir) \
  -I$(top_srcdir)/sesman/libsesman \
  -I$(top_srcdir)/libipm \
  -I$(top_srcdir)/common

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python3
TESTS = test_classic_auth_contract.py
EXTRA_DIST = test_classic_auth_contract.py

if ENABLE_BROKER_AUTH
TESTS += test_auth_provider_null
check_PROGRAMS = test_auth_provider_null
test_auth_provider_null_SOURCES = test_auth_provider_null.c
test_auth_provider_null_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la
endif
