AM_CPPFLAGS = \
  -I$(top_builddir) \
  -I$(top_srcdir)/common \
  -I$(top_srcdir)/sesman/libsesman \
  -I$(top_srcdir)/libipm \
  -DXRDP_SOCKET_ROOT_PATH=\"/tmp\" \
  $(BROKER_AUTH_CFLAGS) \
  -DTEST_PRIVATE_KEY=\"$(srcdir)/data/test-private.pem\" \
  -DTEST_PUBLIC_KEY=\"$(srcdir)/data/test-public.pem\" \
  -DTEST_VECTOR_FILE=\"$(top_srcdir)/broker-auth/vectors/phase2-vectors.json\" \
  -DTEST_VECTOR_PUBLIC_KEY=\"$(top_srcdir)/broker-auth/vectors/test-public.pem\"

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python3

if ENABLE_BROKER_AUTH
TESTS = test_replay_cache test_auth_provider_jwt test_phase2_vectors \
  test_baf_runtime_config test_baf_transport test_baf_identity test_replay_service test_handle_service \
  test_rdsaad_ingress \
  test_pam_broker_contract.py \
  test_security_contract.py
check_PROGRAMS = test_replay_cache test_auth_provider_jwt test_phase2_vectors \
  test_baf_runtime_config test_baf_transport test_baf_identity test_replay_service test_handle_service test_rdsaad_ingress
test_replay_cache_SOURCES = test_replay_cache.c
test_replay_cache_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la
test_replay_service_SOURCES = test_replay_service.c
test_replay_service_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la
test_baf_runtime_config_SOURCES = test_baf_runtime_config.c
test_baf_runtime_config_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(top_builddir)/common/libcommon.la
test_handle_service_SOURCES = test_handle_service.c
test_handle_service_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
test_auth_provider_jwt_SOURCES = test_auth_provider_jwt.c
test_auth_provider_jwt_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
test_phase2_vectors_SOURCES = test_phase2_vectors.c
test_phase2_vectors_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
test_baf_transport_SOURCES = test_baf_transport.c
test_baf_transport_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
test_baf_identity_SOURCES = test_baf_identity.c
test_baf_identity_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(BROKER_AUTH_LIBS)
test_rdsaad_ingress_SOURCES = test_rdsaad_ingress.c
test_rdsaad_ingress_LDADD = \
  $(top_builddir)/sesman/libsesman/libsesman.la \
  $(top_builddir)/common/libcommon.la \
  $(BROKER_AUTH_LIBS)
endif

EXTRA_DIST = \
  data/test-private.pem \
  data/test-public.pem \
  fuzz/fuzz_baf_compact.c \
  fuzz/README.md \
  test_baf_identity.c \
  test_baf_runtime_config.c \
  test_baf_transport.c \
  test_handle_service.c \
  test_pam_broker_contract.py \
  test_phase2_vectors.c \
  test_rdsaad_ingress.c \
  test_replay_service.c \
  test_security_contract.py

# Top-level EXTRA_DIST includes broker-auth, preserving vector asset paths.
