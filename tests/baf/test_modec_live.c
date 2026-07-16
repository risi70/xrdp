/*
 * Broker-RDP Handle live daemon-binary integration test.
 *
 * Unlike test_handle_service (which forks baf_handle_service_run() inside
 * the test process), this test launches the *deployed* xrdp-baf-handled
 * executable as a separate process and drives the full Broker-RDP Handle
 * lifecycle against it over a real UNIX socket:
 *
 *   store -> single-use resolve -> recovered bytes match -> real validator
 *   -> replay of the handle fails (single-use)
 *   -> wrong-target resolve fails and consumes the handle (SD-007)
 *
 * It proves the shipped daemon binary, the real handle client API, and the
 * real BAF JWT validator integrate end-to-end. It is the runnable-here half
 * of the Broker-RDP Handle smoke test; the RDP-level channels (routing token and
 * one-time credential through xrdp/sesman/PAM) are exercised on the Phase 6
 * VM by test-lab/phase6/modec-smoke.sh.
 */

#include "auth_provider.h"
#include "auth_provider_jwt.h"
#include "baf_handle_service.h"
#include "baf_transport.h"
#include "replay_cache.h"

#include <assert.h>
#include <jansson.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(condition, message) \
    do \
    { \
        if (!(condition)) \
        { \
            fprintf(stderr, "FAIL: %s\n", (message)); \
            failures++; \
        } \
        else \
        { \
            fprintf(stderr, "ok:   %s\n", (message)); \
        } \
    } while (0)

static unsigned char *
read_file(const char *path, size_t *length)
{
    FILE *stream = fopen(path, "rb");
    long size;
    unsigned char *data;

    assert(stream != NULL);
    assert(fseek(stream, 0, SEEK_END) == 0);
    size = ftell(stream);
    assert(size > 0);
    rewind(stream);
    data = malloc((size_t)size + 1);
    assert(data != NULL);
    assert(fread(data, 1, (size_t)size, stream) == (size_t)size);
    fclose(stream);
    data[size] = '\0';
    *length = (size_t)size;
    return data;
}

static int64_t
fixed_now(void *userdata)
{
    return *(const int64_t *)userdata;
}

static const char *
find_token(json_t *vectors, const char *wanted)
{
    size_t index;
    json_t *vector;

    json_array_foreach(vectors, index, vector)
    {
        const char *name = json_string_value(json_object_get(vector, "name"));
        if (name != NULL && strcmp(name, wanted) == 0)
        {
            return json_string_value(json_object_get(vector, "token"));
        }
    }
    assert(!"required vector missing");
    return NULL;
}

/* Launch the real daemon binary and wait until it answers a ping. */
static pid_t
start_daemon(const char *socket_path)
{
    pid_t pid = fork();
    int attempts;

    assert(pid >= 0);
    if (pid == 0)
    {
        execl(MODEC_HANDLED_BIN, MODEC_HANDLED_BIN, "-s", socket_path,
              (char *)NULL);
        perror("execl xrdp-baf-handled");
        _exit(127);
    }

    for (attempts = 0; attempts < 200; ++attempts)
    {
        if (baf_handle_ping(socket_path, 500) == BAF_HANDLE_OK)
        {
            return pid;
        }
        usleep(10 * 1000);
    }
    fprintf(stderr, "FAIL: daemon %s did not become ready\n",
            MODEC_HANDLED_BIN);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    exit(1);
}

int
main(void)
{
    size_t document_length;
    size_t key_length;
    unsigned char *document_data = read_file(TEST_VECTOR_FILE,
                                   &document_length);
    unsigned char *public_key = read_file(TEST_VECTOR_PUBLIC_KEY, &key_length);
    json_error_t error;
    json_t *document = json_loadb((const char *)document_data,
                                  document_length, 0, &error);
    json_t *vectors;
    const char *valid;
    const char *target;
    char socket_path[128];
    pid_t daemon_pid;
    char handle[BAF_HANDLE_TEXT_LENGTH + 1];
    char handle2[BAF_HANDLE_TEXT_LENGTH + 1];
    unsigned char *resolved = NULL;
    size_t resolved_length = 0;
    struct replay_cache *cache;
    struct baf_validator_options options;
    struct auth_provider_config *config = NULL;
    struct auth_provider_result *result = NULL;
    struct baf_transport transport;
    enum baf_transport_status transport_status;
    int64_t now;

    assert(json_is_object(document));
    vectors = json_object_get(document, "vectors");
    assert(json_is_array(vectors));
    now = json_integer_value(json_object_get(document, "validation_time"));
    valid = find_token(vectors, "valid-rs256");
    target = json_string_value(json_object_get(document, "target"));

    snprintf(socket_path, sizeof(socket_path),
             "/tmp/xrdp-modec-live-%ld.sock", (long)getpid());
    daemon_pid = start_daemon(socket_path);
    CHECK(1, "deployed xrdp-baf-handled daemon accepted a ping");

    /* Store a real signed assertion behind a single-use handle. */
    CHECK(baf_handle_store(socket_path, 1000, (const unsigned char *)valid,
                           strlen(valid), time(NULL) + 60, target,
                           handle) == BAF_HANDLE_OK,
          "real daemon stored the RS256 assertion and issued a handle");

    /* Resolve it once: bytes must match. */
    CHECK(baf_handle_resolve_and_consume(socket_path, 1000, handle, target,
                                         &resolved, &resolved_length) ==
          BAF_HANDLE_OK,
          "real daemon resolved the assertion from the handle");
    CHECK(resolved != NULL && resolved_length == strlen(valid) &&
          memcmp(resolved, valid, resolved_length) == 0,
          "recovered assertion bytes match the stored assertion");

    /* The recovered assertion validates through the real BAF validator. */
    cache = replay_cache_memory_create(32);
    assert(cache != NULL);
    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = json_string_value(json_object_get(document, "issuer"));
    options.expected_audience =
        json_string_value(json_object_get(document, "audience"));
    options.local_target = target;
    options.allowed_algorithms = "RS256";
    options.max_assertion_bytes = 16384;
    options.max_lifetime_seconds = 300;
    options.clock_skew_seconds = 30;
    options.key_id = json_string_value(json_object_get(document, "kid"));
    options.trust_pem = public_key;
    options.trust_pem_length = key_length;
    options.replay_cache = cache;
    assert(baf_validator_config_create(&options, &config) ==
           AUTH_PROVIDER_SUCCESS);

    baf_transport_init(&transport);
    CHECK(baf_transport_set(&transport, resolved, resolved_length, 16384,
                            BAF_ASSERTION_TRANSPORT_INTERNAL, "192.0.2.10",
                            target) == 0,
          "recovered assertion accepted by the BAF transport");
    baf_handle_assertion_free(resolved, resolved_length);
    resolved = NULL;
    resolved_length = 0;
    transport_status = baf_transport_validate(
                           &transport, 1, auth_provider_jwt_get(), config,
                           options.expected_audience, NULL, fixed_now, &now,
                           &result);
    CHECK(transport_status ==
          BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED,
          "recovered assertion validates (identity binding still required)");
    CHECK(result != NULL && auth_provider_result_get_identity(result) != NULL,
          "validator returned a prevalidated capability with identity");
    auth_provider_result_free(result);
    result = NULL;

    /* The handle is single-use: a second resolve must fail. */
    CHECK(baf_handle_resolve_and_consume(socket_path, 1000, handle, target,
                                         &resolved, &resolved_length) !=
          BAF_HANDLE_OK,
          "second resolve of the same handle fails (single-use)");
    baf_handle_assertion_free(resolved, resolved_length);
    resolved = NULL;
    resolved_length = 0;

    /* Wrong-target resolve fails and consumes the handle (SD-007). */
    CHECK(baf_handle_store(socket_path, 1000, (const unsigned char *)valid,
                           strlen(valid), time(NULL) + 60, target,
                           handle2) == BAF_HANDLE_OK,
          "real daemon stored a second assertion");
    CHECK(baf_handle_resolve_and_consume(socket_path, 1000, handle2,
                                         "urn:baf:desktop:wrong-target",
                                         &resolved, &resolved_length) ==
          BAF_HANDLE_TARGET_MISMATCH,
          "resolve with the wrong target is rejected");
    CHECK(resolved == NULL && resolved_length == 0,
          "no assertion bytes leak on target mismatch");
    CHECK(baf_handle_resolve_and_consume(socket_path, 1000, handle2, target,
                                         &resolved, &resolved_length) !=
          BAF_HANDLE_OK,
          "target-mismatched handle cannot be recovered afterwards (SD-007)");
    baf_handle_assertion_free(resolved, resolved_length);

    baf_validator_config_free(config);
    replay_cache_free(cache);
    baf_transport_clear(&transport);
    json_decref(document);
    free(document_data);
    free(public_key);

    kill(daemon_pid, SIGTERM);
    waitpid(daemon_pid, NULL, 0);
    unlink(socket_path);

    if (failures != 0)
    {
        fprintf(stderr, "%d Broker-RDP Handle live check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all Broker-RDP Handle live daemon checks passed\n");
    return 0;
}
