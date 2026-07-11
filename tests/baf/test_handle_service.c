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

#define WORKERS 16

static int failures;

#define CHECK(condition, message) \
    do \
    { \
        if (!(condition)) \
        { \
            fprintf(stderr, "FAIL: %s\n", (message)); \
            failures++; \
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
    assert(!"required handle integration vector missing");
    return NULL;
}

static int
ready(const char *path)
{
    int index;

    for (index = 0; index < 100; ++index)
    {
        if (baf_handle_ping(path, 100) == BAF_HANDLE_OK)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

static void
concurrent(const char *path, const char *handle)
{
    pid_t pid[WORKERS];
    int index;
    int ok = 0;
    int rejected = 0;

    for (index = 0; index < WORKERS; ++index)
    {
        pid[index] = fork();
        if (pid[index] == 0)
        {
            unsigned char *assertion = NULL;
            size_t assertion_length = 0;
            enum baf_handle_status status =
                baf_handle_resolve_and_consume(path, 1000, handle, "target-a",
                                               &assertion, &assertion_length);
            baf_handle_assertion_free(assertion, assertion_length);
            _exit(status == BAF_HANDLE_OK ? 0 :
                  (status == BAF_HANDLE_NOT_FOUND ||
                   status == BAF_HANDLE_CONSUMED) ? 10 : 20);
        }
    }

    for (index = 0; index < WORKERS; ++index)
    {
        int status;

        if (waitpid(pid[index], &status, 0) > 0 && WIFEXITED(status))
        {
            if (WEXITSTATUS(status) == 0)
            {
                ok++;
            }
            else if (WEXITSTATUS(status) == 10)
            {
                rejected++;
            }
        }
    }

    CHECK(ok == 1, "exactly one concurrent resolve succeeds");
    CHECK(rejected == WORKERS - 1, "all other resolves fail closed");
}

static void
validate_resolved_handle_assertion(const char *path)
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
    struct replay_cache *cache;
    struct baf_validator_options options;
    struct auth_provider_config *config = NULL;
    struct auth_provider_result *result = NULL;
    struct baf_transport transport;
    int64_t now;
    const char *valid;
    unsigned char *resolved = NULL;
    size_t resolved_length = 0;
    char handle[BAF_HANDLE_TEXT_LENGTH + 1];
    enum baf_transport_status transport_status;

    assert(json_is_object(document));
    vectors = json_object_get(document, "vectors");
    assert(json_is_array(vectors));
    now = json_integer_value(json_object_get(document, "validation_time"));
    valid = find_token(vectors, "valid-rs256");

    CHECK(baf_handle_store(path, 1000, (const unsigned char *)valid,
                           strlen(valid), time(NULL) + 60,
                           json_string_value(json_object_get(document,
                                                             "target")),
                           handle) == BAF_HANDLE_OK,
          "stored RS256 vector assertion behind server-side handle");
    CHECK(baf_handle_resolve_and_consume(path, 1000, handle,
                                         json_string_value(json_object_get(
                                             document, "target")),
                                         &resolved, &resolved_length) ==
          BAF_HANDLE_OK,
          "resolved RS256 vector assertion from handle service");
    CHECK(resolved_length == strlen(valid) &&
          memcmp(resolved, valid, resolved_length) == 0,
          "resolved assertion bytes match stored vector");

    cache = replay_cache_memory_create(32);
    assert(cache != NULL);

    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = json_string_value(json_object_get(document, "issuer"));
    options.expected_audience =
        json_string_value(json_object_get(document, "audience"));
    options.local_target =
        json_string_value(json_object_get(document, "target"));
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
                            options.local_target) == 0,
          "resolved assertion accepted by existing BAF transport");
    baf_handle_assertion_free(resolved, resolved_length);
    resolved = NULL;
    resolved_length = 0;

    transport_status = baf_transport_validate(
        &transport, 1, auth_provider_jwt_get(), config,
        options.expected_audience, NULL, fixed_now, &now, &result);
    CHECK(transport_status ==
          BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED,
          "resolved handle assertion validates but is not login authorization");
    CHECK(result != NULL, "validator returned prevalidated capability");
    CHECK(auth_provider_result_get_identity(result) != NULL,
          "capability has identity claims for later Phase 4b-2 binding");

    auth_provider_result_free(result);
    baf_validator_config_free(config);
    replay_cache_free(cache);
    json_decref(document);
    free(document_data);
    free(public_key);
}

int
main(void)
{
    char path[96];
    char handle[BAF_HANDLE_TEXT_LENGTH + 1];
    char unknown[BAF_HANDLE_TEXT_LENGTH + 1];
    char concurrent_handle[BAF_HANDLE_TEXT_LENGTH + 1];
    pid_t server;
    unsigned char *out = NULL;
    size_t out_length = 0;
    const unsigned char assertion[] = "header.payload.signature";

    snprintf(path, sizeof(path), "/tmp/xrdp-baf-handle-%ld.sock",
             (long)getpid());
    unlink(path);

    server = fork();
    if (server == 0)
    {
        _exit(baf_handle_service_run(path, 64, 120));
    }
    CHECK(server > 0 && ready(path), "service ready");

    CHECK(baf_handle_store(path, 1000, assertion, sizeof(assertion) - 1,
                           time(NULL) + 60, "target-a", handle) ==
          BAF_HANDLE_OK,
          "store assertion");
    CHECK(strlen(handle) == BAF_HANDLE_TEXT_LENGTH, "256-bit hex handle");
    CHECK(strstr(handle, "header") == NULL, "handle does not contain assertion");
    CHECK(baf_handle_resolve_and_consume(path, 1000, handle, "wrong-target",
                                         &out, &out_length) ==
          BAF_HANDLE_TARGET_MISMATCH,
          "target mismatch rejected");
    CHECK(out == NULL && out_length == 0,
          "target mismatch does not return assertion bytes");
    CHECK(baf_handle_resolve_and_consume(path, 1000, handle, "target-a",
                                         &out, &out_length) ==
          BAF_HANDLE_NOT_FOUND,
          "target mismatch consumes handle");
    CHECK(out == NULL && out_length == 0,
          "consumed mismatched handle cannot recover assertion");

    CHECK(baf_handle_store(path, 1000, assertion, sizeof(assertion) - 1,
                           time(NULL) + 60, "target-a", handle) ==
          BAF_HANDLE_OK,
          "store assertion for valid resolve");
    CHECK(baf_handle_resolve_and_consume(path, 1000, handle, "target-a",
                                         &out, &out_length) ==
          BAF_HANDLE_OK &&
          out_length == sizeof(assertion) - 1 &&
          memcmp(out, assertion, out_length) == 0,
          "valid resolve returns assertion");
    baf_handle_assertion_free(out, out_length);
    out = NULL;
    out_length = 0;
    CHECK(baf_handle_resolve_and_consume(path, 1000, handle, "target-a",
                                         &out, &out_length) ==
          BAF_HANDLE_NOT_FOUND,
          "second valid resolve rejected");
    CHECK(out == NULL && out_length == 0,
          "second valid resolve returns no assertion bytes");
    CHECK(baf_handle_resolve_and_consume(path, 1000, "bad", "target-a",
                                         &out, &out_length) ==
          BAF_HANDLE_BAD_REQUEST,
          "malformed handle rejected");
    memset(unknown, 'a', BAF_HANDLE_TEXT_LENGTH);
    unknown[BAF_HANDLE_TEXT_LENGTH] = '\0';
    CHECK(baf_handle_resolve_and_consume(path, 1000, unknown, "target-a",
                                         &out, &out_length) ==
          BAF_HANDLE_NOT_FOUND,
          "unknown handle rejected");
    CHECK(baf_handle_store(path, 1000, assertion, sizeof(assertion) - 1,
                           time(NULL) + 121, "target-a", unknown) ==
          BAF_HANDLE_BAD_REQUEST,
          "excessive lifetime rejected");
    CHECK(baf_handle_store(path, 1000, assertion, sizeof(assertion) - 1,
                           time(NULL) - 1, "target-a", unknown) ==
          BAF_HANDLE_BAD_REQUEST,
          "expired assertion rejected");
    {
        unsigned char *big = malloc(BAF_HANDLE_MAX_ASSERTION + 1);

        CHECK(big != NULL, "oversize buffer allocated");
        CHECK(baf_handle_store(path, 1000, big, BAF_HANDLE_MAX_ASSERTION + 1,
                               time(NULL) + 60, "target-a", unknown) ==
              BAF_HANDLE_BAD_REQUEST,
              "oversize rejected");
        free(big);
    }

    validate_resolved_handle_assertion(path);

    CHECK(baf_handle_store(path, 1000, assertion, sizeof(assertion) - 1,
                           time(NULL) + 60, "target-a",
                           concurrent_handle) == BAF_HANDLE_OK,
          "store concurrent assertion");
    concurrent(path, concurrent_handle);

    kill(server, SIGTERM);
    waitpid(server, NULL, 0);
    unlink(path);
    CHECK(baf_handle_ping(path, 100) == BAF_HANDLE_UNAVAILABLE,
          "unavailable service fails closed");

    return failures ? 1 : 0;
}
