#include "auth_provider.h"
#include "auth_provider_jwt.h"
#include "replay_cache.h"

#include <assert.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int
status_from_string(const char *value, enum auth_provider_status *status)
{
    static const struct
    {
        const char *name;
        enum auth_provider_status status;
    } statuses[] = {
        {"success", AUTH_PROVIDER_SUCCESS},
        {"unsupported", AUTH_PROVIDER_UNSUPPORTED},
        {"invalid", AUTH_PROVIDER_INVALID},
        {"replay", AUTH_PROVIDER_REPLAY},
        {"configuration-error", AUTH_PROVIDER_CONFIG_ERROR},
        {"dependency-unavailable", AUTH_PROVIDER_DEPENDENCY_UNAVAILABLE},
        {"internal-error", AUTH_PROVIDER_INTERNAL_ERROR}
    };
    size_t index;

    if (value == NULL || status == NULL)
    {
        return 0;
    }
    for (index = 0; index < sizeof(statuses) / sizeof(statuses[0]); ++index)
    {
        if (strcmp(value, statuses[index].name) == 0)
        {
            *status = statuses[index].status;
            return 1;
        }
    }
    return 0;
}

int
main(void)
{
    static const char *required_names[] = {
        "valid-rs256", "expired", "not-yet-valid", "lifetime-too-long",
        "wrong-issuer", "wrong-audience", "wrong-target",
        "missing-mandatory-claim", "duplicate-json-member", "alg-none",
        "mac-hs256", "bad-signature", "unknown-kid", "unknown-crit",
        "jku-header", "x5u-header", "embedded-jwk", "replayed-jti",
        "oversized-assertion", "malformed-compact", "invalid-base64url"
    };
    int seen[sizeof(required_names) / sizeof(required_names[0])] = {0};
    size_t document_length;
    size_t key_length;
    unsigned char *document_data =
        read_file(TEST_VECTOR_FILE, &document_length);
    unsigned char *public_key =
        read_file(TEST_VECTOR_PUBLIC_KEY, &key_length);
    json_error_t error;
    json_t *document = json_loadb((const char *)document_data,
                                  document_length, 0, &error);
    json_t *vectors;
    struct replay_cache *cache;
    struct baf_validator_options options;
    struct auth_provider_config *config = NULL;
    int64_t now;
    size_t index;
    json_t *vector;
    int valid_vector_released = 0;

    assert(json_is_object(document));
    vectors = json_object_get(document, "vectors");
    assert(json_is_array(vectors));
    assert(json_array_size(vectors) > 0);
    now = json_integer_value(json_object_get(document, "validation_time"));
    cache = replay_cache_memory_create(128);
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

    json_array_foreach(vectors, index, vector)
    {
        const char *name =
            json_string_value(json_object_get(vector, "name"));
        const char *token =
            json_string_value(json_object_get(vector, "token"));
        const char *expected =
            json_string_value(json_object_get(vector, "expected_status"));
        const char *expected_alias =
            json_string_value(json_object_get(
                                  vector, "expected_validator_status"));
        struct auth_provider_request request;
        struct auth_provider_result *result = NULL;
        enum auth_provider_status expected_status;
        enum auth_provider_status status;

        assert(name != NULL && token != NULL && expected != NULL);
        assert(status_from_string(expected, &expected_status));
        assert(expected_alias == NULL || strcmp(expected, expected_alias) == 0);
        assert(json_is_string(json_object_get(vector, "description")));
        assert(json_is_string(json_object_get(vector, "reason")));
        assert(json_is_object(json_object_get(vector,
                                              "validator_config_overrides")));
        {

            size_t required_index;
            for (required_index = 0;
                    required_index < sizeof(required_names) /
                    sizeof(required_names[0]);
                    ++required_index)
            {
                if (strcmp(name, required_names[required_index]) == 0)
                {
                    seen[required_index] = 1;
                }
            }
        }
        memset(&request, 0, sizeof(request));
        request.assertion = (const unsigned char *)token;
        request.assertion_length = strlen(token);
        request.client_address = "192.0.2.10";
        request.config = config;
        request.expected_audience = options.expected_audience;
        request.local_target = options.local_target;
        request.now = fixed_now;
        request.now_userdata = &now;

        status = auth_provider_validate(auth_provider_jwt_get(), &request,
                                        &result);
        if (status != expected_status)
        {
            fprintf(stderr, "%s: expected %s, got %s\n", name, expected,
                    auth_provider_status_to_string(status));
            return 1;
        }
        /*
         * replayed-jti reuses valid-rs256's (iss,jti). Release is an
         * audit-only transition in Phase 2 and must not permit reuse.
         */
        if (strcmp(name, "valid-rs256") == 0)
        {
            const struct auth_prevalidated_identity *identity =
                auth_provider_result_get_identity(result);
            const unsigned char *key =
                auth_prevalidated_identity_get_jti_digest(identity);

            assert(status == AUTH_PROVIDER_SUCCESS);
            assert(key != NULL);
            assert(replay_cache_release(cache, key, now) == REPLAY_CACHE_OK);
            valid_vector_released = 1;
        }
        else if (strcmp(name, "replayed-jti") == 0)
        {
            assert(valid_vector_released);
            assert(status == AUTH_PROVIDER_REPLAY);
        }
        auth_provider_result_free(result);
    }
    for (index = 0;
            index < sizeof(required_names) / sizeof(required_names[0]);
            ++index)
    {
        assert(seen[index]);
    }
    assert(valid_vector_released);

    baf_validator_config_free(config);
    replay_cache_free(cache);
    json_decref(document);
    free(document_data);
    free(public_key);
    return 0;
}
