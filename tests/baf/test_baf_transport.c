#include "auth_provider_jwt.h"
#include "baf_transport.h"
#include "replay_cache.h"
#include <assert.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned char *read_file(const char *path, size_t *length)
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
static int64_t fixed_now(void *userdata)
{
    return *(const int64_t *)userdata;
}
static const char *find_token(json_t *vectors, const char *wanted)
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
    assert(!"required transport vector missing");
    return NULL;
}
static enum baf_transport_status
run_token(const char *token, int runtime_enabled,
          struct auth_provider_config *config, int64_t *now,
          struct auth_provider_result **result)
{
    struct baf_transport transport;
    enum baf_transport_status status;
    baf_transport_init(&transport);
    assert(baf_transport_set(&transport, (const unsigned char *)token,
                             strlen(token), 16384,
                             BAF_ASSERTION_TRANSPORT_TEST,
                             "192.0.2.10", "urn:baf:desktop:test") == 0);
    status = baf_transport_validate(&transport, runtime_enabled,
                                    auth_provider_jwt_get(), config,
                                    "urn:baf:xrdp:test", fixed_now, now,
                                    result);
    assert(transport.assertion == NULL);
    assert(transport.assertion_length == 0);
    return status;
}
int main(void)
{
    size_t document_length;
    size_t key_length;
    unsigned char *document_data = read_file(TEST_VECTOR_FILE, &document_length);
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
    static const struct { const char *name; enum baf_transport_status status; }
    negative[] = {
        {"wrong-audience", BAF_TRANSPORT_REJECTED},
        {"wrong-target", BAF_TRANSPORT_REJECTED},
        {"expired", BAF_TRANSPORT_REJECTED},
        {"bad-signature", BAF_TRANSPORT_REJECTED}
    };
    size_t index;
    assert(json_is_object(document));
    vectors = json_object_get(document, "vectors");
    assert(json_is_array(vectors));
    now = json_integer_value(json_object_get(document, "validation_time"));
    cache = replay_cache_memory_create(32);
    assert(cache != NULL);
    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = json_string_value(json_object_get(document, "issuer"));
    options.expected_audience = json_string_value(json_object_get(document, "audience"));
    options.local_target = json_string_value(json_object_get(document, "target"));
    options.allowed_algorithms = "RS256";
    options.max_assertion_bytes = 16384;
    options.max_lifetime_seconds = 300;
    options.clock_skew_seconds = 30;
    options.key_id = json_string_value(json_object_get(document, "kid"));
    options.trust_pem = public_key;
    options.trust_pem_length = key_length;
    options.replay_cache = cache;
    assert(baf_validator_config_create(&options, &config) == AUTH_PROVIDER_SUCCESS);

    baf_transport_init(&transport);
    assert(baf_transport_set(&transport, NULL, 0, 16384,
                             BAF_ASSERTION_TRANSPORT_TEST, "", "") != 0);
    assert(baf_transport_set(&transport, (const unsigned char *)"x", 1, 0,
                             BAF_ASSERTION_TRANSPORT_TEST, "", "") != 0);
    assert(baf_transport_set(&transport, (const unsigned char *)"xx", 2, 1,
                             BAF_ASSERTION_TRANSPORT_TEST, "", "") != 0);
    baf_transport_clear(&transport);

    valid = find_token(vectors, "valid-rs256");
    assert(run_token(valid, 0, config, &now, &result) == BAF_TRANSPORT_UNSUPPORTED);
    assert(result == NULL);
    assert(run_token(valid, 1, config, &now, &result) ==
           BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED);
    assert(result != NULL);
    assert(auth_provider_result_get_identity(result) != NULL);
    auth_provider_result_free(result);
    result = NULL;
    assert(run_token(find_token(vectors, "replayed-jti"), 1, config, &now,
                     &result) == BAF_TRANSPORT_REPLAY);
    assert(result == NULL);
    for (index = 0; index < sizeof(negative) / sizeof(negative[0]); ++index)
    {
        assert(run_token(find_token(vectors, negative[index].name), 1,
                         config, &now, &result) == negative[index].status);
        assert(result == NULL);
    }
    baf_validator_config_free(config);
    replay_cache_free(cache);
    json_decref(document);
    free(document_data);
    free(public_key);
    return 0;
}
