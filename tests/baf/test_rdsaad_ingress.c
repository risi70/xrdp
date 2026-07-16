#include "auth_provider_jwt.h"
#include "baf_transport.h"
#include "rdsaad.h"
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
    assert(!"required RDSAAD ingress vector missing");
    return NULL;
}

static void
make_auth_request(const char *token, char *output, size_t output_size,
                  size_t *written)
{
    int n = snprintf(output, output_size, "{\"rdp_assertion\":\"%s\"}", token);

    assert(n > 0);
    assert((size_t)n < output_size);
    *written = (size_t)n;
}

static enum baf_transport_status
validate_rdsaad_token(const char *token, struct auth_provider_config *config,
                      int64_t *now, struct auth_provider_result **result)
{
    char request[RDSAAD_MAX_ASSERTION_BYTES + 64];
    char assertion[RDSAAD_MAX_ASSERTION_BYTES + 1];
    size_t request_length;
    size_t assertion_length;
    struct baf_transport transport;
    enum baf_transport_status status;

    make_auth_request(token, request, sizeof(request), &request_length);
    assert(rdsaad_parse_authentication_request(request, request_length,
            assertion, sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_OK);
    assert(assertion_length == strlen(token));
    assert(strcmp(assertion, token) == 0);

    baf_transport_init(&transport);
    assert(baf_transport_set(&transport, (const unsigned char *)assertion,
                             assertion_length, RDSAAD_MAX_ASSERTION_BYTES,
                             BAF_ASSERTION_TRANSPORT_TEST,
                             "192.0.2.10", "urn:baf:desktop:test") == 0);
    status = baf_transport_validate(&transport, 1, auth_provider_jwt_get(),
                                    config, "urn:baf:xrdp:test", NULL,
                                    fixed_now, now, result);
    assert(transport.assertion == NULL);
    assert(transport.assertion_length == 0);
    return status;
}

int
main(void)
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
    int64_t now;
    char output[512];
    char assertion[RDSAAD_MAX_ASSERTION_BYTES + 1];
    size_t written;
    size_t assertion_length;
    char *oversized_json;
    char *oversized_assertion;
    char *oversized_request;
    const char *duplicate_request =
        "{\"rdp_assertion\":\"a\",\"rdp_assertion\":\"b\"}";
    const char *escaped_request = "{\"rdp_assertion\":\"a\\nb\"}";
    const char *valid;

    assert(json_is_object(document));
    vectors = json_object_get(document, "vectors");
    assert(json_is_array(vectors));
    now = json_integer_value(json_object_get(document, "validation_time"));

    assert(rdsaad_encode_server_nonce("nonce-123", output, sizeof(output),
                                      &written) == RDSAAD_STATUS_OK);
    assert(strcmp(output, "{\"ts_nonce\":\"nonce-123\"}") == 0);
    assert(written == strlen(output));
    assert(rdsaad_encode_server_nonce("bad\"nonce", output, sizeof(output),
                                      &written) == RDSAAD_STATUS_INVALID);
    assert(rdsaad_encode_authentication_result(RDSAAD_HRESULT_E_ACCESSDENIED,
            output, sizeof(output),
            &written) == RDSAAD_STATUS_OK);
    assert(strcmp(output, "{\"authentication_result\":\"2147942405\"}") == 0);

    assert(rdsaad_parse_authentication_request("{}", 2, assertion,
            sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_MISSING_FIELD);
    assert(rdsaad_parse_authentication_request("{bad", 4, assertion,
            sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_INVALID);
    assert(rdsaad_parse_authentication_request(duplicate_request,
            strlen(duplicate_request),
            assertion, sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_DUPLICATE_FIELD);
    assert(rdsaad_parse_authentication_request(escaped_request,
            strlen(escaped_request),
            assertion, sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_INVALID);

    oversized_json = malloc(RDSAAD_MAX_JSON_BYTES + 2);
    assert(oversized_json != NULL);
    memset(oversized_json, ' ', RDSAAD_MAX_JSON_BYTES + 1);
    assert(rdsaad_parse_authentication_request(oversized_json,
            RDSAAD_MAX_JSON_BYTES + 1,
            assertion, sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_OVERSIZE);
    free(oversized_json);

    oversized_assertion = malloc(RDSAAD_MAX_ASSERTION_BYTES + 2);
    oversized_request = malloc(RDSAAD_MAX_ASSERTION_BYTES + 64);
    assert(oversized_assertion != NULL);
    assert(oversized_request != NULL);
    memset(oversized_assertion, 'a', RDSAAD_MAX_ASSERTION_BYTES + 1);
    oversized_assertion[RDSAAD_MAX_ASSERTION_BYTES + 1] = '\0';
    make_auth_request(oversized_assertion, oversized_request,
                      RDSAAD_MAX_ASSERTION_BYTES + 64, &written);
    assert(rdsaad_parse_authentication_request(oversized_request, written,
            assertion, sizeof(assertion),
            &assertion_length) ==
           RDSAAD_STATUS_OVERSIZE);
    free(oversized_request);
    free(oversized_assertion);

    cache = replay_cache_memory_create(64);
    assert(cache != NULL);
    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = json_string_value(json_object_get(document, "issuer"));
    options.expected_audience = json_string_value(json_object_get(document, "audience"));
    options.local_target = json_string_value(json_object_get(document, "target"));
    options.allowed_algorithms = "RS256";
    options.max_assertion_bytes = RDSAAD_MAX_ASSERTION_BYTES;
    options.max_lifetime_seconds = 300;
    options.clock_skew_seconds = 30;
    options.key_id = json_string_value(json_object_get(document, "kid"));
    options.trust_pem = public_key;
    options.trust_pem_length = key_length;
    options.replay_cache = cache;
    assert(baf_validator_config_create(&options, &config) == AUTH_PROVIDER_SUCCESS);

    valid = find_token(vectors, "valid-rs256");
    assert(validate_rdsaad_token(valid, config, &now, &result) ==
           BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED);
    assert(result != NULL);
    auth_provider_result_free(result);
    result = NULL;
    assert(validate_rdsaad_token(find_token(vectors, "replayed-jti"), config,
                                 &now, &result) == BAF_TRANSPORT_REPLAY);
    assert(result == NULL);
    assert(validate_rdsaad_token(find_token(vectors, "expired"), config,
                                 &now, &result) == BAF_TRANSPORT_REJECTED);
    assert(result == NULL);
    assert(validate_rdsaad_token(find_token(vectors, "bad-signature"), config,
                                 &now, &result) == BAF_TRANSPORT_REJECTED);
    assert(result == NULL);
    assert(validate_rdsaad_token(find_token(vectors, "wrong-audience"), config,
                                 &now, &result) == BAF_TRANSPORT_REJECTED);
    assert(result == NULL);

    baf_validator_config_free(config);
    replay_cache_free(cache);
    json_decref(document);
    free(public_key);
    free(document_data);
    return 0;
}
