#include "auth_provider_jwt.h"
#include "baf_identity.h"
#include "replay_cache.h"
#include <assert.h>
#include <jansson.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum lookup_mode { LOOKUP_VALID, LOOKUP_UNKNOWN, LOOKUP_ROOT, LOOKUP_AMBIGUOUS };
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
    assert(!"required vector missing");
    return NULL;
}
static enum baf_nss_status mock_lookup(const char *username, void *userdata,
                                       struct baf_nss_record *record)
{
    enum lookup_mode mode = *(enum lookup_mode *)userdata;
    assert(strcmp(username, "alice") == 0);
    if (mode == LOOKUP_UNKNOWN)
    {
        return BAF_NSS_NOT_FOUND;
    }
    if (mode == LOOKUP_AMBIGUOUS)
    {
        return BAF_NSS_AMBIGUOUS;
    }
    record->canonical_username = "alice";
    record->uid = mode == LOOKUP_ROOT ? 0 : 1000;
    record->primary_gid = mode == LOOKUP_ROOT ? 0 : 1000;
    record->home_directory = "/home/alice";
    record->shell = "/bin/sh";
    return BAF_NSS_SUCCESS;
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
    struct replay_cache *cache = replay_cache_memory_create(16);
    struct baf_validator_options validator;
    struct auth_provider_config *config = NULL;
    struct auth_provider_request request;
    struct auth_provider_result *capability = NULL;
    struct baf_resolved_identity *identity = NULL;
    struct baf_identity_options options;
    enum lookup_mode mode;
    int64_t now;
    char overlong[BAF_IDENTITY_MAX_USERNAME_BYTES + 2];
    {
        struct passwd *current = getpwuid(getuid());
        struct baf_nss_record system_record;
        assert(current != NULL);
        assert(baf_nss_lookup_system(current->pw_name, NULL, &system_record) ==
               BAF_NSS_SUCCESS);
        assert(system_record.uid == getuid());
        assert(system_record.canonical_username != NULL);
        free(system_record.storage);
    }
    assert(json_is_object(document));
    assert(cache != NULL);
    vectors = json_object_get(document, "vectors");
    now = json_integer_value(json_object_get(document, "validation_time"));
    memset(&validator, 0, sizeof(validator));
    validator.enabled = 1;
    validator.issuer = json_string_value(json_object_get(document, "issuer"));
    validator.expected_audience = json_string_value(json_object_get(document, "audience"));
    validator.local_target = json_string_value(json_object_get(document, "target"));
    validator.allowed_algorithms = "RS256";
    validator.max_assertion_bytes = 16384;
    validator.max_lifetime_seconds = 300;
    validator.clock_skew_seconds = 30;
    validator.key_id = json_string_value(json_object_get(document, "kid"));
    validator.trust_pem = public_key;
    validator.trust_pem_length = key_length;
    validator.replay_cache = cache;
    assert(baf_validator_config_create(&validator, &config) == AUTH_PROVIDER_SUCCESS);
    memset(&request, 0, sizeof(request));
    request.assertion = (const unsigned char *)find_token(vectors, "valid-rs256");
    request.assertion_length = strlen((const char *)request.assertion);
    request.client_address = "192.0.2.10";
    request.config = config;
    request.expected_audience = validator.expected_audience;
    request.local_target = validator.local_target;
    request.now = fixed_now;
    request.now_userdata = &now;
    assert(auth_provider_validate(auth_provider_jwt_get(), &request,
                                  &capability) == AUTH_PROVIDER_SUCCESS);
    memset(&options, 0, sizeof(options));
    mode = LOOKUP_VALID;
    assert(baf_identity_bind(capability, &options, mock_lookup, &mode,
                             &identity) == BAF_IDENTITY_SUCCESS);
    assert(strcmp(baf_resolved_identity_get_username(identity), "alice") == 0);
    assert(baf_resolved_identity_get_uid(identity) == 1000);
    assert(baf_resolved_identity_get_primary_gid(identity) == 1000);
    assert(strcmp(baf_resolved_identity_get_home(identity), "/home/alice") == 0);
    baf_resolved_identity_free(identity);
    identity = NULL;
    mode = LOOKUP_UNKNOWN;
    assert(baf_identity_bind(capability, &options, mock_lookup, &mode,
                             &identity) == BAF_IDENTITY_NOT_FOUND);
    mode = LOOKUP_ROOT;
    assert(baf_identity_bind(capability, &options, mock_lookup, &mode,
                             &identity) == BAF_IDENTITY_UID0_REJECTED);
    mode = LOOKUP_AMBIGUOUS;
    assert(baf_identity_bind(capability, &options, mock_lookup, &mode,
                             &identity) == BAF_IDENTITY_AMBIGUOUS);
    assert(baf_identity_bind(NULL, &options, mock_lookup, &mode,
                             &identity) == BAF_IDENTITY_INVALID_CAPABILITY);
    assert(!baf_identity_username_is_safe("", 255));
    assert(!baf_identity_username_is_safe("bad/user", 255));
    assert(!baf_identity_username_is_safe("bad user", 255));
    assert(!baf_identity_username_is_safe("bad\nuser", 255));
    assert(baf_identity_username_is_safe("EXAMPLE\\alice", 255));
    assert(baf_identity_username_is_safe("alice@example.test", 255));
    memset(overlong, 'a', sizeof(overlong));
    overlong[sizeof(overlong) - 1] = '\0';
    assert(!baf_identity_username_is_safe(overlong, 255));
    auth_provider_result_free(capability);
    capability = NULL;
    assert(auth_provider_validate(auth_provider_jwt_get(), &request,
                                  &capability) == AUTH_PROVIDER_REPLAY);
    assert(capability == NULL);
    baf_validator_config_free(config);
    replay_cache_free(cache);
    json_decref(document);
    free(document_data);
    free(public_key);
    return 0;
}
