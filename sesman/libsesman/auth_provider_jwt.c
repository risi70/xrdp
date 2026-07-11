#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "auth_provider_jwt.h"
#include "auth_provider_jwt_private.h"
#include "auth_provider_private.h"
#include "replay_cache.h"

#include <jansson.h>
#include <jwt.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(ENABLE_BROKER_AUTH)
#error "auth_provider_jwt.c must only be built with broker auth enabled"
#endif

#define BAF_MAX_TRUST_FILE_BYTES (1024 * 1024)

static char *
copy_string(const char *value)
{
    size_t length;
    char *copy;
    if (value == NULL)
    {
        return NULL;
    }
    length = strlen(value);
    copy = malloc(length + 1);
    if (copy != NULL)
    {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

static int
copy_string_array(json_t *array, char ***output, size_t *output_count)
{
    size_t index;
    size_t count = json_array_size(array);
    char **values = calloc(count == 0 ? 1 : count, sizeof(values[0]));
    if (values == NULL)
    {
        return 0;
    }
    *output = values;
    *output_count = 0;
    for (index = 0; index < count; ++index)
    {
        values[index] = copy_string(json_string_value(json_array_get(array, index)));
        if (values[index] == NULL)
        {
            return 0;
        }
        *output_count = index + 1;
    }
    return 1;
}

static int
nonempty(const char *value)
{
    return value != NULL && value[0] != '\0';
}

/**
 * Enforce the urn:baf:ts_nonce extension against the ingress challenge.
 *
 * When binding is required, the ingress must supply a nonce and the
 * assertion must carry a matching extension. When binding is optional, a
 * present extension must still match any available ingress nonce; a
 * missing extension or a challenge-less ingress (Mode C) is accepted.
 */
static int
nonce_binding_valid(json_t *claims,
                    const struct auth_provider_config *config,
                    const char *server_nonce)
{
    json_t *extensions = json_object_get(claims, "extensions");
    json_t *claim = extensions == NULL ? NULL :
                    json_object_get(extensions, BAF_NONCE_EXTENSION_KEY);
    const char *claim_value = NULL;

    if (claim != NULL)
    {
        claim_value = json_string_value(claim);
        if (claim_value == NULL || claim_value[0] == '\0' ||
                strlen(claim_value) > BAF_MAX_SERVER_NONCE_BYTES)
        {
            return 0;
        }
    }
    if (server_nonce != NULL &&
            (server_nonce[0] == '\0' ||
             strlen(server_nonce) > BAF_MAX_SERVER_NONCE_BYTES))
    {
        return 0;
    }
    if (config->require_nonce_binding)
    {
        return claim_value != NULL && server_nonce != NULL &&
               strcmp(claim_value, server_nonce) == 0;
    }
    if (claim_value != NULL && server_nonce != NULL)
    {
        return strcmp(claim_value, server_nonce) == 0;
    }
    return 1;
}

static int
comma_list_contains(const char *list, const char *algorithm)
{
    const char *p = list;
    size_t length = strlen(algorithm);
    while (p != NULL && *p != '\0')
    {
        const char *end = strchr(p, ',');
        size_t item_length = end == NULL ? strlen(p) : (size_t)(end - p);
        if (item_length == length && memcmp(p, algorithm, length) == 0)
        {
            return 1;
        }
        p = end == NULL ? NULL : end + 1;
    }
    return 0;
}

static int
load_trust_file(const char *path, unsigned char **data, size_t *length)
{
    FILE *stream;
    long size;
    unsigned char *buffer;
    if (!nonempty(path) || (stream = fopen(path, "rb")) == NULL)
    {
        return 0;
    }
    if (fseek(stream, 0, SEEK_END) != 0 ||
            (size = ftell(stream)) <= 0 ||
            size > BAF_MAX_TRUST_FILE_BYTES ||
            fseek(stream, 0, SEEK_SET) != 0)
    {
        fclose(stream);
        return 0;
    }
    buffer = malloc((size_t)size + 1);
    if (buffer == NULL ||
            fread(buffer, 1, (size_t)size, stream) != (size_t)size)
    {
        free(buffer);
        fclose(stream);
        return 0;
    }
    fclose(stream);
    buffer[size] = '\0';
    *data = buffer;
    *length = (size_t)size;
    return 1;
}

enum auth_provider_status
baf_validator_config_create(const struct baf_validator_options *options,
                            struct auth_provider_config **output)
{
    struct auth_provider_config *config;
    size_t max_size;
    int64_t lifetime;
    int64_t skew;

    if (output == NULL)
    {
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    *output = NULL;
    if (options == NULL)
    {
        return AUTH_PROVIDER_CONFIG_ERROR;
    }
    max_size = options->max_assertion_bytes == 0 ?
               BAF_DEFAULT_MAX_ASSERTION_BYTES :
               options->max_assertion_bytes;
    lifetime = options->max_lifetime_seconds == 0 ?
               BAF_DEFAULT_MAX_LIFETIME_SECONDS :
               options->max_lifetime_seconds;
    skew = options->clock_skew_seconds < 0 ?
           BAF_DEFAULT_CLOCK_SKEW_SECONDS : options->clock_skew_seconds;
    if (!nonempty(options->issuer) || strchr(options->issuer, ':') == NULL ||
            !nonempty(options->expected_audience) ||
            !nonempty(options->local_target) ||
            !nonempty(options->key_id) ||
            !nonempty(options->allowed_algorithms) ||
            strcmp(options->allowed_algorithms, "RS256") != 0 ||
            max_size < 1024 || max_size > 65536 ||
            lifetime < 30 || lifetime > 900 ||
            skew < 0 || skew > BAF_MAX_CLOCK_SKEW_SECONDS ||
            (options->require_service_replay &&
             !replay_cache_is_service(options->replay_cache)))
    {
        return AUTH_PROVIDER_CONFIG_ERROR;
    }
    config = calloc(1, sizeof(*config));
    if (config == NULL)
    {
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    config->enabled = options->enabled;
    config->issuer = copy_string(options->issuer);
    config->audience = copy_string(options->expected_audience);
    config->target = copy_string(options->local_target);
    config->key_id = copy_string(options->key_id);
    config->required_assurance = copy_string(options->required_assurance);
    config->required_role = copy_string(options->required_role);
    config->allowed_device_status =
        copy_string(options->allowed_device_status);
    config->max_assertion_bytes = max_size;
    config->max_lifetime = lifetime;
    config->clock_skew = skew;
    config->replay_cache = options->replay_cache;
    config->require_nonce_binding = options->require_nonce_binding;
    if (options->trust_pem != NULL && options->trust_pem_length > 0)
    {
        config->trust_pem = malloc(options->trust_pem_length + 1);
        if (config->trust_pem != NULL)
        {
            memcpy(config->trust_pem, options->trust_pem,
                   options->trust_pem_length);
            config->trust_pem[options->trust_pem_length] = '\0';
            config->trust_pem_length = options->trust_pem_length;
        }
    }
    else
    {
        load_trust_file(options->trust_file, &config->trust_pem,
                        &config->trust_pem_length);
    }
    if (config->issuer == NULL || config->audience == NULL ||
            config->target == NULL || config->key_id == NULL ||
            config->trust_pem == NULL)
    {
        baf_validator_config_free(config);
        return AUTH_PROVIDER_CONFIG_ERROR;
    }
    *output = config;
    return AUTH_PROVIDER_SUCCESS;
}

void
baf_validator_config_free(struct auth_provider_config *config)
{
    if (config != NULL)
    {
        free(config->issuer);
        free(config->audience);
        free(config->target);
        free(config->key_id);
        if (config->trust_pem != NULL)
        {
            OPENSSL_cleanse(config->trust_pem, config->trust_pem_length);
        }
        free(config->trust_pem);
        free(config->required_assurance);
        free(config->required_role);
        free(config->allowed_device_status);
        free(config);
    }
}

static int
strict_base64url_decode(const unsigned char *input, size_t input_length,
                        unsigned char **output, size_t *output_length)
{
    size_t i;
    size_t padded_length;
    int decoded_length;
    unsigned char *padded;
    unsigned char *decoded;
    if (input_length == 0 || input_length % 4 == 1)
    {
        return 0;
    }
    padded_length = (input_length + 3) & ~(size_t)3;
    padded = malloc(padded_length + 1);
    decoded = malloc((padded_length / 4) * 3 + 1);
    if (padded == NULL || decoded == NULL)
    {
        free(padded);
        free(decoded);
        return 0;
    }
    for (i = 0; i < input_length; ++i)
    {
        unsigned char c = input[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_'))
        {
            free(padded);
            free(decoded);
            return 0;
        }
        padded[i] = c == '-' ? '+' : (c == '_' ? '/' : c);
    }
    while (i < padded_length)
    {
        padded[i++] = '=';
    }
    padded[padded_length] = '\0';
    decoded_length = EVP_DecodeBlock(decoded, padded, (int)padded_length);
    free(padded);
    if (decoded_length < 0)
    {
        free(decoded);
        return 0;
    }
    decoded_length -= (int)(padded_length - input_length);
    decoded[decoded_length] = '\0';
    *output = decoded;
    *output_length = (size_t)decoded_length;
    return 1;
}

static int
parse_compact(const unsigned char *assertion, size_t length,
              char **token, json_t **header, json_t **claims)
{
    const unsigned char *first;
    const unsigned char *second;
    unsigned char *header_data = NULL;
    unsigned char *claims_data = NULL;
    unsigned char *signature_data = NULL;
    size_t header_length;
    size_t claims_length;
    size_t signature_length;
    json_error_t error;
    int ok = 0;

    if (assertion == NULL || length == 0 ||
            memchr(assertion, '\0', length) != NULL)
    {
        return 0;
    }
    first = memchr(assertion, '.', length);
    if (first == NULL)
    {
        return 0;
    }
    second = memchr(first + 1, '.', length - (size_t)(first + 1 - assertion));
    if (second == NULL ||
            memchr(second + 1, '.', length - (size_t)(second + 1 - assertion))
            != NULL)
    {
        return 0;
    }
    if (!strict_base64url_decode(assertion, (size_t)(first - assertion),
                                 &header_data, &header_length) ||
            !strict_base64url_decode(first + 1, (size_t)(second - first - 1),
                                     &claims_data, &claims_length) ||
            !strict_base64url_decode(second + 1,
                                     length - (size_t)(second + 1 - assertion),
                                     &signature_data, &signature_length))
    {
        goto cleanup;
    }
    *header = json_loadb((const char *)header_data, header_length,
                         JSON_REJECT_DUPLICATES, &error);
    *claims = json_loadb((const char *)claims_data, claims_length,
                         JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(*header) || !json_is_object(*claims))
    {
        goto cleanup;
    }
    *token = malloc(length + 1);
    if (*token == NULL)
    {
        goto cleanup;
    }
    memcpy(*token, assertion, length);
    (*token)[length] = '\0';
    ok = 1;
cleanup:
    free(header_data);
    free(claims_data);
    free(signature_data);
    if (!ok)
    {
        json_decref(*header);
        json_decref(*claims);
        *header = NULL;
        *claims = NULL;
    }
    return ok;
}

static const char *
required_string(json_t *object, const char *name, size_t max_length)
{
    json_t *value = json_object_get(object, name);
    const char *string;
    if (!json_is_string(value) || (string = json_string_value(value)) == NULL ||
            string[0] == '\0' || strlen(string) > max_length)
    {
        return NULL;
    }
    return string;
}

static int
unique_string_array(json_t *array, size_t minimum, size_t maximum)
{
    size_t i;
    size_t j;
    if (!json_is_array(array) || json_array_size(array) < minimum ||
            json_array_size(array) > maximum)
    {
        return 0;
    }
    for (i = 0; i < json_array_size(array); ++i)
    {
        const char *left = json_string_value(json_array_get(array, i));
        if (left == NULL || left[0] == '\0' || strlen(left) > 255)
        {
            return 0;
        }
        for (j = 0; j < i; ++j)
        {
            if (strcmp(left,
                       json_string_value(json_array_get(array, j))) == 0)
            {
                return 0;
            }
        }
    }
    return 1;
}

static int
array_contains(json_t *array, const char *wanted)
{
    size_t i;
    if (json_is_string(array))
    {
        return strcmp(json_string_value(array), wanted) == 0;
    }
    if (!unique_string_array(array, 1, 256))
    {
        return 0;
    }
    for (i = 0; i < json_array_size(array); ++i)
    {
        if (strcmp(json_string_value(json_array_get(array, i)), wanted) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int
header_valid(json_t *header, const struct auth_provider_config *config)
{
    const char *alg = required_string(header, "alg", 16);
    const char *kid = required_string(header, "kid", 255);
    const char *typ = required_string(header, "typ", 32);
    json_t *crit = json_object_get(header, "crit");
    if (alg == NULL || kid == NULL || typ == NULL ||
            strcmp(typ, "baf+jwt") != 0 ||
            strcmp(alg, "RS256") != 0 ||
            strcmp(kid, config->key_id) != 0 ||
            json_object_get(header, "jku") != NULL ||
            json_object_get(header, "x5u") != NULL ||
            json_object_get(header, "jwk") != NULL)
    {
        return 0;
    }
    return crit == NULL || (json_is_array(crit) && json_array_size(crit) == 0);
}

static int
key_is_strong_rsa(const struct auth_provider_config *config)
{
    BIO *bio = BIO_new_mem_buf(config->trust_pem,
                               (int)config->trust_pem_length);
    EVP_PKEY *key = bio == NULL ? NULL :
                    PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    int valid = key != NULL && EVP_PKEY_is_a(key, "RSA") &&
                EVP_PKEY_get_bits(key) >= 2048;
    EVP_PKEY_free(key);
    BIO_free(bio);
    return valid;
}

static int
schema_valid(json_t *claims)
{
    static const char *allowed[] = {
        "iss", "aud", "sub", "preferred_username", "groups", "roles",
        "auth_method", "assurance_level", "broker_session_id", "target",
        "iat", "nbf", "exp", "jti", "device_trust", "extensions"
    };
    const char *key;
    json_t *value;
    size_t i;
    json_t *device = json_object_get(claims, "device_trust");
    json_t *extensions = json_object_get(claims, "extensions");
    json_t *status;
    static const char *device_allowed[] = {
        "status", "device_id", "provider", "evaluated_at", "evidence"
    };
    json_object_foreach(claims, key, value)
    {
        for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
        {
            if (strcmp(key, allowed[i]) == 0)
            {
                break;
            }
        }
        if (i == sizeof(allowed) / sizeof(allowed[0]))
        {
            return 0;
        }
    }
    if (required_string(claims, "iss", 2048) == NULL ||
            json_object_get(claims, "aud") == NULL ||
            required_string(claims, "sub", 255) == NULL ||
            required_string(claims, "preferred_username", 255) == NULL ||
            !unique_string_array(json_object_get(claims, "groups"), 0, 256) ||
            !unique_string_array(json_object_get(claims, "roles"), 0, 256) ||
            !unique_string_array(json_object_get(claims, "auth_method"), 1, 16) ||
            required_string(claims, "assurance_level", 255) == NULL ||
            required_string(claims, "broker_session_id", 255) == NULL ||
            required_string(claims, "target", 255) == NULL ||
            required_string(claims, "jti", 255) == NULL ||
            strlen(json_string_value(json_object_get(claims, "jti"))) < 16 ||
            !json_is_integer(json_object_get(claims, "iat")) ||
            !json_is_integer(json_object_get(claims, "nbf")) ||
            !json_is_integer(json_object_get(claims, "exp")) ||
            !json_is_object(device) ||
            (status = json_object_get(device, "status")) == NULL ||
            !json_is_string(status))
    {
        return 0;
    }
    json_array_foreach(json_object_get(claims, "auth_method"), i, value)
    {
        if (strlen(json_string_value(value)) > 64)
        {
            return 0;
        }
    }
    json_object_foreach(device, key, value)
    {
        for (i = 0; i < sizeof(device_allowed) / sizeof(device_allowed[0]); ++i)
        {
            if (strcmp(key, device_allowed[i]) == 0)
            {
                break;
            }
        }
        if (i == sizeof(device_allowed) / sizeof(device_allowed[0]))
        {
            return 0;
        }
    }
    if ((json_object_get(device, "device_id") != NULL &&
            required_string(device, "device_id", 255) == NULL) ||
            (json_object_get(device, "provider") != NULL &&
             required_string(device, "provider", 255) == NULL) ||
            (json_object_get(device, "evaluated_at") != NULL &&
             (!json_is_integer(json_object_get(device, "evaluated_at")) ||
              json_integer_value(json_object_get(device, "evaluated_at")) < 0)) ||
            (json_object_get(device, "evidence") != NULL &&
             !json_is_object(json_object_get(device, "evidence"))))
    {
        return 0;
    }
    key = json_string_value(json_object_get(claims, "preferred_username"));
    for (i = 0; key[i] != '\0'; ++i)
    {
        if ((unsigned char)key[i] < 0x20 || (unsigned char)key[i] == 0x7f)
        {
            return 0;
        }
    }
    if (extensions != NULL)
    {
        if (!json_is_object(extensions))
        {
            return 0;
        }
        json_object_foreach(extensions, key, value)
        {
            if (key[0] == ':' || strchr(key, ':') == NULL)
            {
                return 0;
            }
        }
    }
    if (strchr(json_string_value(json_object_get(claims, "iss")), ':') == NULL)
    {
        return 0;
    }
    key = json_string_value(status);
    return strcmp(key, "trusted") == 0 || strcmp(key, "untrusted") == 0 ||
           strcmp(key, "unknown") == 0;
}

static enum auth_provider_status
provider_validate(const struct auth_provider_request *request,
             struct auth_provider_result **output)
{
    const struct auth_provider_config *config;
    json_t *header = NULL;
    json_t *claims = NULL;
    json_t *device;
    char *token = NULL;
    jwt_t *jwt = NULL;
    const char *issuer;
    const char *subject;
    const char *username;
    const char *session_id;
    const char *jti;
    const char *assurance;
    const char *device_status;
    int64_t iat;
    int64_t nbf;
    int64_t exp;
    int64_t now;
    unsigned char replay_key[REPLAY_CACHE_KEY_SIZE];
    enum replay_cache_status replay_status;
    struct auth_provider_result *result = NULL;
    enum auth_provider_status status = AUTH_PROVIDER_INVALID;

    *output = NULL;
    if (request == NULL || (config = request->config) == NULL)
    {
        return AUTH_PROVIDER_CONFIG_ERROR;
    }
    if (!config->enabled)
    {
        return AUTH_PROVIDER_UNSUPPORTED;
    }
    if (request->assertion_length > config->max_assertion_bytes ||
            request->assertion_length == 0)
    {
        return AUTH_PROVIDER_INVALID;
    }
    if ((request->expected_audience != NULL &&
            strcmp(request->expected_audience, config->audience) != 0) ||
            (request->local_target != NULL &&
             strcmp(request->local_target, config->target) != 0))
    {
        return AUTH_PROVIDER_CONFIG_ERROR;
    }
    if (!parse_compact(request->assertion, request->assertion_length,
                       &token, &header, &claims) ||
            !header_valid(header, config) || !key_is_strong_rsa(config))
    {
        goto cleanup;
    }
    if (jwt_decode(&jwt, token, config->trust_pem,
                   (int)config->trust_pem_length) != 0 ||
            jwt_get_alg(jwt) != JWT_ALG_RS256 || !schema_valid(claims))
    {
        goto cleanup;
    }
    issuer = required_string(claims, "iss", 2048);
    subject = required_string(claims, "sub", 255);
    username = required_string(claims, "preferred_username", 255);
    session_id = required_string(claims, "broker_session_id", 255);
    jti = required_string(claims, "jti", 255);
    assurance = required_string(claims, "assurance_level", 255);
    device = json_object_get(claims, "device_trust");
    device_status = json_string_value(json_object_get(device, "status"));
    iat = json_integer_value(json_object_get(claims, "iat"));
    nbf = json_integer_value(json_object_get(claims, "nbf"));
    exp = json_integer_value(json_object_get(claims, "exp"));
    now = request->now == NULL ? (int64_t)time(NULL) :
          request->now(request->now_userdata);
    if (now > INT64_MAX - config->clock_skew ||
            now < INT64_MIN + config->clock_skew ||
            exp > INT64_MAX - config->clock_skew ||
            strcmp(issuer, config->issuer) != 0 ||
            !array_contains(json_object_get(claims, "aud"),
                            config->audience) ||
            strcmp(required_string(claims, "target", 255),
                   config->target) != 0 ||
            iat < 0 || iat > nbf || nbf >= exp ||
            exp - iat > config->max_lifetime ||
            iat > now + config->clock_skew ||
            now + config->clock_skew < nbf ||
            now - config->clock_skew >= exp ||
            (nonempty(config->required_assurance) &&
             strcmp(assurance, config->required_assurance) != 0) ||
            (nonempty(config->required_role) &&
             !array_contains(json_object_get(claims, "roles"),
                             config->required_role)) ||
            (nonempty(config->allowed_device_status) &&
             !comma_list_contains(config->allowed_device_status, device_status)))
    {
        goto cleanup;
    }
    if (!nonce_binding_valid(claims, config, request->server_nonce))
    {
        goto cleanup;
    }
    if (replay_cache_make_key(issuer, jti, replay_key) != REPLAY_CACHE_OK)
    {
        status = AUTH_PROVIDER_INTERNAL_ERROR;
        goto cleanup;
    }
    replay_status = replay_cache_reserve(config->replay_cache, replay_key,
                                         exp + config->clock_skew, now);
    if (replay_status == REPLAY_CACHE_EXISTS)
    {
        status = AUTH_PROVIDER_REPLAY;
        goto cleanup;
    }
    if (replay_status == REPLAY_CACHE_UNAVAILABLE ||
            replay_status == REPLAY_CACHE_FULL)
    {
        status = AUTH_PROVIDER_DEPENDENCY_UNAVAILABLE;
        goto cleanup;
    }
    if (replay_status != REPLAY_CACHE_OK)
    {
        status = AUTH_PROVIDER_INTERNAL_ERROR;
        goto cleanup;
    }
    result = calloc(1, sizeof(*result));
    if (result == NULL)
    {
        status = AUTH_PROVIDER_INTERNAL_ERROR;
        goto cleanup;
    }
    result->identity.issuer = copy_string(issuer);
    result->identity.subject = copy_string(subject);
    result->identity.preferred_username = copy_string(username);
    result->identity.broker_session_id = copy_string(session_id);
    result->identity.client_address =
        copy_string(request->client_address == NULL ? "" :
                    request->client_address);
    result->identity.assurance_level = copy_string(assurance);
    result->identity.device_trust_status = copy_string(device_status);
    if (!copy_string_array(json_object_get(claims, "groups"),
                           &result->identity.groups,
                           &result->identity.group_count) ||
            !copy_string_array(json_object_get(claims, "roles"),
                               &result->identity.roles,
                               &result->identity.role_count) ||
            !copy_string_array(json_object_get(claims, "auth_method"),
                               &result->identity.auth_methods,
                               &result->identity.auth_method_count))
    {
        auth_provider_result_free(result);
        result = NULL;
        status = AUTH_PROVIDER_INTERNAL_ERROR;
        goto cleanup;
    }
    memcpy(result->identity.jti_digest, replay_key, sizeof(replay_key));
    result->identity.expiry = exp;
    if (result->identity.issuer == NULL || result->identity.subject == NULL ||
            result->identity.preferred_username == NULL ||
            result->identity.broker_session_id == NULL ||
            result->identity.client_address == NULL ||
            result->identity.assurance_level == NULL ||
            result->identity.device_trust_status == NULL)
    {
        auth_provider_result_free(result);
        result = NULL;
        status = AUTH_PROVIDER_INTERNAL_ERROR;
        goto cleanup;
    }
    *output = result;
    status = AUTH_PROVIDER_SUCCESS;
cleanup:
    jwt_free(jwt);
    json_decref(header);
    json_decref(claims);
    if (token != NULL)
    {
        OPENSSL_cleanse(token, request->assertion_length);
        free(token);
    }
    return status;
}

const struct auth_provider *
auth_provider_jwt_get(void)
{
    static const struct auth_provider_ops ops = { provider_validate };
    static const struct auth_provider provider = { "jwt", &ops };
    return &provider;
}

#if defined(BAF_FUZZING)
int
auth_provider_jwt_fuzz_compact(const unsigned char *data, size_t size)
{
    char *token = NULL;
    json_t *header = NULL;
    json_t *claims = NULL;
    int parsed = parse_compact(data, size, &token, &header, &claims);
    if (token != NULL)
    {
        OPENSSL_cleanse(token, size);
    }
    free(token);
    json_decref(header);
    json_decref(claims);
    return parsed;
}
#endif
