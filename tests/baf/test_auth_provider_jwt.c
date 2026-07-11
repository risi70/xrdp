#include "auth_provider.h"
#include "auth_provider_jwt.h"
#include "replay_cache.h"

#include <assert.h>
#include <jwt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOW 1700000000L
#define ISSUER "https://issuer.example.test"
#define AUDIENCE "urn:baf:xrdp:test"
#define TARGET "urn:baf:desktop:test"
#define KID "test-rsa-1"

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

static char *
make_token(const unsigned char *key, size_t key_length, jwt_alg_t algorithm,
           const char *headers, const char *claims)
{
    jwt_t *jwt = NULL;
    char *token;
    assert(jwt_new(&jwt) == 0);
    assert(jwt_add_grants_json(jwt, claims) == 0);
    assert(jwt_add_headers_json(jwt, headers) == 0);
    assert(jwt_set_alg(jwt, algorithm, key, (int)key_length) == 0);
    token = jwt_encode_str(jwt);
    assert(token != NULL);
    jwt_free(jwt);
    return token;
}

static int64_t
fixed_now(void *userdata)
{
    (void)userdata;
    return NOW;
}

static enum auth_provider_status
validate(const char *token, struct auth_provider_config *config,
         struct auth_provider_result **result)
{
    struct auth_provider_request request;
    memset(&request, 0, sizeof(request));
    request.assertion = (const unsigned char *)token;
    request.assertion_length = strlen(token);
    request.client_address = "192.0.2.10";
    request.config = config;
    request.expected_audience = AUDIENCE;
    request.local_target = TARGET;
    request.now = fixed_now;
    return auth_provider_validate(auth_provider_jwt_get(), &request, result);
}

static enum auth_provider_status
validate_nonce(const char *token, struct auth_provider_config *config,
               const char *server_nonce, struct auth_provider_result **result)
{
    struct auth_provider_request request;
    memset(&request, 0, sizeof(request));
    request.assertion = (const unsigned char *)token;
    request.assertion_length = strlen(token);
    request.client_address = "192.0.2.10";
    request.config = config;
    request.expected_audience = AUDIENCE;
    request.local_target = TARGET;
    request.server_nonce = server_nonce;
    request.now = fixed_now;
    return auth_provider_validate(auth_provider_jwt_get(), &request, result);
}

#define NONCE_CLAIMS(jti, ext) \
    "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\"," \
    "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[]," \
    "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\"," \
    "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\"," \
    "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000100," \
    "\"jti\":\"" jti "\",\"device_trust\":{\"status\":\"unknown\"}" ext "}"

int
main(void)
{
    const char *valid_claims =
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\","
        "\"sub\":\"subject-1\",\"preferred_username\":\"alice\","
        "\"groups\":[\"engineering\"],\"roles\":[\"desktop-user\"],"
        "\"auth_method\":[\"pwd\",\"otp\"],"
        "\"assurance_level\":\"urn:test:aal2\","
        "\"broker_session_id\":\"session-1\",\"target\":\"" TARGET "\","
        "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000100,"
        "\"jti\":\"0123456789abcdef\",\"device_trust\":{\"status\":\"trusted\"}}";
    const char *headers =
        "{\"alg\":\"RS256\",\"kid\":\"" KID "\",\"typ\":\"baf+jwt\"}";
    unsigned char *private_key;
    unsigned char *public_key;
    size_t private_length;
    size_t public_length;
    struct replay_cache *cache;
    struct baf_validator_options options;
    struct auth_provider_config *config = NULL;
    struct auth_provider_config *unavailable_config = NULL;
    struct auth_provider_config *rejected_config = NULL;
    struct auth_provider_result *result = NULL;
    const struct auth_prevalidated_identity *identity;
    char *token;
    char *bad;

    private_key = read_file(TEST_PRIVATE_KEY, &private_length);
    public_key = read_file(TEST_PUBLIC_KEY, &public_length);
    cache = replay_cache_memory_create(32);
    assert(cache != NULL);
    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = ISSUER;
    options.expected_audience = AUDIENCE;
    options.local_target = TARGET;
    options.allowed_algorithms = "RS256";
    options.max_assertion_bytes = 16384;
    options.max_lifetime_seconds = 300;
    options.clock_skew_seconds = 30;
    options.key_id = KID;
    options.trust_pem = public_key;
    options.trust_pem_length = public_length;
    options.replay_cache = cache;
    options.allowed_algorithms = "PS256";
    assert(baf_validator_config_create(&options, &rejected_config) ==
           AUTH_PROVIDER_CONFIG_ERROR);
    assert(rejected_config == NULL);
    options.allowed_algorithms = "ES256";
    assert(baf_validator_config_create(&options, &rejected_config) ==
           AUTH_PROVIDER_CONFIG_ERROR);
    options.allowed_algorithms = "RS256,PS256";
    assert(baf_validator_config_create(&options, &rejected_config) ==
           AUTH_PROVIDER_CONFIG_ERROR);
    options.allowed_algorithms = "HS256";
    assert(baf_validator_config_create(&options, &rejected_config) ==
           AUTH_PROVIDER_CONFIG_ERROR);
    options.allowed_algorithms = "RS256";
    options.require_service_replay = 1;
    assert(baf_validator_config_create(&options, &rejected_config) ==
           AUTH_PROVIDER_CONFIG_ERROR);
    assert(rejected_config == NULL);
    options.require_service_replay = 0;
    assert(baf_validator_config_create(&options, &config) ==
           AUTH_PROVIDER_SUCCESS);

    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       headers, valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_SUCCESS);
    identity = auth_provider_result_get_identity(result);
    assert(identity != NULL);
    assert(strcmp(auth_prevalidated_identity_get_issuer(identity), ISSUER) == 0);
    assert(strcmp(auth_prevalidated_identity_get_preferred_username(identity),
                  "alice") == 0);
    assert(auth_prevalidated_identity_get_expiry(identity) == 1700000100);
    auth_provider_result_free(result);
    result = NULL;
    assert(validate(token, config, &result) == AUTH_PROVIDER_REPLAY);
    assert(result == NULL);

    bad = strdup(token);
    assert(bad != NULL);
    {
        char *signature = strrchr(bad, '.');
        assert(signature != NULL && signature[1] != '\0');
        signature[1] = signature[1] == 'A' ? 'B' : 'A';
    }
    assert(validate(bad, config, &result) == AUTH_PROVIDER_INVALID);
    free(bad);
    free(token);

    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       headers,
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\","
        "\"sub\":\"s\",\"preferred_username\":\"alice\","
        "\"groups\":[],\"roles\":[],\"auth_method\":[\"pwd\"],"
        "\"assurance_level\":\"aal\",\"broker_session_id\":\"s\","
        "\"target\":\"" TARGET "\",\"iat\":1700000000,"
        "\"nbf\":1700000030,\"exp\":1700000100,"
        "\"jti\":\"skewboundary0001\","
        "\"device_trust\":{\"status\":\"unknown\"}}");
    assert(validate(token, config, &result) == AUTH_PROVIDER_SUCCESS);
    auth_provider_result_free(result);
    result = NULL;
    free(token);

#define REJECT_CLAIMS(json) do { \
    token = make_token(private_key, private_length, JWT_ALG_RS256, \
                       headers, (json)); \
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID); \
    free(token); \
} while (0)

    REJECT_CLAIMS(
        "{\"iss\":\"wrong\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\","
        "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000100,"
        "\"jti\":\"wrongissuer00001\",\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"wrong\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\","
        "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000100,"
        "\"jti\":\"wrongaudience001\",\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"wrong\","
        "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000100,"
        "\"jti\":\"wrongtarget000001\",\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"groups\":[],\"roles\":[],\"auth_method\":[\"pwd\"],"
        "\"assurance_level\":\"aal\",\"broker_session_id\":\"s\","
        "\"target\":\"" TARGET "\",\"iat\":1700000000,\"nbf\":1700000000,"
        "\"exp\":1700000100,\"jti\":\"missingusername1\","
        "\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\","
        "\"iat\":1699999000,\"nbf\":1699999000,\"exp\":1699999900,"
        "\"jti\":\"expiredtoken0001\",\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\","
        "\"iat\":1700000100,\"nbf\":1700000100,\"exp\":1700000200,"
        "\"jti\":\"futuretoken00001\",\"device_trust\":{\"status\":\"unknown\"}}");
    REJECT_CLAIMS(
        "{\"iss\":\"" ISSUER "\",\"aud\":\"" AUDIENCE "\",\"sub\":\"s\","
        "\"preferred_username\":\"alice\",\"groups\":[],\"roles\":[],"
        "\"auth_method\":[\"pwd\"],\"assurance_level\":\"aal\","
        "\"broker_session_id\":\"s\",\"target\":\"" TARGET "\","
        "\"iat\":1700000000,\"nbf\":1700000000,\"exp\":1700000400,"
        "\"jti\":\"longlifetime0001\",\"device_trust\":{\"status\":\"unknown\"}}");

    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       "{\"alg\":\"RS256\",\"kid\":\"unknown\",\"typ\":\"baf+jwt\"}",
                       valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       "{\"alg\":\"RS256\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\",\"crit\":[\"unknown\"]}",
                       valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       "{\"alg\":\"RS256\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\",\"jku\":\"https://attacker.invalid\"}",
                       valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(NULL, 0, JWT_ALG_NONE,
                       "{\"alg\":\"none\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\"}", valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token((const unsigned char *)"test-secret", 11,
                       JWT_ALG_HS256,
                       "{\"alg\":\"HS256\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\"}", valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       "{\"alg\":\"RS256\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\","
                       "\"x5u\":\"https://attacker.invalid\"}", valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       "{\"alg\":\"RS256\",\"kid\":\"" KID "\","
                       "\"typ\":\"baf+jwt\",\"jwk\":{\"kty\":\"RSA\"}}",
                       valid_claims);
    assert(validate(token, config, &result) == AUTH_PROVIDER_INVALID);
    free(token);
    assert(validate("a.b.c", config, &result) == AUTH_PROVIDER_INVALID);
    assert(validate("a=.b.c", config, &result) == AUTH_PROVIDER_INVALID);
    assert(validate("eyJhbGciOiJSUzI1NiIsImFsZyI6IlJTMjU2Iiwia2lkIjoidGVzdC1yc2EtMSIsInR5cCI6ImJhZitqd3QifQ.e30.AA",
                    config, &result) == AUTH_PROVIDER_INVALID);
    bad = malloc(16386);
    assert(bad != NULL);
    memset(bad, 'a', 16385);
    bad[16385] = '\0';
    assert(validate(bad, config, &result) == AUTH_PROVIDER_INVALID);
    free(bad);

    /* Nonce binding: optional mode with the default config. */
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("noncematch000001",
                                    ",\"extensions\":{\"urn:baf:ts_nonce\":"
                                    "\"nonce-abc\"}"));
    assert(validate_nonce(token, config, "nonce-abc", &result) ==
           AUTH_PROVIDER_SUCCESS);
    auth_provider_result_free(result);
    result = NULL;
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("noncemismatch001",
                                    ",\"extensions\":{\"urn:baf:ts_nonce\":"
                                    "\"nonce-abc\"}"));
    assert(validate_nonce(token, config, "nonce-xyz", &result) ==
           AUTH_PROVIDER_INVALID);
    free(token);
    /* Claim present but no ingress challenge (Mode C) is accepted when
     * binding is optional. */
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("noncemodec000001",
                                    ",\"extensions\":{\"urn:baf:ts_nonce\":"
                                    "\"nonce-abc\"}"));
    assert(validate_nonce(token, config, NULL, &result) ==
           AUTH_PROVIDER_SUCCESS);
    auth_provider_result_free(result);
    result = NULL;
    free(token);
    /* Challenge present but claim absent is accepted when optional. */
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("nonceabsent00001", ""));
    assert(validate_nonce(token, config, "nonce-abc", &result) ==
           AUTH_PROVIDER_SUCCESS);
    auth_provider_result_free(result);
    result = NULL;
    free(token);
    /* Empty or non-string nonce extensions always fail closed. */
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("nonceempty000001",
                                    ",\"extensions\":{\"urn:baf:ts_nonce\":"
                                    "\"\"}"));
    assert(validate_nonce(token, config, "nonce-abc", &result) ==
           AUTH_PROVIDER_INVALID);
    free(token);
    token = make_token(private_key, private_length, JWT_ALG_RS256, headers,
                       NONCE_CLAIMS("noncenotstring01",
                                    ",\"extensions\":{\"urn:baf:ts_nonce\":"
                                    "17}"));
    assert(validate_nonce(token, config, "nonce-abc", &result) ==
           AUTH_PROVIDER_INVALID);
    free(token);

    /* Nonce binding: required mode fails closed without a bound nonce. */
    {
        struct auth_provider_config *nonce_config = NULL;
        options.require_nonce_binding = 1;
        assert(baf_validator_config_create(&options, &nonce_config) ==
               AUTH_PROVIDER_SUCCESS);
        token = make_token(private_key, private_length, JWT_ALG_RS256,
                           headers,
                           NONCE_CLAIMS("noncereq00000001",
                                        ",\"extensions\":"
                                        "{\"urn:baf:ts_nonce\":"
                                        "\"nonce-abc\"}"));
        assert(validate_nonce(token, nonce_config, "nonce-abc", &result) ==
               AUTH_PROVIDER_SUCCESS);
        auth_provider_result_free(result);
        result = NULL;
        /* Required binding with no ingress challenge fails even when the
         * claim is present. */
        assert(validate_nonce(token, nonce_config, NULL, &result) ==
               AUTH_PROVIDER_INVALID);
        assert(validate_nonce(token, nonce_config, "nonce-xyz", &result) ==
               AUTH_PROVIDER_INVALID);
        free(token);
        token = make_token(private_key, private_length, JWT_ALG_RS256,
                           headers,
                           NONCE_CLAIMS("noncereqabsent01", ""));
        assert(validate_nonce(token, nonce_config, "nonce-abc", &result) ==
               AUTH_PROVIDER_INVALID);
        assert(validate_nonce(token, nonce_config, NULL, &result) ==
               AUTH_PROVIDER_INVALID);
        free(token);
        baf_validator_config_free(nonce_config);
        options.require_nonce_binding = 0;
    }

    options.replay_cache = NULL;
    assert(baf_validator_config_create(&options, &unavailable_config) ==
           AUTH_PROVIDER_SUCCESS);
    token = make_token(private_key, private_length, JWT_ALG_RS256,
                       headers, valid_claims);
    assert(validate(token, unavailable_config, &result) ==
           AUTH_PROVIDER_DEPENDENCY_UNAVAILABLE);
    free(token);
    baf_validator_config_free(unavailable_config);

    baf_validator_config_free(config);
    replay_cache_free(cache);
    free(private_key);
    free(public_key);
    return 0;
}
