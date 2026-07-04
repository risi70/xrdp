#ifndef AUTH_PROVIDER_JWT_H
#define AUTH_PROVIDER_JWT_H

#include "auth_provider.h"

struct replay_cache;

#define BAF_DEFAULT_MAX_ASSERTION_BYTES 16384
#define BAF_DEFAULT_MAX_LIFETIME_SECONDS 300
#define BAF_DEFAULT_CLOCK_SKEW_SECONDS 30
#define BAF_MAX_CLOCK_SKEW_SECONDS 120

struct baf_validator_options
{
    int enabled;
    const char *issuer;
    const char *expected_audience;
    const char *local_target;
    const char *allowed_algorithms;
    size_t max_assertion_bytes;
    int64_t max_lifetime_seconds;
    int64_t clock_skew_seconds;
    const char *key_id;
    const char *trust_file;
    const unsigned char *trust_pem;
    size_t trust_pem_length;
    const char *required_assurance;
    const char *required_role;
    const char *allowed_device_status;
    struct replay_cache *replay_cache;
};

enum auth_provider_status baf_validator_config_create(
    const struct baf_validator_options *options,
    struct auth_provider_config **config);
void baf_validator_config_free(struct auth_provider_config *config);
const struct auth_provider *auth_provider_jwt_get(void);

#if defined(BAF_FUZZING)
int auth_provider_jwt_fuzz_compact(const unsigned char *data, size_t size);
#endif

#endif
