#ifndef AUTH_PROVIDER_JWT_PRIVATE_H
#define AUTH_PROVIDER_JWT_PRIVATE_H

#include "auth_provider_jwt.h"

struct auth_provider_config
{
    int enabled;
    char *issuer;
    char *audience;
    char *target;
    char *key_id;
    unsigned char *trust_pem;
    size_t trust_pem_length;
    size_t max_assertion_bytes;
    int64_t max_lifetime;
    int64_t clock_skew;
    char *required_assurance;
    char *required_role;
    char *allowed_device_status;
    struct replay_cache *replay_cache;
};

#endif
