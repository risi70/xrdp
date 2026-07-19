/** Internal provider declarations. Not a public provider ABI. */
#ifndef AUTH_PROVIDER_PRIVATE_H
#define AUTH_PROVIDER_PRIVATE_H

#include "auth_provider.h"

struct auth_provider_ops
{
    enum auth_provider_status (*validate)(
        const struct auth_provider_request *request,
        struct auth_provider_result **result);
};

struct auth_provider
{
    const char *name;
    const struct auth_provider_ops *ops;
};

struct auth_prevalidated_identity
{
    char *issuer;
    char *subject;
    char *preferred_username;
    char *broker_session_id;
    char *client_address;
    char *assurance_level;
    char *device_trust_status;
    char **groups;
    size_t group_count;
    char **roles;
    size_t role_count;
    char **auth_methods;
    size_t auth_method_count;
    unsigned char jti_digest[32];
    int64_t expiry;
};
struct auth_provider_result
{
    struct auth_prevalidated_identity identity;
};

#endif /* AUTH_PROVIDER_PRIVATE_H */
