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

#endif /* AUTH_PROVIDER_PRIVATE_H */
