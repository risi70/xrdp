/** Authentication provider interface. */
#ifndef AUTH_PROVIDER_H
#define AUTH_PROVIDER_H

#include "scp_application_types.h"

struct auth_provider_request
{
    const char *assertion;
    const char *client_ip;
};

struct auth_provider_context;

/**
 * Providers validate assertions only. Local account and session lifecycle
 * remains owned by sesman_auth.h and the system authentication backend.
 */
struct auth_provider
{
    const char *name;
    int (*is_available)(void);
    struct auth_provider_context *(*validate_assertion)(
        const struct auth_provider_request *request,
        enum scp_login_status *status);
    int (*is_locally_validated)(const struct auth_provider_context *context);
    const char *(*get_username)(
        const struct auth_provider_context *context);
    const char *(*get_client_ip)(
        const struct auth_provider_context *context);
    void (*context_free)(struct auth_provider_context *context);
};

#endif /* AUTH_PROVIDER_H */
