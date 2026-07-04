#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "auth_provider_broker.h"

#include <stddef.h>

#if !defined(ENABLE_BROKER_AUTH)
#error "broker provider built without ENABLE_BROKER_AUTH"
#endif

static int
broker_is_available(void)
{
    return 0;
}

static struct auth_provider_context *
broker_validate_assertion(const struct auth_provider_request *request,
                          enum scp_login_status *status)
{
    (void)request;
    if (status != NULL)
    {
        *status = E_SCP_LOGIN_GENERAL_ERROR;
    }
    return NULL;
}

static int
broker_is_locally_validated(const struct auth_provider_context *context)
{
    (void)context;
    return 0;
}

static const char *
broker_get_username(const struct auth_provider_context *context)
{
    (void)context;
    return NULL;
}

static const char *
broker_get_client_ip(const struct auth_provider_context *context)
{
    (void)context;
    return NULL;
}

static void
broker_context_free(struct auth_provider_context *context)
{
    (void)context;
}

const struct auth_provider *
auth_provider_broker_get(void)
{
    static const struct auth_provider provider =
    {
        "broker",
        broker_is_available,
        broker_validate_assertion,
        broker_is_locally_validated,
        broker_get_username,
        broker_get_client_ip,
        broker_context_free
    };
    return &provider;
}
