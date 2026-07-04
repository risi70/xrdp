/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) 2026 xrdp contributors
 * Licensed under the Apache License, Version 2.0.
 */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "auth_provider.h"
#include "auth_provider_private.h"

#include <stddef.h>

#if !defined(ENABLE_BROKER_AUTH)
#error "auth_provider.c must only be built with broker auth enabled"
#endif

enum auth_provider_status
auth_provider_validate(const struct auth_provider *provider,
                       const struct auth_provider_request *request,
                       struct auth_provider_result **result)
{
    enum auth_provider_status status;

    if (result == NULL)
    {
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    *result = NULL;

    if (provider == NULL || provider->ops == NULL ||
            provider->ops->validate == NULL || request == NULL)
    {
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }

    status = provider->ops->validate(request, result);
    if ((status == AUTH_PROVIDER_SUCCESS && *result == NULL) ||
            (status != AUTH_PROVIDER_SUCCESS && *result != NULL))
    {
        auth_provider_result_free(*result);
        *result = NULL;
        status = AUTH_PROVIDER_INTERNAL_ERROR;
    }

    return status;
}

const struct auth_prevalidated_identity *
auth_provider_result_get_identity(const struct auth_provider_result *result)
{
    (void)result;
    return NULL;
}

void
auth_provider_result_free(struct auth_provider_result *result)
{
    /* No Phase 1 provider can allocate this opaque type. */
    (void)result;
}

const char *
auth_provider_status_to_string(enum auth_provider_status status)
{
    switch (status)
    {
        case AUTH_PROVIDER_SUCCESS:
            return "success";
        case AUTH_PROVIDER_UNSUPPORTED:
            return "unsupported";
        case AUTH_PROVIDER_INVALID:
            return "invalid";
        case AUTH_PROVIDER_CONFIG_ERROR:
            return "configuration-error";
        case AUTH_PROVIDER_INTERNAL_ERROR:
            return "internal-error";
        default:
            return "unknown";
    }
}
