/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) 2026 xrdp contributors
 * Licensed under the Apache License, Version 2.0.
 */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "auth_provider_null.h"
#include "auth_provider_private.h"

#include <stddef.h>

#if !defined(ENABLE_BROKER_AUTH)
#error "auth_provider_null.c must only be built with broker auth enabled"
#endif

static enum auth_provider_status
null_validate(const struct auth_provider_request *request,
              struct auth_provider_result **result)
{
    (void)request;
    if (result != NULL)
    {
        *result = NULL;
    }
    return AUTH_PROVIDER_UNSUPPORTED;
}

const struct auth_provider *
auth_provider_null_get(void)
{
    static const struct auth_provider_ops ops = { null_validate };
    static const struct auth_provider provider = { "null", &ops };
    return &provider;
}
