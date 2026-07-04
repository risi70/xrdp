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
#include <stdlib.h>

#if !defined(ENABLE_BROKER_AUTH)
#error "auth_provider.c must only be built with broker auth enabled"
#endif

static void
free_strings(char **values, size_t count)
{
    size_t index;
    for (index = 0; index < count; ++index)
    {
        free(values[index]);
    }
    free(values);
}

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
    return result == NULL ? NULL : &result->identity;
}

void
auth_provider_result_free(struct auth_provider_result *result)
{
    if (result != NULL)
    {
        free(result->identity.issuer);
        free(result->identity.subject);
        free(result->identity.preferred_username);
        free(result->identity.broker_session_id);
        free(result->identity.client_address);
        free(result->identity.assurance_level);
        free(result->identity.device_trust_status);
        free_strings(result->identity.groups, result->identity.group_count);
        free_strings(result->identity.roles, result->identity.role_count);
        free_strings(result->identity.auth_methods,
                     result->identity.auth_method_count);
        free(result);
    }
}

#define STRING_ACCESSOR(function_name, member_name) \
const char *function_name(const struct auth_prevalidated_identity *identity) \
{ return identity == NULL ? NULL : identity->member_name; }

STRING_ACCESSOR(auth_prevalidated_identity_get_issuer, issuer)
STRING_ACCESSOR(auth_prevalidated_identity_get_subject, subject)
STRING_ACCESSOR(auth_prevalidated_identity_get_preferred_username, preferred_username)
STRING_ACCESSOR(auth_prevalidated_identity_get_broker_session_id, broker_session_id)
STRING_ACCESSOR(auth_prevalidated_identity_get_client_address, client_address)
STRING_ACCESSOR(auth_prevalidated_identity_get_assurance_level, assurance_level)
STRING_ACCESSOR(auth_prevalidated_identity_get_device_trust_status, device_trust_status)

const unsigned char *
auth_prevalidated_identity_get_jti_digest(const struct auth_prevalidated_identity *identity)
{ return identity == NULL ? NULL : identity->jti_digest; }

int64_t
auth_prevalidated_identity_get_expiry(const struct auth_prevalidated_identity *identity)
{ return identity == NULL ? 0 : identity->expiry; }

#define ARRAY_ACCESSORS(count_function, item_function, values_member, count_member) \
size_t count_function(const struct auth_prevalidated_identity *identity) \
{ return identity == NULL ? 0 : identity->count_member; } \
const char *item_function(const struct auth_prevalidated_identity *identity, size_t index) \
{ return identity == NULL || index >= identity->count_member ? NULL : identity->values_member[index]; }

ARRAY_ACCESSORS(auth_prevalidated_identity_get_group_count, auth_prevalidated_identity_get_group, groups, group_count)
ARRAY_ACCESSORS(auth_prevalidated_identity_get_role_count, auth_prevalidated_identity_get_role, roles, role_count)
ARRAY_ACCESSORS(auth_prevalidated_identity_get_auth_method_count, auth_prevalidated_identity_get_auth_method, auth_methods, auth_method_count)

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
        case AUTH_PROVIDER_REPLAY:
            return "replay";
        case AUTH_PROVIDER_CONFIG_ERROR:
            return "configuration-error";
        case AUTH_PROVIDER_DEPENDENCY_UNAVAILABLE:
            return "dependency-unavailable";
        case AUTH_PROVIDER_INTERNAL_ERROR:
            return "internal-error";
        default:
            return "unknown";
    }
}
