/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) 2026 xrdp contributors
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef AUTH_PROVIDER_H
#define AUTH_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

enum auth_provider_status
{
    AUTH_PROVIDER_SUCCESS = 0,
    AUTH_PROVIDER_UNSUPPORTED,
    AUTH_PROVIDER_INVALID,
    AUTH_PROVIDER_CONFIG_ERROR,
    AUTH_PROVIDER_INTERNAL_ERROR
};

struct auth_provider;
struct auth_provider_config;
struct auth_provider_result;
struct auth_prevalidated_identity;

typedef int64_t (*auth_provider_now_fn)(void *userdata);

/**
 * Input to future assertion validation. Assertion data is opaque and is not
 * required to be NUL-terminated. Providers must not retain these pointers.
 */
struct auth_provider_request
{
    const unsigned char *assertion;
    size_t assertion_length;
    const char *client_address;
    const struct auth_provider_config *config;
    const char *expected_audience;
    const char *local_target;
    auth_provider_now_fn now;
    void *now_userdata;
};

/**
 * Validate a provider request. On failure, *result is always set to NULL.
 * Result and identity are opaque capabilities callers cannot construct.
 */
enum auth_provider_status
auth_provider_validate(const struct auth_provider *provider,
                       const struct auth_provider_request *request,
                       struct auth_provider_result **result);

const struct auth_prevalidated_identity *
auth_provider_result_get_identity(const struct auth_provider_result *result);

void
auth_provider_result_free(struct auth_provider_result *result);

const char *
auth_provider_status_to_string(enum auth_provider_status status);

#endif /* AUTH_PROVIDER_H */
