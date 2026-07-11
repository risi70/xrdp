/** Broker Authentication Framework opaque assertion transport. */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "baf_transport.h"
#include <stdlib.h>
#include <string.h>
#if !defined(ENABLE_BROKER_AUTH)
#error "baf_transport.c must only be built with broker auth enabled"
#endif
static void
secure_erase(void *memory, size_t length)
{
    volatile unsigned char *p = memory;
    while (p != NULL && length-- != 0)
    {
        *p++ = 0;
    }
}
static char *
copy_string(const char *value)
{
    size_t length;
    char *copy;
    if (value == NULL)
    {
        value = "";
    }
    length = strlen(value);
    copy = malloc(length + 1);
    if (copy != NULL)
    {
        memcpy(copy, value, length + 1);
    }
    return copy;
}
void
baf_transport_init(struct baf_transport *transport)
{
    if (transport != NULL)
    {
        memset(transport, 0, sizeof(*transport));
    }
}
void
baf_transport_clear(struct baf_transport *transport)
{
    if (transport != NULL)
    {
        secure_erase(transport->assertion, transport->assertion_length);
        free(transport->assertion);
        free(transport->client_address);
        free(transport->local_target);
        memset(transport, 0, sizeof(*transport));
    }
}
int
baf_transport_set(struct baf_transport *transport,
                  const unsigned char *assertion,
                  size_t assertion_length,
                  size_t configured_maximum,
                  enum baf_assertion_transport_source source,
                  const char *client_address,
                  const char *local_target)
{
    unsigned char *copy;
    char *address_copy;
    char *target_copy;
    if (transport == NULL || assertion == NULL || assertion_length == 0 ||
            source == BAF_ASSERTION_TRANSPORT_NONE || configured_maximum == 0 ||
            configured_maximum > BAF_TRANSPORT_HARD_MAX_ASSERTION_BYTES ||
            assertion_length > configured_maximum ||
            assertion_length > BAF_TRANSPORT_HARD_MAX_ASSERTION_BYTES)
    {
        return 1;
    }
    copy = malloc(assertion_length);
    address_copy = copy_string(client_address);
    target_copy = copy_string(local_target);
    if (copy == NULL || address_copy == NULL || target_copy == NULL)
    {
        free(copy);
        free(address_copy);
        free(target_copy);
        return 1;
    }
    memcpy(copy, assertion, assertion_length);
    baf_transport_clear(transport);
    transport->assertion = copy;
    transport->assertion_length = assertion_length;
    transport->source = source;
    transport->client_address = address_copy;
    transport->local_target = target_copy;
    return 0;
}
static enum baf_transport_status
map_status(enum auth_provider_status status)
{
    switch (status)
    {
        case AUTH_PROVIDER_SUCCESS:
            return BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED;
        case AUTH_PROVIDER_UNSUPPORTED:
            return BAF_TRANSPORT_UNSUPPORTED;
        case AUTH_PROVIDER_REPLAY:
            return BAF_TRANSPORT_REPLAY;
        case AUTH_PROVIDER_CONFIG_ERROR:
            return BAF_TRANSPORT_CONFIG_ERROR;
        case AUTH_PROVIDER_DEPENDENCY_UNAVAILABLE:
            return BAF_TRANSPORT_DEPENDENCY_UNAVAILABLE;
        case AUTH_PROVIDER_INTERNAL_ERROR:
            return BAF_TRANSPORT_INTERNAL_ERROR;
        case AUTH_PROVIDER_INVALID:
        default:
            return BAF_TRANSPORT_REJECTED;
    }
}
enum baf_transport_status
baf_transport_validate(struct baf_transport *transport,
                       int runtime_enabled,
                       const struct auth_provider *provider,
                       const struct auth_provider_config *config,
                       const char *expected_audience,
                       const char *server_nonce,
                       auth_provider_now_fn now,
                       void *now_userdata,
                       struct auth_provider_result **result)
{
    struct auth_provider_request request;
    enum auth_provider_status provider_status;
    if (result == NULL)
    {
        baf_transport_clear(transport);
        return BAF_TRANSPORT_INTERNAL_ERROR;
    }
    *result = NULL;
    if (!runtime_enabled)
    {
        baf_transport_clear(transport);
        return BAF_TRANSPORT_UNSUPPORTED;
    }
    if (transport == NULL || transport->assertion == NULL ||
            transport->assertion_length == 0 || config == NULL ||
            expected_audience == NULL || transport->local_target == NULL)
    {
        baf_transport_clear(transport);
        return BAF_TRANSPORT_CONFIG_ERROR;
    }
    memset(&request, 0, sizeof(request));
    request.assertion = transport->assertion;
    request.assertion_length = transport->assertion_length;
    request.client_address = transport->client_address;
    request.config = config;
    request.expected_audience = expected_audience;
    request.local_target = transport->local_target;
    request.server_nonce = server_nonce;
    request.now = now;
    request.now_userdata = now_userdata;
    provider_status = auth_provider_validate(provider, &request, result);
    baf_transport_clear(transport);
    return map_status(provider_status);
}
