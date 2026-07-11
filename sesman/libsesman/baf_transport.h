/** Internal opaque transport for Broker Authentication Framework assertions. */
#ifndef BAF_TRANSPORT_H
#define BAF_TRANSPORT_H
#include <stddef.h>
#include "auth_provider.h"
#define BAF_TRANSPORT_HARD_MAX_ASSERTION_BYTES (64U * 1024U)
enum baf_assertion_transport_source
{
    BAF_ASSERTION_TRANSPORT_NONE = 0,
    BAF_ASSERTION_TRANSPORT_INTERNAL,
    BAF_ASSERTION_TRANSPORT_TEST
};
enum baf_transport_status
{
    BAF_TRANSPORT_REJECTED = 0,
    BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED,
    BAF_TRANSPORT_UNSUPPORTED,
    BAF_TRANSPORT_REPLAY,
    BAF_TRANSPORT_CONFIG_ERROR,
    BAF_TRANSPORT_DEPENDENCY_UNAVAILABLE,
    BAF_TRANSPORT_INTERNAL_ERROR
};
struct baf_transport
{
    unsigned char *assertion;
    size_t assertion_length;
    enum baf_assertion_transport_source source;
    char *client_address;
    char *local_target;
};
void baf_transport_init(struct baf_transport *transport);
int baf_transport_set(struct baf_transport *transport,
                      const unsigned char *assertion,
                      size_t assertion_length,
                      size_t configured_maximum,
                      enum baf_assertion_transport_source source,
                      const char *client_address,
                      const char *local_target);
void baf_transport_clear(struct baf_transport *transport);
/**
 * Validate and immediately discard raw assertion bytes.
 *
 * Success is deliberately named IDENTITY_BINDING_REQUIRED. The returned
 * capability is not login authorization and cannot create a session.
 */
enum baf_transport_status
baf_transport_validate(struct baf_transport *transport,
                       int runtime_enabled,
                       const struct auth_provider *provider,
                       const struct auth_provider_config *config,
                       const char *expected_audience,
                       const char *server_nonce,
                       auth_provider_now_fn now,
                       void *now_userdata,
                       struct auth_provider_result **result);
#endif
