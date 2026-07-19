/** Fail-closed Phase 1 provider. */
#ifndef AUTH_PROVIDER_NULL_H
#define AUTH_PROVIDER_NULL_H

struct auth_provider;

#if defined(ENABLE_BROKER_AUTH)
const struct auth_provider *
auth_provider_null_get(void);
#endif

#endif /* AUTH_PROVIDER_NULL_H */
