#ifndef AUTH_PROVIDER_BROKER_H
#define AUTH_PROVIDER_BROKER_H

#include "auth_provider.h"

#if defined(ENABLE_BROKER_AUTH)
/* Returns the deliberately unavailable broker provider skeleton. */
const struct auth_provider *
auth_provider_broker_get(void);
#endif

#endif
