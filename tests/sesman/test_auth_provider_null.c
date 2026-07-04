/** Phase 1 fail-closed provider contract test. */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "auth_provider.h"
#include "auth_provider_null.h"
#include <stdint.h>
#include <stdio.h>

static int64_t
test_now(void *userdata)
{
    (void)userdata;
    return 1700000000;
}

static int
expect(int condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        return 1;
    }
    return 0;
}

int
main(void)
{
    static const unsigned char assertion[] = "opaque-not-a-jwt";
    struct auth_provider_request request = {0};
    struct auth_provider_result *result =
        (struct auth_provider_result *)(uintptr_t)1;
    enum auth_provider_status status;
    int failures = 0;

    request.assertion = assertion;
    request.assertion_length = sizeof(assertion) - 1;
    request.client_address = "192.0.2.1";
    request.expected_audience = "urn:test:audience";
    request.local_target = "urn:test:target";
    request.now = test_now;

    status = auth_provider_validate(auth_provider_null_get(),
                                    &request, &result);
    failures += expect(status == AUTH_PROVIDER_UNSUPPORTED,
                       "null provider must return unsupported");
    failures += expect(result == NULL,
                       "null provider must not return a result capability");
    failures += expect(auth_provider_result_get_identity(result) == NULL,
                       "no prevalidated identity may be obtained");

    result = (struct auth_provider_result *)(uintptr_t)1;
    status = auth_provider_validate(NULL, &request, &result);
    failures += expect(status == AUTH_PROVIDER_INTERNAL_ERROR,
                       "missing provider must fail closed");
    failures += expect(result == NULL,
                       "failure must clear the result pointer");
    failures += expect(auth_provider_status_to_string(
                           AUTH_PROVIDER_SUCCESS) != NULL,
                       "reserved success status must stringify");

    return failures == 0 ? 0 : 1;
}
