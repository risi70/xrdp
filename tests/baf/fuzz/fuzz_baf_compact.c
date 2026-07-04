/*
 * Optional libFuzzer entry point. Build this file together with the BAF
 * provider using -fsanitize=fuzzer,address,undefined.
 */
#include "auth_provider_jwt.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)auth_provider_jwt_fuzz_compact(data, size);
    return 0;
}
