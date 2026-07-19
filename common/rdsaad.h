/**
 * RDS AAD Auth-style PDU helpers.
 *
 * These helpers cover the UTF-8 JSON payloads defined by [MS-RDPBCGR]
 * sections 2.2.18.1, 2.2.18.2, and 2.2.18.3. They do not perform identity
 * lookup, PAM checks, session startup, or assertion validation.
 */

#if !defined(RDSAAD_H)
#define RDSAAD_H

#include <stddef.h>
#include <stdint.h>

#define RDSAAD_MAX_JSON_BYTES 32768U
#define RDSAAD_MAX_ASSERTION_BYTES 16384U
#define RDSAAD_MAX_NONCE_BYTES 256U

#define RDSAAD_HRESULT_S_OK 0x00000000U
#define RDSAAD_HRESULT_SEC_E_INVALID_TOKEN 0x80090308U
#define RDSAAD_HRESULT_E_ACCESSDENIED 0x80070005U
#define RDSAAD_HRESULT_STATUS_LOGON_FAILURE 0xD000006DU
#define RDSAAD_HRESULT_STATUS_NO_LOGON_SERVERS 0xD000005EU

enum rdsaad_status
{
    RDSAAD_STATUS_OK = 0,
    RDSAAD_STATUS_INVALID,
    RDSAAD_STATUS_MISSING_FIELD,
    RDSAAD_STATUS_DUPLICATE_FIELD,
    RDSAAD_STATUS_OVERFLOW,
    RDSAAD_STATUS_OVERSIZE
};

enum rdsaad_status
rdsaad_encode_server_nonce(const char *nonce,
                           char *output,
                           size_t output_size,
                           size_t *written);

enum rdsaad_status
rdsaad_parse_authentication_request(const char *json,
                                    size_t json_length,
                                    char *assertion,
                                    size_t assertion_size,
                                    size_t *assertion_length);

enum rdsaad_status
rdsaad_encode_authentication_result(uint32_t hresult,
                                    char *output,
                                    size_t output_size,
                                    size_t *written);

#endif
