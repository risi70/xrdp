/**
 * RDS AAD Auth-style PDU helpers.
 *
 * The RDS AAD Auth PDUs in [MS-RDPBCGR] 2.2.18 are UTF-8 JSON strings. This
 * file intentionally implements only the small schema needed by the wire PDUs:
 *   {"ts_nonce":"..."}
 *   {"rdp_assertion":"..."}
 *   {"authentication_result":"<HRESULT>"}
 *
 * It never logs raw assertions and never interprets assertions as identities.
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "rdsaad.h"

#include <stdio.h>
#include <string.h>

static int
is_valid_utf8(const char *p, size_t n)
{
    size_t i = 0;

    while (i < n)
    {
        unsigned char c = (unsigned char)p[i];
        if (c <= 0x7f)
        {
            ++i;
        }
        else if ((c & 0xe0) == 0xc0)
        {
            if (i + 1 >= n || ((unsigned char)p[i + 1] & 0xc0) != 0x80 ||
                    c < 0xc2)
            {
                return 0;
            }
            i += 2;
        }
        else if ((c & 0xf0) == 0xe0)
        {
            unsigned char c1;
            if (i + 2 >= n ||
                    ((unsigned char)p[i + 1] & 0xc0) != 0x80 ||
                    ((unsigned char)p[i + 2] & 0xc0) != 0x80)
            {
                return 0;
            }
            c1 = (unsigned char)p[i + 1];
            if ((c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 >= 0xa0))
            {
                return 0;
            }
            i += 3;
        }
        else if ((c & 0xf8) == 0xf0)
        {
            unsigned char c1;
            if (i + 3 >= n ||
                    ((unsigned char)p[i + 1] & 0xc0) != 0x80 ||
                    ((unsigned char)p[i + 2] & 0xc0) != 0x80 ||
                    ((unsigned char)p[i + 3] & 0xc0) != 0x80)
            {
                return 0;
            }
            c1 = (unsigned char)p[i + 1];
            if ((c == 0xf0 && c1 < 0x90) || c > 0xf4 ||
                    (c == 0xf4 && c1 >= 0x90))
            {
                return 0;
            }
            i += 4;
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

static const char *
skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
    {
        ++p;
    }
    return p;
}

static int
json_string_equal(const char **p, const char *end, const char *wanted)
{
    size_t wanted_len = strlen(wanted);

    if (*p >= end || **p != '"')
    {
        return 0;
    }
    ++*p;
    if ((size_t)(end - *p) < wanted_len ||
            memcmp(*p, wanted, wanted_len) != 0)
    {
        return 0;
    }
    *p += wanted_len;
    if (*p >= end || **p != '"')
    {
        return 0;
    }
    ++*p;
    return 1;
}

static enum rdsaad_status
read_json_string(const char **p, const char *end,
                 char *output, size_t output_size, size_t *output_length)
{
    size_t used = 0;

    if (*p >= end || **p != '"' || output == NULL || output_size == 0 ||
            output_length == NULL)
    {
        return RDSAAD_STATUS_INVALID;
    }
    ++ *p;
    while (*p < end && **p != '"')
    {
        unsigned char c = (unsigned char) **p;
        if (c < 0x20)
        {
            return RDSAAD_STATUS_INVALID;
        }
        if (c == '\\')
        {
            return RDSAAD_STATUS_INVALID;
        }
        if (used + 1 >= output_size)
        {
            return RDSAAD_STATUS_OVERSIZE;
        }
        output[used++] = (char)c;
        ++*p;
    }
    if (*p >= end || **p != '"')
    {
        return RDSAAD_STATUS_INVALID;
    }
    ++ *p;
    output[used] = '\0';
    *output_length = used;
    return RDSAAD_STATUS_OK;
}

static enum rdsaad_status
parse_single_string_member(const char *json, size_t json_length,
                           const char *name, char *value,
                           size_t value_size, size_t *value_length)
{
    const char *p = json;
    const char *end = json + json_length;
    enum rdsaad_status status;

    if (json == NULL || json_length == 0 || json_length > RDSAAD_MAX_JSON_BYTES ||
            !is_valid_utf8(json, json_length))
    {
        return json_length > RDSAAD_MAX_JSON_BYTES ?
        RDSAAD_STATUS_OVERSIZE : RDSAAD_STATUS_INVALID;
    }

    p = skip_ws(p, end);
    if (p >= end || *p != '{')
    {
        return RDSAAD_STATUS_INVALID;
    }
    ++p;
    p = skip_ws(p, end);
    if (p < end && *p == '}')
    {
        return RDSAAD_STATUS_MISSING_FIELD;
    }
    if (p >= end || *p != '"')
    {
        return RDSAAD_STATUS_INVALID;
    }
    if (!json_string_equal(&p, end, name))
    {
        return RDSAAD_STATUS_MISSING_FIELD;
    }
    p = skip_ws(p, end);
    if (p >= end || *p != ':')
    {
        return RDSAAD_STATUS_INVALID;
    }
    ++p;
    p = skip_ws(p, end);
    status = read_json_string(&p, end, value, value_size, value_length);
    if (status != RDSAAD_STATUS_OK)
    {
        return status;
    }
    p = skip_ws(p, end);
    if (p < end && *p == ',')
    {
        ++p;
        p = skip_ws(p, end);
        if (json_string_equal(&p, end, name))
        {
            return RDSAAD_STATUS_DUPLICATE_FIELD;
        }
        return RDSAAD_STATUS_INVALID;
    }
    if (p >= end || *p != '}')
    {
        return RDSAAD_STATUS_INVALID;
    }
    ++p;
    p = skip_ws(p, end);
    return p == end ? RDSAAD_STATUS_OK : RDSAAD_STATUS_INVALID;
}

static int
json_string_needs_escape(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    for (; *p != '\0'; ++p)
    {
        if (*p < 0x20 || *p == '"' || *p == '\\')
        {
            return 1;
        }
    }
    return 0;
}

enum rdsaad_status
rdsaad_encode_server_nonce(const char *nonce,
                           char *output,
                           size_t output_size,
                           size_t *written)
{
    int n;
    size_t nonce_length;

    if (written != NULL)
    {
        *written = 0;
    }
    if (nonce == NULL || output == NULL || output_size == 0)
    {
        return RDSAAD_STATUS_INVALID;
    }
    nonce_length = strlen(nonce);
    if (nonce_length == 0 || nonce_length > RDSAAD_MAX_NONCE_BYTES ||
            json_string_needs_escape(nonce) ||
            !is_valid_utf8(nonce, nonce_length))
    {
        return RDSAAD_STATUS_INVALID;
    }
    n = snprintf(output, output_size, "{\"ts_nonce\":\"%s\"}", nonce);
    if (n < 0)
    {
        return RDSAAD_STATUS_INVALID;
    }
    if ((size_t)n >= output_size)
    {
        return RDSAAD_STATUS_OVERFLOW;
    }
    if (written != NULL)
    {
        *written = (size_t)n;
    }
    return RDSAAD_STATUS_OK;
}

enum rdsaad_status
rdsaad_parse_authentication_request(const char *json,
                                    size_t json_length,
                                    char *assertion,
                                    size_t assertion_size,
                                    size_t *assertion_length)
{
    enum rdsaad_status status;

    if (assertion_length != NULL)
    {
        *assertion_length = 0;
    }
    if (assertion == NULL || assertion_size == 0 ||
            assertion_size > RDSAAD_MAX_ASSERTION_BYTES + 1)
    {
        return RDSAAD_STATUS_INVALID;
    }
    status = parse_single_string_member(json, json_length, "rdp_assertion",
                                        assertion, assertion_size,
                                        assertion_length);
    if (status == RDSAAD_STATUS_OK &&
            (assertion_length == NULL || *assertion_length == 0))
    {
        return RDSAAD_STATUS_MISSING_FIELD;
    }
    return status;
}

enum rdsaad_status
rdsaad_encode_authentication_result(uint32_t hresult,
                                    char *output,
                                    size_t output_size,
                                    size_t *written)
{
    int n;

    if (written != NULL)
    {
        *written = 0;
    }
    if (output == NULL || output_size == 0)
    {
        return RDSAAD_STATUS_INVALID;
    }
    n = snprintf(output, output_size, "{\"authentication_result\":\"%u\"}",
                 hresult);
    if (n < 0)
    {
        return RDSAAD_STATUS_INVALID;
    }
    if ((size_t)n >= output_size)
    {
        return RDSAAD_STATUS_OVERFLOW;
    }
    if (written != NULL)
    {
        *written = (size_t)n;
    }
    return RDSAAD_STATUS_OK;
}
