#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "baf_runtime_config.h"

#include "os_calls.h"
#include "string_calls.h"

static int
is_nonempty(const char *value)
{
    return value != NULL && value[0] != '\0';
}

static void
replace_string(char **dst, const char *value)
{
    g_free(*dst);
    *dst = g_strdup(value == NULL ? "" : value);
}

void
baf_runtime_config_init(struct baf_runtime_config *config)
{
    if (config != NULL)
    {
        config->broker_auth_enabled = 0;
        config->broker_auth_rdsaad_enabled = 0;
        config->reject_uid0 = 1;
        config->allow_session_start = 0;
        config->max_assertion_size = BAF_RUNTIME_MAX_ASSERTION_BYTES;
        config->provider = g_strdup(BAF_RUNTIME_DEFAULT_PROVIDER);
        config->trust_anchor = g_strdup("");
        config->expected_audience = g_strdup("");
        config->local_target = g_strdup("");
        config->replay_backend = g_strdup(BAF_RUNTIME_DEFAULT_REPLAY_BACKEND);
        config->replay_socket = g_strdup("");
    }
}

void
baf_runtime_config_free(struct baf_runtime_config *config)
{
    if (config != NULL)
    {
        g_free(config->provider);
        g_free(config->trust_anchor);
        g_free(config->expected_audience);
        g_free(config->local_target);
        g_free(config->replay_backend);
        g_free(config->replay_socket);
        config->provider = NULL;
        config->trust_anchor = NULL;
        config->expected_audience = NULL;
        config->local_target = NULL;
        config->replay_backend = NULL;
        config->replay_socket = NULL;
    }
}

enum baf_runtime_config_status
baf_runtime_config_validate(const struct baf_runtime_config *config)
{
    if (config == NULL)
    {
        return BAF_RUNTIME_CONFIG_INVALID;
    }

    if (!config->broker_auth_enabled || !config->broker_auth_rdsaad_enabled)
    {
        return BAF_RUNTIME_CONFIG_DISABLED;
    }

    if (!is_nonempty(config->provider) ||
            !is_nonempty(config->replay_backend) ||
            g_strcasecmp(config->provider, BAF_RUNTIME_DEFAULT_PROVIDER) != 0 ||
            g_strcasecmp(config->replay_backend,
                         BAF_RUNTIME_DEFAULT_REPLAY_BACKEND) != 0 ||
            !is_nonempty(config->trust_anchor) ||
            !is_nonempty(config->expected_audience) ||
            !is_nonempty(config->local_target) ||
            !is_nonempty(config->replay_socket) ||
            config->max_assertion_size == 0 ||
            config->max_assertion_size > BAF_RUNTIME_MAX_ASSERTION_BYTES ||
            !config->reject_uid0 ||
            config->allow_session_start)
    {
        return BAF_RUNTIME_CONFIG_INVALID;
    }

    return BAF_RUNTIME_CONFIG_OK;
}

int
baf_runtime_config_copy(struct baf_runtime_config *dst,
                        const struct baf_runtime_config *src)
{
    if (dst == NULL || src == NULL)
    {
        return 1;
    }

    baf_runtime_config_free(dst);
    dst->broker_auth_enabled = src->broker_auth_enabled;
    dst->broker_auth_rdsaad_enabled = src->broker_auth_rdsaad_enabled;
    dst->reject_uid0 = src->reject_uid0;
    dst->allow_session_start = src->allow_session_start;
    dst->max_assertion_size = src->max_assertion_size;
    dst->provider = NULL;
    dst->trust_anchor = NULL;
    dst->expected_audience = NULL;
    dst->local_target = NULL;
    dst->replay_backend = NULL;
    dst->replay_socket = NULL;

    replace_string(&dst->provider, src->provider);
    replace_string(&dst->trust_anchor, src->trust_anchor);
    replace_string(&dst->expected_audience, src->expected_audience);
    replace_string(&dst->local_target, src->local_target);
    replace_string(&dst->replay_backend, src->replay_backend);
    replace_string(&dst->replay_socket, src->replay_socket);

    return dst->provider == NULL || dst->trust_anchor == NULL ||
           dst->expected_audience == NULL || dst->local_target == NULL ||
           dst->replay_backend == NULL || dst->replay_socket == NULL;
}
