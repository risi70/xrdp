/**
 * Broker Authentication Framework trusted runtime configuration.
 */

#ifndef BAF_RUNTIME_CONFIG_H
#define BAF_RUNTIME_CONFIG_H

#define BAF_RUNTIME_DEFAULT_PROVIDER "jwt"
#define BAF_RUNTIME_DEFAULT_REPLAY_BACKEND "service"
#define BAF_RUNTIME_DEFAULT_ALLOWED_ALGORITHMS "RS256"
#define BAF_RUNTIME_MAX_ASSERTION_BYTES 16384U

enum baf_runtime_config_status
{
    BAF_RUNTIME_CONFIG_OK = 0,
    BAF_RUNTIME_CONFIG_DISABLED,
    BAF_RUNTIME_CONFIG_INVALID
};

struct baf_runtime_config
{
    int broker_auth_enabled;
    int broker_auth_rdsaad_enabled;
    int reject_uid0;
    int allow_session_start;
    unsigned int max_assertion_size;
    char *provider;
    char *issuer;
    char *key_id;
    char *allowed_algorithms;
    char *trust_anchor;
    char *expected_audience;
    char *local_target;
    char *replay_backend;
    char *replay_socket;
};

void
baf_runtime_config_init(struct baf_runtime_config *config);

void
baf_runtime_config_free(struct baf_runtime_config *config);

enum baf_runtime_config_status
baf_runtime_config_validate(const struct baf_runtime_config *config);

enum baf_runtime_config_status
baf_runtime_config_validate_live(const struct baf_runtime_config *config);

int
baf_runtime_config_copy(struct baf_runtime_config *dst,
                        const struct baf_runtime_config *src);

#endif
