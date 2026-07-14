#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "baf_runtime_config.h"
#include "sesman_config.h"

#include "os_calls.h"
#include "string_calls.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static void
replace(char **dst, const char *value)
{
    g_free(*dst);
    *dst = g_strdup(value);
    assert(*dst != NULL);
}

static void
make_valid(struct baf_runtime_config *config)
{
    baf_runtime_config_init(config);
    config->broker_auth_enabled = 1;
    config->broker_auth_rdsaad_enabled = 1;
    replace(&config->issuer, "https://broker.example.test");
    replace(&config->key_id, "baf-key-1");
    replace(&config->allowed_algorithms, "RS256");
    replace(&config->trust_anchor, "/etc/xrdp/baf/trust-anchor.pem");
    replace(&config->expected_audience, "xrdp-baf");
    replace(&config->local_target, "xrdp-session");
    replace(&config->replay_socket, "/run/xrdp/baf-replay.sock");
}

static void
test_defaults_fail_closed(void)
{
    struct baf_runtime_config config = {0};

    baf_runtime_config_init(&config);

    assert(config.broker_auth_enabled == 0);
    assert(config.broker_auth_rdsaad_enabled == 0);
    assert(config.reject_uid0 == 1);
    assert(config.allow_session_start == 0);
    assert(config.max_assertion_size == BAF_RUNTIME_MAX_ASSERTION_BYTES);
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_DISABLED);

    baf_runtime_config_free(&config);
}

static void
test_valid_config_passes(void)
{
    struct baf_runtime_config config = {0};

    make_valid(&config);
    assert(baf_runtime_config_validate(&config) == BAF_RUNTIME_CONFIG_OK);

    baf_runtime_config_free(&config);
}

static void
test_required_fields_fail_closed(void)
{
    struct baf_runtime_config config = {0};

    make_valid(&config);
    replace(&config.issuer, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.key_id, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.allowed_algorithms, "HS256");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.trust_anchor, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.expected_audience, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.local_target, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);
}

static void
test_replay_service_required(void)
{
    struct baf_runtime_config config = {0};

    make_valid(&config);
    replace(&config.replay_backend, "process");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    make_valid(&config);
    replace(&config.replay_socket, "");
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);
}

static void
test_session_start_stays_disabled(void)
{
    struct baf_runtime_config config = {0};

    make_valid(&config);
    assert(baf_runtime_config_validate(&config) ==
           BAF_RUNTIME_CONFIG_OK);
    assert(baf_runtime_config_validate_live(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    config.allow_session_start = 1;
    assert(baf_runtime_config_validate_live(&config) ==
           BAF_RUNTIME_CONFIG_OK);
    baf_runtime_config_free(&config);
}

static void
test_mode_c_gating(void)
{
    struct baf_runtime_config config = {0};

    /* Defaults: Broker-RDP Handle disabled and off by default. */
    baf_runtime_config_init(&config);
    assert(config.mode_c_otc_enabled == 0);
    assert(config.require_nonce_binding == 0);
    assert(baf_runtime_config_validate_mode_c(&config) ==
           BAF_RUNTIME_CONFIG_DISABLED);
    baf_runtime_config_free(&config);

    /* Valid RDSAAD config alone does not enable Broker-RDP Handle. */
    make_valid(&config);
    config.allow_session_start = 1;
    assert(baf_runtime_config_validate_mode_c(&config) ==
           BAF_RUNTIME_CONFIG_DISABLED);

    /* Broker-RDP Handle works without RDSAAD but needs the session-start gate. */
    config.mode_c_otc_enabled = 1;
    config.broker_auth_rdsaad_enabled = 0;
    assert(baf_runtime_config_validate_mode_c(&config) ==
           BAF_RUNTIME_CONFIG_OK);
    config.allow_session_start = 0;
    assert(baf_runtime_config_validate_mode_c(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);

    /* Field problems still fail closed for Broker-RDP Handle. */
    config.allow_session_start = 1;
    replace(&config.replay_socket, "");
    assert(baf_runtime_config_validate_mode_c(&config) ==
           BAF_RUNTIME_CONFIG_INVALID);
    baf_runtime_config_free(&config);

    /* Copy preserves the Broker-RDP Handle fields. */
    make_valid(&config);
    config.mode_c_otc_enabled = 1;
    config.require_nonce_binding = 1;
    replace(&config.handle_socket, "/run/xrdp/baf-handle.sock");
    {
        struct baf_runtime_config copy = {0};
        baf_runtime_config_init(&copy);
        assert(baf_runtime_config_copy(&copy, &config) == 0);
        assert(copy.mode_c_otc_enabled == 1);
        assert(copy.require_nonce_binding == 1);
        assert(g_strcmp(copy.handle_socket,
                        "/run/xrdp/baf-handle.sock") == 0);
        baf_runtime_config_free(&copy);
    }
    baf_runtime_config_free(&config);
}

static void
test_sesexec_config_path(void)
{
    char path[256];
    FILE *fp;
    struct config_sesman *config;

    g_snprintf(path, sizeof(path), "/tmp/xrdp-baf-runtime-%ld.ini",
               (long)getpid());
    fp = fopen(path, "w");
    assert(fp != NULL);
    fprintf(fp,
            "[BrokerAuth]\n"
            "BrokerAuthEnabled=true\n"
            "RDSAADEnabled=true\n"
            "Provider=jwt\n"
            "Issuer=https://broker.example.test\n"
            "KeyId=baf-key-1\n"
            "AllowedAlgorithms=RS256\n"
            "TrustAnchor=/etc/xrdp/baf/trust-anchor.pem\n"
            "ExpectedAudience=xrdp-baf\n"
            "LocalTarget=xrdp-session\n"
            "MaxAssertionSize=8192\n"
            "ReplayBackend=service\n"
            "ReplaySocket=/run/xrdp/baf-replay.sock\n"
            "RejectUid0=true\n"
            "AllowSessionStart=false\n"
            "RequireNonceBinding=true\n"
            "ModeCOneTimeCredential=true\n"
            "HandleSocket=/run/xrdp/baf-handle.sock\n");
    fclose(fp);

    config = config_read(path);
    assert(config != NULL);
    assert(config->baf.broker_auth_enabled == 1);
    assert(config->baf.broker_auth_rdsaad_enabled == 1);
    assert(config->baf.max_assertion_size == 8192);
    assert(config->baf.reject_uid0 == 1);
    assert(config->baf.allow_session_start == 0);
    assert(config->baf.require_nonce_binding == 1);
    assert(config->baf.mode_c_otc_enabled == 1);
    assert(g_strcmp(config->baf.handle_socket,
                    "/run/xrdp/baf-handle.sock") == 0);
    /* Broker-RDP Handle still fails closed without the session-start gate. */
    assert(baf_runtime_config_validate_mode_c(&config->baf) ==
           BAF_RUNTIME_CONFIG_INVALID);
    assert(baf_runtime_config_validate(&config->baf) ==
           BAF_RUNTIME_CONFIG_OK);

    config_free(config);
    unlink(path);
}

int
main(void)
{
    test_defaults_fail_closed();
    test_valid_config_passes();
    test_required_fields_fail_closed();
    test_replay_service_required();
    test_session_start_stays_disabled();
    test_mode_c_gating();
    test_sesexec_config_path();
    return 0;
}
