/*
 * baf_handle_tool - Broker-RDP Handle lab helper.
 *
 * Stands in for the broker-side registration component in focused integration
 * tests. Two subcommands:
 *
 *   store  -s SOCKET -t TARGET [-l TTL] < assertion
 *       Register an assertion with the trusted handle service and print the
 *       one-time handle on stdout. The broker (or this lab script) then
 *       feeds the handle to the client launch path.
 *
 *   check  -s SOCKET -H HANDLE -t TARGET -k TRUST_PEM -i ISSUER -a AUDIENCE
 *          -K KID [-n TS_NONCE] [-r REPLAY_SOCKET]
 *       Resolve+consume the handle and run the BAF validator on the
 *       recovered assertion, exactly as xrdp-sesexec does before identity
 *       binding. With -n, RequireNonceBinding is enforced. Prints PASS/FAIL.
 *       This is a headless pre-flight for the RDP-level smoke test; it does
 *       not perform NSS/PAM (those need the live session path).
 *
 * NOT a production tool: no auditing, minimal hardening. Lab use only.
 */

#include "auth_provider.h"
#include "auth_provider_jwt.h"
#include "baf_handle_service.h"
#include "baf_transport.h"
#include "replay_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned char *
read_stream(FILE *stream, size_t *length)
{
    size_t cap = 4096;
    size_t len = 0;
    unsigned char *buf = malloc(cap);

    if (buf == NULL)
    {
        return NULL;
    }
    for (;;)
    {
        size_t n = fread(buf + len, 1, cap - len, stream);
        len += n;
        if (n == 0)
        {
            break;
        }
        if (len == cap)
        {
            unsigned char *grown;
            cap *= 2;
            grown = realloc(buf, cap);
            if (grown == NULL)
            {
                free(buf);
                return NULL;
            }
            buf = grown;
        }
    }
    /* Trim a single trailing newline for convenience. */
    if (len > 0 && buf[len - 1] == '\n')
    {
        --len;
    }
    *length = len;
    return buf;
}

static unsigned char *
read_file(const char *path, size_t *length)
{
    FILE *stream = fopen(path, "rb");
    unsigned char *data;

    if (stream == NULL)
    {
        return NULL;
    }
    data = read_stream(stream, length);
    fclose(stream);
    return data;
}

static int
do_store(int argc, char **argv)
{
    const char *socket_path = NULL;
    const char *target = NULL;
    long ttl = 90;
    unsigned char *assertion;
    size_t assertion_length = 0;
    char handle[BAF_HANDLE_TEXT_LENGTH + 1];
    enum baf_handle_status status;
    int opt;

    while ((opt = getopt(argc, argv, "s:t:l:")) != -1)
    {
        switch (opt)
        {
            case 's':
                socket_path = optarg;
                break;
            case 't':
                target = optarg;
                break;
            case 'l':
                ttl = atol(optarg);
                break;
            default:
                return 2;
        }
    }
    if (socket_path == NULL || target == NULL || ttl <= 0)
    {
        fprintf(stderr, "store: -s SOCKET -t TARGET [-l TTL] required\n");
        return 2;
    }
    assertion = read_stream(stdin, &assertion_length);
    if (assertion == NULL || assertion_length == 0)
    {
        fprintf(stderr, "store: empty assertion on stdin\n");
        free(assertion);
        return 2;
    }
    status = baf_handle_store(socket_path, 2000, assertion, assertion_length,
                              time(NULL) + ttl, target, handle);
    free(assertion);
    if (status != BAF_HANDLE_OK)
    {
        fprintf(stderr, "store: handle service returned status %d\n",
                (int)status);
        return 1;
    }
    printf("%s\n", handle);
    return 0;
}

static int
do_check(int argc, char **argv)
{
    const char *socket_path = NULL;
    const char *handle = NULL;
    const char *target = NULL;
    const char *trust_pem_path = NULL;
    const char *issuer = NULL;
    const char *audience = NULL;
    const char *kid = NULL;
    const char *nonce = NULL;
    const char *replay_socket = NULL;
    unsigned char *trust_pem = NULL;
    size_t trust_pem_length = 0;
    unsigned char *resolved = NULL;
    size_t resolved_length = 0;
    struct replay_cache *cache = NULL;
    struct baf_validator_options options;
    struct auth_provider_config *config = NULL;
    struct auth_provider_result *result = NULL;
    struct baf_transport transport;
    enum baf_handle_status handle_status;
    enum baf_transport_status transport_status;
    int rv = 1;
    int opt;

    while ((opt = getopt(argc, argv, "s:H:t:k:i:a:K:n:r:")) != -1)
    {
        switch (opt)
        {
            case 's':
                socket_path = optarg;
                break;
            case 'H':
                handle = optarg;
                break;
            case 't':
                target = optarg;
                break;
            case 'k':
                trust_pem_path = optarg;
                break;
            case 'i':
                issuer = optarg;
                break;
            case 'a':
                audience = optarg;
                break;
            case 'K':
                kid = optarg;
                break;
            case 'n':
                nonce = optarg;
                break;
            case 'r':
                replay_socket = optarg;
                break;
            default:
                return 2;
        }
    }
    if (socket_path == NULL || handle == NULL || target == NULL ||
            trust_pem_path == NULL || issuer == NULL || audience == NULL ||
            kid == NULL)
    {
        fprintf(stderr, "check: -s -H -t -k -i -a -K required\n");
        return 2;
    }
    trust_pem = read_file(trust_pem_path, &trust_pem_length);
    if (trust_pem == NULL || trust_pem_length == 0)
    {
        fprintf(stderr, "check: cannot read trust anchor %s\n",
                trust_pem_path);
        free(trust_pem);
        return 2;
    }

    baf_transport_init(&transport);

    handle_status = baf_handle_resolve_and_consume(socket_path, 2000, handle,
                    target, &resolved, &resolved_length);
    if (handle_status != BAF_HANDLE_OK || resolved == NULL ||
            resolved_length == 0)
    {
        fprintf(stderr, "FAIL: handle resolve status %d\n",
                (int)handle_status);
        goto out;
    }

    if (replay_socket != NULL)
    {
        cache = replay_cache_service_create(replay_socket, 1000);
        if (cache == NULL || !replay_cache_is_service(cache))
        {
            fprintf(stderr, "FAIL: replay service unavailable\n");
            goto out;
        }
    }
    else
    {
        cache = replay_cache_memory_create(32);
    }

    memset(&options, 0, sizeof(options));
    options.enabled = 1;
    options.issuer = issuer;
    options.expected_audience = audience;
    options.local_target = target;
    options.allowed_algorithms = "RS256";
    options.max_assertion_bytes = 16384;
    options.max_lifetime_seconds = 300;
    options.clock_skew_seconds = 30;
    options.key_id = kid;
    options.trust_pem = trust_pem;
    options.trust_pem_length = trust_pem_length;
    options.replay_cache = cache;
    options.require_service_replay = replay_socket != NULL ? 1 : 0;
    options.require_nonce_binding = nonce != NULL ? 1 : 0;
    if (baf_validator_config_create(&options, &config) !=
            AUTH_PROVIDER_SUCCESS)
    {
        fprintf(stderr, "FAIL: validator config invalid\n");
        goto out;
    }

    if (baf_transport_set(&transport, resolved, resolved_length, 16384,
                          BAF_ASSERTION_TRANSPORT_INTERNAL, NULL,
                          target) != 0)
    {
        fprintf(stderr, "FAIL: transport rejected assertion\n");
        goto out;
    }
    transport_status = baf_transport_validate(&transport, 1,
                       auth_provider_jwt_get(), config, audience, nonce,
                       NULL, NULL, &result);
    if (transport_status == BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED &&
            result != NULL)
    {
        const struct auth_prevalidated_identity *identity =
            auth_provider_result_get_identity(result);
        printf("PASS: assertion validated%s; preferred_username=%s\n",
               nonce != NULL ? " (nonce-bound)" : "",
               identity != NULL ?
               auth_prevalidated_identity_get_preferred_username(identity) :
               "?");
        rv = 0;
    }
    else
    {
        fprintf(stderr, "FAIL: validation status %d\n",
                (int)transport_status);
    }

out:
    auth_provider_result_free(result);
    baf_validator_config_free(config);
    replay_cache_free(cache);
    baf_transport_clear(&transport);
    baf_handle_assertion_free(resolved, resolved_length);
    free(trust_pem);
    return rv;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s {store|check} ...\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "store") == 0)
    {
        return do_store(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "check") == 0)
    {
        return do_check(argc - 1, argv + 1);
    }
    fprintf(stderr, "unknown subcommand %s\n", argv[1]);
    return 2;
}
