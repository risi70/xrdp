/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file login_info.c
 * @brief Define functionality associated with user logins for sesexec
 * @author Matt Burt
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "login_info.h"

#include "trans.h"

#include "sesman_auth.h"
#include "sesman_access.h"
#include "sesman_config.h"
#include "login_info.h"
#include "os_calls.h"
#include "scp.h"
#include "sesexec.h"
#include "string_calls.h"

#if defined(ENABLE_BROKER_AUTH)
#include "auth_provider.h"
#include "auth_provider_jwt.h"
#include "baf_handle_service.h"
#include "baf_identity.h"
#include "baf_runtime_config.h"
#include "baf_transport.h"
#include "replay_cache.h"
#endif

// Sys login fails all take a fixed time before returning. This
// prevents an attacker using timing differences to determine
// information about the users on the system (CVE-2026-42218)
//
// Note that some systems may provide an upper time bound for
// a login failure that is higher than this. For example, the Linux
// PAM stack default sys login fail time is around 2000 milli-seconds.
// Consequently, it is important the auth stack is always called, even
// if it has been determined that this is unnecessary.
#define FAILED_LOGIN_CONSTANT_TIME 600 // milli-seconds

/******************************************************************************/
/**
 * Logs an authentication failure message
 *
 * @param username Username
 * @param ip_addr IP address, if known
 *
 * The message is intended for use by fail2ban. Make changes with care.
 */
static void
log_authfail_message(const char *username, const char *ip_addr)
{
    if (ip_addr == NULL || ip_addr[0] == '\0')
    {
        ip_addr = "unknown";
    }
    LOG(LOG_LEVEL_INFO, "AUTHFAIL: user=%s ip=%s time=%ld",
        username, ip_addr, (long)time(NULL));
}

#if defined(ENABLE_BROKER_AUTH)
/******************************************************************************/
static void
secure_erase_bytes(char *data, size_t length)
{
    volatile char *p = data;
    while (p != NULL && length-- != 0)
    {
        *p++ = 0;
    }
}

/******************************************************************************/
/**
 * Run the shared BAF authorization chain on a raw assertion.
 *
 * Covers the trusted replay service, JWT validation, NSS/SSSD identity
 * binding, UID 0 rejection, PAM account preconditions and the group access
 * policy. Callers gate on the trusted runtime configuration first; this
 * function does not check ingress enablement.
 *
 * @param required_username When non-NULL, the NSS-resolved username or the
 *                          assertion preferred_username must match exactly
 * @post On E_SCP_LOGIN_OK, *uid, *username (allocated) and *auth_info_out
 *       are filled in and owned by the caller
 */
static enum scp_login_status
baf_authorize_assertion(const unsigned char *assertion,
                        unsigned int assertion_length,
                        const char *client_address,
                        const char *server_nonce,
                        int require_nonce_binding,
                        const char *required_username,
                        uid_t *uid,
                        char **username,
                        struct auth_info **auth_info_out)
{
    struct replay_cache *replay_cache = NULL;
    struct auth_provider_config *provider_config = NULL;
    struct auth_provider_result *capability = NULL;
    struct baf_resolved_identity *identity = NULL;
    struct auth_info *auth_info = NULL;
    struct baf_transport transport;
    struct baf_validator_options validator_options = {0};
    struct baf_identity_options identity_options = {0};
    enum scp_login_status login_status = E_SCP_LOGIN_GENERAL_ERROR;
    enum baf_transport_status transport_status;
    enum baf_identity_status identity_status;
    const char *resolved_username;

    baf_transport_init(&transport);
    *uid = (uid_t) -1;
    *username = NULL;
    *auth_info_out = NULL;

    replay_cache = replay_cache_service_create(g_cfg->baf.replay_socket,
                   1000);
    if (replay_cache == NULL || !replay_cache_is_service(replay_cache))
    {
        LOG(LOG_LEVEL_WARNING,
            "BAF authorization rejected because trusted replay service is unavailable");
        login_status = E_SCP_LOGIN_GENERAL_ERROR;
        goto out;
    }

    validator_options.enabled = 1;
    validator_options.issuer = g_cfg->baf.issuer;
    validator_options.expected_audience = g_cfg->baf.expected_audience;
    validator_options.local_target = g_cfg->baf.local_target;
    validator_options.allowed_algorithms = g_cfg->baf.allowed_algorithms;
    validator_options.max_assertion_bytes = g_cfg->baf.max_assertion_size;
    validator_options.max_lifetime_seconds = BAF_DEFAULT_MAX_LIFETIME_SECONDS;
    validator_options.clock_skew_seconds = BAF_DEFAULT_CLOCK_SKEW_SECONDS;
    validator_options.key_id = g_cfg->baf.key_id;
    validator_options.trust_file = g_cfg->baf.trust_anchor;
    validator_options.replay_cache = replay_cache;
    validator_options.require_service_replay = 1;
    validator_options.require_nonce_binding = require_nonce_binding;

    if (baf_validator_config_create(&validator_options,
                                    &provider_config) !=
            AUTH_PROVIDER_SUCCESS)
    {
        LOG(LOG_LEVEL_WARNING,
            "BAF authorization rejected because trusted validator config is invalid");
        login_status = E_SCP_LOGIN_GENERAL_ERROR;
        goto out;
    }

    if (baf_transport_set(&transport, assertion, assertion_length,
                          g_cfg->baf.max_assertion_size,
                          BAF_ASSERTION_TRANSPORT_INTERNAL,
                          client_address, g_cfg->baf.local_target) != 0)
    {
        LOG(LOG_LEVEL_WARNING, "BAF authorization rejected malformed assertion");
        login_status = E_SCP_LOGIN_NOT_AUTHENTICATED;
        goto out;
    }

    transport_status = baf_transport_validate(&transport, 1,
                       auth_provider_jwt_get(), provider_config,
                       g_cfg->baf.expected_audience,
                       server_nonce != NULL && server_nonce[0] != '\0' ?
                       server_nonce : NULL,
                       NULL, NULL, &capability);
    if (transport_status != BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED)
    {
        LOG(LOG_LEVEL_WARNING, "BAF assertion validation failed");
        login_status = E_SCP_LOGIN_NOT_AUTHORIZED;
        goto out;
    }

    identity_options.allow_uid0 = !g_cfg->baf.reject_uid0;
    identity_options.max_username_bytes = BAF_IDENTITY_MAX_USERNAME_BYTES;
    identity_status = baf_identity_bind_and_authorize(capability,
                      &identity_options, NULL, NULL, client_address,
                      &identity, &auth_info, &login_status);
    if (identity_status != BAF_IDENTITY_SUCCESS ||
            auth_info == NULL || login_status != E_SCP_LOGIN_OK)
    {
        LOG(LOG_LEVEL_WARNING,
            "BAF identity or PAM account authorization failed");
        goto out;
    }

    resolved_username = baf_resolved_identity_get_username(identity);
    if (required_username != NULL)
    {
        const struct auth_prevalidated_identity *claims =
            auth_provider_result_get_identity(capability);
        const char *preferred = claims == NULL ? NULL :
                                auth_prevalidated_identity_get_preferred_username(claims);

        if (g_strcmp(resolved_username, required_username) != 0 &&
                (preferred == NULL ||
                 g_strcmp(preferred, required_username) != 0))
        {
            LOG(LOG_LEVEL_WARNING,
                "BAF authorization rejected: supplied username does not "
                "match the broker-bound identity");
            login_status = E_SCP_LOGIN_NOT_AUTHORIZED;
            goto out;
        }
    }

    if (!access_login_allowed(&g_cfg->sec, resolved_username))
    {
        LOG(LOG_LEVEL_INFO, "BAF user denied by access policy");
        login_status = E_SCP_LOGIN_NOT_AUTHORIZED;
        goto out;
    }

    *username = g_strdup(resolved_username);
    if (*username == NULL)
    {
        login_status = E_SCP_LOGIN_NO_MEMORY;
        goto out;
    }
    *uid = baf_resolved_identity_get_uid(identity);
    *auth_info_out = auth_info;
    auth_info = NULL;
    login_status = E_SCP_LOGIN_OK;

out:
    auth_end(auth_info);
    baf_resolved_identity_free(identity);
    auth_provider_result_free(capability);
    baf_transport_clear(&transport);
    baf_validator_config_free(provider_config);
    replay_cache_free(replay_cache);
    return login_status;
}

/******************************************************************************/
/**
 * Check whether a supplied secret has the exact shape of a Broker-RDP Handle
 * (64 lowercase hex characters). Handle-shaped secrets never reach the PAM
 * password stack when Broker-RDP Handle is enabled.
 */
static int
password_is_otc_handle(const char *password)
{
    size_t i;

    if (password == NULL)
    {
        return 0;
    }
    for (i = 0; password[i] != '\0'; ++i)
    {
        char c = password[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            return 0;
        }
    }
    return i == BAF_HANDLE_TEXT_LENGTH;
}

/******************************************************************************/
/**
 * Atomically consume a Broker-RDP Handle in the trusted handle service and
 * recover the server-side assertion. Fails closed on any service error.
 */
static enum baf_handle_status
modec_resolve_handle(const char *handle,
                     unsigned char **assertion,
                     size_t *assertion_length)
{
    const char *socket_path =
        g_cfg->baf.handle_socket[0] != '\0' ?
        g_cfg->baf.handle_socket : BAF_HANDLE_DEFAULT_SOCKET;
    enum baf_handle_status handle_status;

    handle_status = baf_handle_resolve_and_consume(socket_path, 1000,
        handle, g_cfg->baf.local_target,
        assertion, assertion_length);
    if (handle_status == BAF_HANDLE_OK &&
            (*assertion == NULL || *assertion_length == 0 ||
             *assertion_length > BAF_HANDLE_MAX_ASSERTION))
    {
        baf_handle_assertion_free(*assertion, *assertion_length);
        *assertion = NULL;
        *assertion_length = 0;
        handle_status = BAF_HANDLE_ERROR;
    }
    return handle_status;
}

/******************************************************************************/
/**
 * Broker-RDP Handle one-time-credential login.
 *
 * Atomically consumes the handle in the trusted handle service, then runs
 * the full BAF authorization chain on the recovered assertion. A failed
 * handle never falls back to password authentication.
 */
static enum scp_login_status
mode_c_authenticate(const char *supplied_username,
                    const char *handle,
                    const char *ip_addr,
                    struct login_info *login_info)
{
    unsigned char *assertion = NULL;
    size_t assertion_length = 0;
    enum baf_handle_status handle_status;
    enum scp_login_status status;
    uid_t uid = (uid_t) -1;
    char *username = NULL;
    struct auth_info *auth_info = NULL;

    handle_status = modec_resolve_handle(handle, &assertion,
                                         &assertion_length);
    if (handle_status != BAF_HANDLE_OK)
    {
        LOG(LOG_LEVEL_WARNING,
            "Broker-RDP Handle one-time credential rejected by handle service "
            "(status %d)", (int)handle_status);
        log_authfail_message(supplied_username, ip_addr);
        return E_SCP_LOGIN_NOT_AUTHENTICATED;
    }

    status = baf_authorize_assertion(assertion,
                                     (unsigned int)assertion_length,
                                     ip_addr, NULL, 0, supplied_username,
                                     &uid, &username, &auth_info);
    baf_handle_assertion_free(assertion, assertion_length);

    if (status == E_SCP_LOGIN_OK)
    {
        char *dup_ip_addr = g_strdup(ip_addr == NULL ? "" : ip_addr);

        if (dup_ip_addr == NULL)
        {
            g_free(username);
            auth_end(auth_info);
            status = E_SCP_LOGIN_NO_MEMORY;
        }
        else
        {
            LOG(LOG_LEVEL_INFO,
                "Access permitted for user: %s (Broker-RDP Handle login)",
                username);
            login_info->uid = uid;
            login_info->username = username;
            login_info->ip_addr = dup_ip_addr;
            login_info->auth_info = auth_info;
        }
    }
    else
    {
        log_authfail_message(supplied_username, ip_addr);
        g_free(username);
    }
    return status;
}
#endif /* ENABLE_BROKER_AUTH */

/******************************************************************************/
/**
 * Authenticate and authorize the connection
 *
 * @param supplied_username Name for user
 * @param password Password
 * @param ip_addr Remote IP address
 * @param login_info Structure to fill in for a successful login
 * @return Status for the operation
 *
 * @post If E_SCP_LOGIN_OK is returned, g_login_info is filled in
 */
static enum scp_login_status
authenticate_and_authorize_connection(const char *supplied_username,
                                      const char *password,
                                      const char *ip_addr,
                                      struct login_info *login_info)
{
    int uid;
    char *username; // From reverse-looking up the UID
    enum scp_login_status status;
    struct auth_info *auth_info;
    unsigned int start_time = g_get_elapsed_ms();

#if defined(ENABLE_BROKER_AUTH)
    if (password_is_otc_handle(password) &&
            baf_runtime_config_validate_mode_c(&g_cfg->baf) ==
            BAF_RUNTIME_CONFIG_OK)
    {
        /* Handle-shaped secrets are consumed by Broker-RDP Handle exclusively and
         * never reach the PAM password stack or retry as a password. */
        status = mode_c_authenticate(supplied_username, password, ip_addr,
                                     login_info);
    }
    else
#endif
        if (g_getuser_info_by_name(supplied_username,
                                   &uid, NULL, NULL, NULL, NULL) != 0)
        {
            /* we can't get a UID for the user */
            LOG(LOG_LEVEL_ERROR, "Can't get UID for user %s",
                supplied_username);
            log_authfail_message(supplied_username, ip_addr);
            status = E_SCP_LOGIN_NOT_AUTHENTICATED;

            /* Call the auth stack anyway. On some systems (e.g. linux-pam),
             * a fixed delay is built in to the stack for an unsuccessful
             * login, and this delay may exceed FAILED_LOGIN_CONSTANT_TIME */
            auth_end(auth_userpass(supplied_username, password, ip_addr, NULL));
        }
        else if (g_getuser_info_by_uid(uid,
                                       &username,
                                       NULL, NULL, NULL, NULL) != 0)
        {
            LOG(LOG_LEVEL_ERROR, "Can't reverse lookup UID %d", uid);
            status = E_SCP_LOGIN_NOT_AUTHENTICATED;
            auth_end(auth_userpass(supplied_username, password, ip_addr, NULL));
        }
        else
        {
            if (g_strcmp(username, supplied_username) != 0)
            {
                /*
                 * If using a federated naming service (e.g. AD), the username
                 * supplied may not match that name mapped to by the UID. We
                 * will generate a warning in this instance so the user can see
                 * what is being used
                 */
                LOG(LOG_LEVEL_WARNING,
                    "Using username %s for the session (from UID %d)",
                    username, uid);
            }

            auth_info = auth_userpass(username, password, ip_addr, &status);

            /* Sanity check on result of call */
            if ((auth_info != NULL && status != E_SCP_LOGIN_OK) ||
                    (auth_info == NULL && status == E_SCP_LOGIN_OK))
            {
                LOG(LOG_LEVEL_ERROR, "Bugcheck; inconsistent auth result. "
                    "info = %p, status = %d", (void *)auth_info, (int)status);
                status = E_SCP_LOGIN_GENERAL_ERROR;
                auth_end(auth_info);
                auth_info = NULL;
            }

            /* Group access allowed? */
            if (status == E_SCP_LOGIN_OK &&
                    !access_login_allowed(&g_cfg->sec, username))
            {
                LOG(LOG_LEVEL_INFO, "Username okay but group problem for "
                    "user: %s", username);
                status = E_SCP_LOGIN_NOT_AUTHORIZED;
                auth_end(auth_info);
                auth_info = NULL;
            }

            switch (status)
            {
                case E_SCP_LOGIN_OK:
                {
                    char *dup_username = g_strdup(username);
                    char *dup_ip_addr = g_strdup(ip_addr);

                    if (dup_username == NULL || dup_ip_addr == NULL)
                    {
                        LOG(LOG_LEVEL_ERROR, "%s : Memory allocation failed",
                            __func__);
                        g_free(dup_username);
                        g_free(dup_ip_addr);
                        status = E_SCP_LOGIN_NO_MEMORY;
                        auth_end(auth_info);
                        auth_info = NULL;
                    }
                    else
                    {
                        LOG(LOG_LEVEL_INFO, "Access permitted for user: %s",
                            username);
                        login_info->uid = uid;
                        login_info->username = dup_username;
                        login_info->ip_addr = dup_ip_addr;
                        login_info->auth_info = auth_info;
                    }
                }
                break;

                case E_SCP_LOGIN_NOT_AUTHENTICATED:
                    log_authfail_message(username, ip_addr);
                    break;

                default:
                    break;
            }

            g_free(username);
        }

    if (status != E_SCP_LOGIN_OK)
    {
        unsigned int elapsed_ms = g_get_elapsed_ms() - start_time;
        if (elapsed_ms < FAILED_LOGIN_CONSTANT_TIME)
        {
            g_sleep(FAILED_LOGIN_CONSTANT_TIME - elapsed_ms);
        }
    }
    return status;
}

/******************************************************************************/
static int
get_scp_client_retry(struct trans *scp_trans,
                     const char **username, const char **password,
                     const char **ip_addr)
{
    int got_message = 0;

    // Wait for an SCP message
    enum scp_msg_code msgno;

    scp_msg_in_reset(scp_trans);

    if (scp_msg_in_wait_available(scp_trans) == 0)
    {
        msgno = scp_msg_in_get_msgno(scp_trans);
        switch (msgno)
        {
            case E_SCP_SYS_LOGIN_REQUEST:
                if (scp_get_sys_login_request(scp_trans, username,
                                              password, ip_addr) == 0)
                {
                    got_message = 1;
                }
                break;

            case E_SCP_CLOSE_CONNECTION_REQUEST:
                break;

            default:
            {
                char buff[64];
                scp_msgno_to_str(msgno, buff, sizeof(buff));
                LOG(LOG_LEVEL_ERROR, "unexpected message %s from SCP client",
                    buff);
            }
            break;
        }
    }

    return got_message;
}

/******************************************************************************/
struct login_info *
login_info_sys_login_user(struct trans *scp_trans,
                          const char *username,
                          const char *password,
                          const char *ip_addr)
{
    struct login_info *result;
    enum scp_login_status status = E_SCP_LOGIN_GENERAL_ERROR;
    int server_closed = 0;

    if ((result = g_new0(struct login_info, 1)) == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Allocation failure logging in user");
    }
    else
    {
        int first_time = 1;
        unsigned int retry_count = g_cfg->sec.login_retry;

        result->uid = (uid_t) -1;

        while (status != E_SCP_LOGIN_OK && !server_closed)
        {
            // First time round, we have credentials supplied by the
            // caller. On subsequent trips, we have to wait for the
            // SCP client to send us more.
            if (first_time)
            {
                first_time = 0;
            }
            else if (!get_scp_client_retry(scp_trans, &username,
                                           &password, &ip_addr))
            {
                status = E_SCP_LOGIN_GENERAL_ERROR;
                break;
            }

            status = authenticate_and_authorize_connection(username,
                     password,
                     ip_addr,
                     result);

            if (status != E_SCP_LOGIN_OK)
            {
                if (retry_count > 0)
                {
                    --retry_count;
                }
                else
                {
                    server_closed = 1;
                }
            }

            if (scp_send_login_response(scp_trans, status,
                                        server_closed, result->uid) != 0)
            {
                status = E_SCP_LOGIN_GENERAL_ERROR;
                break;
            }
        }
    }

    if (status != E_SCP_LOGIN_OK)
    {
        login_info_free(result);
        result = NULL;
    }

    return result;
}

/******************************************************************************/
struct login_info *
login_info_uds_login_user(struct trans *scp_trans)
{
    struct login_info *result;
    int uid; // Needed as g_sck_get_peer_cred() doesn't use uid_t

    // Allocate a struct for the result, with the IP address set to ""
    if ((result = g_new0(struct login_info, 1)) == NULL ||
            (result->ip_addr = g_new0(char, 1)) == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Allocation failure logging in user");
    }
    else if (g_sck_get_peer_cred(scp_trans->sck, NULL, &uid, NULL) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "Unable to get peer credentials for SCP socket");
    }
    else if (g_getuser_info_by_uid(uid, &result->username,
                                   NULL, NULL, NULL, NULL) != 0)
    {
        LOG(LOG_LEVEL_ERROR, "Can't reverse lookup UID %d", result->uid);
    }
    else if ((result->auth_info = auth_uds(result->username, NULL)) == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Can't authorize user %s over UDS",
            result->username);
    }
    else if (!access_login_allowed(&g_cfg->sec, result->username))
    {
        LOG(LOG_LEVEL_ERROR, "Access denied for user %s by your system admin",
            result->username);
    }
    else
    {
        result->uid = (uid_t)uid;
        return result;
    }

    login_info_free(result);
    return NULL;
}


#if defined(ENABLE_BROKER_AUTH)
/******************************************************************************/
struct login_info *
login_info_baf_preauth_user(struct trans *scp_trans,
                            unsigned short credential_kind,
                            const unsigned char *assertion,
                            unsigned int assertion_length,
                            const char *client_address,
                            const char *server_nonce)
{
    struct login_info *result = NULL;
    enum scp_login_status login_status = E_SCP_LOGIN_GENERAL_ERROR;
    uid_t uid = (uid_t) -1;
    char *username = NULL;
    struct auth_info *auth_info = NULL;

    if (credential_kind == SCP_BROKER_CREDENTIAL_HANDLE)
    {
        /* Broker-RDP Handle routing-token ingress: the credential is a single-use
         * handle; the assertion is recovered server-side. */
        char handle[BAF_HANDLE_TEXT_LENGTH + 1];
        unsigned char *resolved = NULL;
        size_t resolved_length = 0;

        if (baf_runtime_config_validate_mode_c(&g_cfg->baf) !=
                BAF_RUNTIME_CONFIG_OK)
        {
            LOG(LOG_LEVEL_WARNING,
                "Broker-RDP Handle preauth rejected because trusted Broker-RDP Handle config "
                "is disabled");
            login_status = E_SCP_LOGIN_NOT_AUTHORIZED;
        }
        else if (assertion_length != BAF_HANDLE_TEXT_LENGTH)
        {
            login_status = E_SCP_LOGIN_NOT_AUTHENTICATED;
        }
        else
        {
            g_memcpy(handle, assertion, BAF_HANDLE_TEXT_LENGTH);
            handle[BAF_HANDLE_TEXT_LENGTH] = '\0';
            if (modec_resolve_handle(handle, &resolved,
                                     &resolved_length) != BAF_HANDLE_OK)
            {
                LOG(LOG_LEVEL_WARNING,
                    "Broker-RDP Handle preauth handle rejected by handle service");
                log_authfail_message("<baf-mode-c>", client_address);
                login_status = E_SCP_LOGIN_NOT_AUTHENTICATED;
            }
            else
            {
                login_status = baf_authorize_assertion(
                                   resolved,
                                   (unsigned int)resolved_length,
                                   client_address, NULL, 0, NULL,
                                   &uid, &username, &auth_info);
                baf_handle_assertion_free(resolved, resolved_length);
            }
            secure_erase_bytes(handle, sizeof(handle));
        }
    }
    else if (baf_runtime_config_validate_live(&g_cfg->baf) !=
             BAF_RUNTIME_CONFIG_OK)
    {
        LOG(LOG_LEVEL_WARNING,
            "BAF preauth rejected because trusted live config is disabled");
        login_status = E_SCP_LOGIN_NOT_AUTHORIZED;
    }
    else
    {
        login_status = baf_authorize_assertion(
                           assertion, assertion_length, client_address,
                           server_nonce, g_cfg->baf.require_nonce_binding,
                           NULL, &uid, &username, &auth_info);
    }

    if (login_status == E_SCP_LOGIN_OK)
    {
        result = g_new0(struct login_info, 1);
        if (result == NULL)
        {
            login_status = E_SCP_LOGIN_NO_MEMORY;
        }
        else
        {
            result->uid = uid;
            result->username = username;
            username = NULL;
            result->ip_addr =
                g_strdup(client_address == NULL ? "" : client_address);
            result->auth_info = auth_info;
            auth_info = NULL;
            if (result->ip_addr == NULL)
            {
                login_status = E_SCP_LOGIN_NO_MEMORY;
                login_info_free(result);
                result = NULL;
            }
        }
    }

    (void)scp_send_login_response(scp_trans, login_status,
                                  login_status == E_SCP_LOGIN_OK ? 0 : 1,
                                  result == NULL ? (uid_t) -1 : result->uid);
    auth_end(auth_info);
    g_free(username);
    return result;
}
#endif


/******************************************************************************/
void
login_info_free(struct login_info *self)
{
    if (self != NULL)
    {
        g_free(self->username);
        g_free(self->ip_addr);
        if (self->auth_info != NULL)
        {
            auth_end(self->auth_info);
        }
        g_free(self);
    }
}
