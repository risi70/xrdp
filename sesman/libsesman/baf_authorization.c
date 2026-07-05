#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "baf_identity.h"
#include "sesman_auth.h"
#if !defined(ENABLE_BROKER_AUTH)
#error "baf_authorization.c must only be built with broker auth enabled"
#endif
enum baf_identity_status
baf_identity_bind_and_authorize(const struct auth_provider_result *capability,
                                const struct baf_identity_options *options,
                                baf_nss_lookup_fn lookup,
                                void *lookup_userdata,
                                const char *client_address,
                                struct baf_resolved_identity **identity,
                                struct auth_info **auth_info,
                                enum scp_login_status *login_status)
{
    enum baf_identity_status status;
    enum scp_login_status local_login_status = E_SCP_LOGIN_GENERAL_ERROR;
    if (identity == NULL || auth_info == NULL)
    {
        return BAF_IDENTITY_INTERNAL_ERROR;
    }
    *identity = NULL;
    *auth_info = NULL;
    status = baf_identity_bind(capability, options, lookup, lookup_userdata,
                               identity);
    if (status == BAF_IDENTITY_SUCCESS)
    {
        *auth_info = auth_prevalidated_broker(
                         baf_resolved_identity_get_username(*identity),
                         client_address, &local_login_status);
        if (*auth_info == NULL || local_login_status != E_SCP_LOGIN_OK)
        {
            auth_end(*auth_info);
            *auth_info = NULL;
            baf_resolved_identity_free(*identity);
            *identity = NULL;
            status = BAF_IDENTITY_PAM_DENIED;
        }
    }
    if (login_status != NULL)
    {
        *login_status = local_login_status;
    }
    return status;
}
