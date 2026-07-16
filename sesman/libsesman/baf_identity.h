#ifndef BAF_IDENTITY_H
#define BAF_IDENTITY_H
#include <stddef.h>
#include <sys/types.h>
#include "auth_provider.h"
#include "scp_application_types.h"
struct auth_info;
#define BAF_IDENTITY_MAX_USERNAME_BYTES 255U
enum baf_identity_status
{
    BAF_IDENTITY_SUCCESS = 0,
    BAF_IDENTITY_INVALID_CAPABILITY,
    BAF_IDENTITY_INVALID_USERNAME,
    BAF_IDENTITY_NOT_FOUND,
    BAF_IDENTITY_AMBIGUOUS,
    BAF_IDENTITY_UID0_REJECTED,
    BAF_IDENTITY_NSS_UNAVAILABLE,
    BAF_IDENTITY_PAM_DENIED,
    BAF_IDENTITY_INTERNAL_ERROR
};
enum baf_nss_status
{
    BAF_NSS_SUCCESS = 0,
    BAF_NSS_NOT_FOUND,
    BAF_NSS_AMBIGUOUS,
    BAF_NSS_UNAVAILABLE
};
struct baf_nss_record
{
    const char *canonical_username;
    uid_t uid;
    gid_t primary_gid;
    const char *home_directory;
    const char *shell;
    void *storage;
};
typedef enum baf_nss_status (*baf_nss_lookup_fn)(const char *username,
        void *userdata,
        struct baf_nss_record *record);
struct baf_identity_options
{
    int allow_uid0;
    size_t max_username_bytes;
};
struct baf_resolved_identity;
int baf_identity_username_is_safe(const char *username, size_t maximum);
enum baf_identity_status
baf_identity_bind(const struct auth_provider_result *capability,
                  const struct baf_identity_options *options,
                  baf_nss_lookup_fn lookup,
                  void *lookup_userdata,
                  struct baf_resolved_identity **identity);
enum baf_identity_status
baf_identity_bind_and_authorize(const struct auth_provider_result *capability,
                                const struct baf_identity_options *options,
                                baf_nss_lookup_fn lookup,
                                void *lookup_userdata,
                                const char *client_address,
                                struct baf_resolved_identity **identity,
                                struct auth_info **auth_info,
                                enum scp_login_status *login_status);
enum baf_nss_status baf_nss_lookup_system(const char *username,
        void *userdata,
        struct baf_nss_record *record);
const char *baf_resolved_identity_get_username(const struct baf_resolved_identity *identity);
uid_t baf_resolved_identity_get_uid(const struct baf_resolved_identity *identity);
gid_t baf_resolved_identity_get_primary_gid(const struct baf_resolved_identity *identity);
const char *baf_resolved_identity_get_home(const struct baf_resolved_identity *identity);
const char *baf_resolved_identity_get_shell(const struct baf_resolved_identity *identity);
void baf_resolved_identity_free(struct baf_resolved_identity *identity);
enum baf_nss_status baf_resolved_identity_get_nss_status(const struct baf_resolved_identity *identity);
#endif
