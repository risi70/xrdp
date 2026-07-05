#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "baf_identity.h"
#include "sesman_auth.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(ENABLE_BROKER_AUTH)
#error "baf_identity.c must only be built with broker auth enabled"
#endif
struct baf_resolved_identity
{
    char *canonical_username;
    uid_t uid;
    gid_t primary_gid;
    char *home_directory;
    char *shell;
    enum baf_nss_status nss_status;
};
static char *copy_string(const char *value)
{
    size_t length;
    char *copy;
    if (value == NULL)
    {
        value = "";
    }
    length = strlen(value);
    copy = malloc(length + 1);
    if (copy != NULL)
    {
        memcpy(copy, value, length + 1);
    }
    return copy;
}
int baf_identity_username_is_safe(const char *username, size_t maximum)
{
    const unsigned char *p = (const unsigned char *)username;
    size_t length;
    if (username == NULL || maximum == 0 || username[0] == '\0')
    {
        return 0;
    }
    length = strlen(username);
    if (length > maximum)
    {
        return 0;
    }
    while (*p != '\0')
    {
        if (*p == '/' || iscntrl(*p) || isspace(*p))
        {
            return 0;
        }
        ++p;
    }
    return 1;
}
static void release_record(struct baf_nss_record *record)
{
    free(record->storage);
    memset(record, 0, sizeof(*record));
}
enum baf_nss_status baf_nss_lookup_system(const char *username,
                                          void *userdata,
                                          struct baf_nss_record *record)
{
    long configured = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buffer_size = configured > 0 ? (size_t)configured : 16384U;
    char *buffer = NULL;
    char *reverse_buffer = NULL;
    struct passwd pwd;
    struct passwd reverse_pwd;
    struct passwd *result = NULL;
    struct passwd *reverse_result = NULL;
    enum baf_nss_status status = BAF_NSS_UNAVAILABLE;
    int error;
    size_t name_length;
    size_t home_length;
    size_t shell_length;
    char *storage;
    (void)userdata;
    memset(record, 0, sizeof(*record));
    if (buffer_size > 1024U * 1024U)
    {
        buffer_size = 1024U * 1024U;
    }
    buffer = malloc(buffer_size);
    reverse_buffer = malloc(buffer_size);
    if (buffer == NULL || reverse_buffer == NULL)
    {
        goto done;
    }
    error = getpwnam_r(username, &pwd, buffer, buffer_size, &result);
    if (error == 0 && result == NULL)
    {
        status = BAF_NSS_NOT_FOUND;
        goto done;
    }
    if (error != 0)
    {
        goto done;
    }
    error = getpwuid_r(pwd.pw_uid, &reverse_pwd, reverse_buffer,
                       buffer_size, &reverse_result);
    if (error != 0 || reverse_result == NULL ||
            reverse_pwd.pw_uid != pwd.pw_uid)
    {
        goto done;
    }
    name_length = strlen(reverse_pwd.pw_name) + 1;
    home_length = strlen(reverse_pwd.pw_dir == NULL ? "" : reverse_pwd.pw_dir) + 1;
    shell_length = strlen(reverse_pwd.pw_shell == NULL ? "" : reverse_pwd.pw_shell) + 1;
    storage = malloc(name_length + home_length + shell_length);
    if (storage == NULL)
    {
        goto done;
    }
    memcpy(storage, reverse_pwd.pw_name, name_length);
    memcpy(storage + name_length,
           reverse_pwd.pw_dir == NULL ? "" : reverse_pwd.pw_dir, home_length);
    memcpy(storage + name_length + home_length,
           reverse_pwd.pw_shell == NULL ? "" : reverse_pwd.pw_shell, shell_length);
    record->canonical_username = storage;
    record->home_directory = storage + name_length;
    record->shell = storage + name_length + home_length;
    record->uid = reverse_pwd.pw_uid;
    record->primary_gid = reverse_pwd.pw_gid;
    record->storage = storage;
    status = BAF_NSS_SUCCESS;
done:
    free(buffer);
    free(reverse_buffer);
    return status;
}
enum baf_identity_status
baf_identity_bind(const struct auth_provider_result *capability,
                  const struct baf_identity_options *options,
                  baf_nss_lookup_fn lookup,
                  void *lookup_userdata,
                  struct baf_resolved_identity **identity)
{
    const struct auth_prevalidated_identity *claims;
    const char *username;
    size_t maximum;
    struct baf_nss_record record;
    enum baf_nss_status nss_status;
    struct baf_resolved_identity *resolved;
    if (identity == NULL)
    {
        return BAF_IDENTITY_INTERNAL_ERROR;
    }
    *identity = NULL;
    claims = auth_provider_result_get_identity(capability);
    if (claims == NULL)
    {
        return BAF_IDENTITY_INVALID_CAPABILITY;
    }
    username = auth_prevalidated_identity_get_preferred_username(claims);
    maximum = options == NULL || options->max_username_bytes == 0 ?
              BAF_IDENTITY_MAX_USERNAME_BYTES : options->max_username_bytes;
    if (!baf_identity_username_is_safe(username, maximum))
    {
        return BAF_IDENTITY_INVALID_USERNAME;
    }
    if (lookup == NULL)
    {
        lookup = baf_nss_lookup_system;
    }
    memset(&record, 0, sizeof(record));
    nss_status = lookup(username, lookup_userdata, &record);
    if (nss_status != BAF_NSS_SUCCESS)
    {
        release_record(&record);
        return nss_status == BAF_NSS_NOT_FOUND ? BAF_IDENTITY_NOT_FOUND :
               nss_status == BAF_NSS_AMBIGUOUS ? BAF_IDENTITY_AMBIGUOUS :
               BAF_IDENTITY_NSS_UNAVAILABLE;
    }
    if (!baf_identity_username_is_safe(record.canonical_username, maximum))
    {
        release_record(&record);
        return BAF_IDENTITY_AMBIGUOUS;
    }
    if (record.uid == (uid_t)-1 || record.primary_gid == (gid_t)-1)
    {
        release_record(&record);
        return BAF_IDENTITY_AMBIGUOUS;
    }
    if ((options == NULL || !options->allow_uid0) && record.uid == 0)
    {
        release_record(&record);
        return BAF_IDENTITY_UID0_REJECTED;
    }
    resolved = calloc(1, sizeof(*resolved));
    if (resolved == NULL)
    {
        release_record(&record);
        return BAF_IDENTITY_INTERNAL_ERROR;
    }
    resolved->canonical_username = copy_string(record.canonical_username);
    resolved->home_directory = copy_string(record.home_directory);
    resolved->shell = copy_string(record.shell);
    resolved->uid = record.uid;
    resolved->primary_gid = record.primary_gid;
    resolved->nss_status = BAF_NSS_SUCCESS;
    release_record(&record);
    if (resolved->canonical_username == NULL || resolved->home_directory == NULL ||
            resolved->shell == NULL)
    {
        baf_resolved_identity_free(resolved);
        return BAF_IDENTITY_INTERNAL_ERROR;
    }
    *identity = resolved;
    return BAF_IDENTITY_SUCCESS;
}
const char *baf_resolved_identity_get_username(const struct baf_resolved_identity *i)
{ return i == NULL ? NULL : i->canonical_username; }
uid_t baf_resolved_identity_get_uid(const struct baf_resolved_identity *i)
{ return i == NULL ? (uid_t)-1 : i->uid; }
gid_t baf_resolved_identity_get_primary_gid(const struct baf_resolved_identity *i)
{ return i == NULL ? (gid_t)-1 : i->primary_gid; }
const char *baf_resolved_identity_get_home(const struct baf_resolved_identity *i)
{ return i == NULL ? NULL : i->home_directory; }
const char *baf_resolved_identity_get_shell(const struct baf_resolved_identity *i)
{ return i == NULL ? NULL : i->shell; }
void baf_resolved_identity_free(struct baf_resolved_identity *identity)
{
    if (identity != NULL)
    {
        free(identity->canonical_username);
        free(identity->home_directory);
        free(identity->shell);
        free(identity);
    }
}
enum baf_nss_status baf_resolved_identity_get_nss_status(const struct baf_resolved_identity *i)
{ return i == NULL ? BAF_NSS_UNAVAILABLE : i->nss_status; }
