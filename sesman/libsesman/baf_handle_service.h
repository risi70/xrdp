#ifndef BAF_HANDLE_SERVICE_H
#define BAF_HANDLE_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#define BAF_HANDLE_DEFAULT_SOCKET XRDP_SOCKET_ROOT_PATH "/baf-handle.sock"
#define BAF_HANDLE_BYTES 32
#define BAF_HANDLE_TEXT_LENGTH 64
#define BAF_HANDLE_MAX_ASSERTION 16384
#define BAF_HANDLE_MAX_TARGET 255
#define BAF_HANDLE_DEFAULT_CAPACITY 1024
#define BAF_HANDLE_DEFAULT_MAX_TTL 120
enum baf_handle_status { BAF_HANDLE_OK, BAF_HANDLE_NOT_FOUND, BAF_HANDLE_EXPIRED,
                         BAF_HANDLE_CONSUMED, BAF_HANDLE_TARGET_MISMATCH, BAF_HANDLE_BAD_REQUEST,
                         BAF_HANDLE_CAPACITY, BAF_HANDLE_UNAVAILABLE, BAF_HANDLE_ERROR
                       };
enum baf_handle_status baf_handle_store(const char *, int, const unsigned char *, size_t, int64_t, const char *, char [BAF_HANDLE_TEXT_LENGTH + 1]);
enum baf_handle_status baf_handle_resolve_and_consume(const char *, int, const char *, const char *, unsigned char **, size_t *);
enum baf_handle_status baf_handle_ping(const char *, int);
enum baf_handle_status baf_handle_cleanup_expired(const char *, int, uint32_t *);
void baf_handle_assertion_free(unsigned char *, size_t);
int baf_handle_service_run(const char *, size_t, int64_t);
#endif
