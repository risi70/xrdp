#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "replay_cache_service.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

_Static_assert(sizeof(struct baf_replay_request) == BAF_REPLAY_REQUEST_SIZE,
               "replay request wire size");
_Static_assert(sizeof(struct baf_replay_response) == BAF_REPLAY_RESPONSE_SIZE,
               "replay response wire size");

static int
socket_address(const char *path, struct sockaddr_un *address)
{
    size_t length;
    if (path == NULL || address == NULL || path[0] == '\0')
    {
        return -1;
    }
    length = strlen(path);
    if (length >= sizeof(address->sun_path))
    {
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, length + 1);
    return 0;
}

static int
connect_service(const char *path, int timeout_ms)
{
    struct sockaddr_un address;
    struct timeval timeout;
    int fd;
    if (socket_address(path, &address) != 0 || timeout_ms <= 0)
    {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0)
    {
        return -1;
    }
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       sizeof(timeout)) != 0 ||
            connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static enum replay_cache_status
map_result(uint32_t result)
{
    switch (result)
    {
        case BAF_REPLAY_RESULT_OK_RESERVED:
                case BAF_REPLAY_RESULT_OK:
                        return REPLAY_CACHE_OK;
        case BAF_REPLAY_RESULT_REPLAY:
            return REPLAY_CACHE_EXISTS;
        case BAF_REPLAY_RESULT_NOT_FOUND:
            return REPLAY_CACHE_NOT_FOUND;
        case BAF_REPLAY_RESULT_CAPACITY:
            return REPLAY_CACHE_FULL;
        case BAF_REPLAY_RESULT_UNAVAILABLE:
            return REPLAY_CACHE_UNAVAILABLE;
        default:
            return REPLAY_CACHE_ERROR;
    }
}

enum replay_cache_status
replay_cache_service_request(const char *socket_path, int timeout_ms,
                             enum baf_replay_operation operation,
                             const unsigned char key[REPLAY_CACHE_KEY_SIZE],
                             int64_t expires_at,
                             enum replay_cache_state *state)
{
    struct baf_replay_request request;
    struct baf_replay_response response;
    ssize_t size;
    int fd;

    if (operation < BAF_REPLAY_OP_RESERVE || operation > BAF_REPLAY_OP_PING ||
            ((operation == BAF_REPLAY_OP_RESERVE ||
              operation == BAF_REPLAY_OP_MARK_CONSUMED ||
              operation == BAF_REPLAY_OP_MARK_RELEASED ||
              operation == BAF_REPLAY_OP_STATUS) && key == NULL))
    {
        return REPLAY_CACHE_ERROR;
    }
    memset(&request, 0, sizeof(request));
    baf_replay_put_u16(request.version, BAF_REPLAY_PROTOCOL_VERSION);
    baf_replay_put_u16(request.operation, (uint16_t)operation);
    baf_replay_put_u32(request.length, sizeof(request));
    if (key != NULL)
    {
        memcpy(request.key, key, REPLAY_CACHE_KEY_SIZE);
    }
    baf_replay_put_i64(request.expires_at, expires_at);

    fd = connect_service(socket_path, timeout_ms);
    if (fd < 0)
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    size = send(fd, &request, sizeof(request), MSG_NOSIGNAL);
    if (size == (ssize_t)sizeof(request))
    {
        size = recv(fd, &response, sizeof(response), 0);
    }
    close(fd);
    memset(&request, 0, sizeof(request));
    if (size != (ssize_t)sizeof(response) ||
            baf_replay_get_u16(response.version) != BAF_REPLAY_PROTOCOL_VERSION ||
            baf_replay_get_u16(response.operation) != (uint16_t)operation ||
            baf_replay_get_u32(response.length) != sizeof(response))
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    if (baf_replay_get_u32(response.state) > REPLAY_CACHE_RELEASED)
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    if (state != NULL)
    {
        *state = (enum replay_cache_state)baf_replay_get_u32(response.state);
    }
    return map_result(baf_replay_get_u32(response.result));
}

static uint32_t
map_cache_status(enum replay_cache_status status, int reserve)
{
    switch (status)
    {
        case REPLAY_CACHE_OK:
            return reserve ? BAF_REPLAY_RESULT_OK_RESERVED : BAF_REPLAY_RESULT_OK;
        case REPLAY_CACHE_EXISTS:
            return BAF_REPLAY_RESULT_REPLAY;
        case REPLAY_CACHE_NOT_FOUND:
            return BAF_REPLAY_RESULT_NOT_FOUND;
        case REPLAY_CACHE_FULL:
            return BAF_REPLAY_RESULT_CAPACITY;
        case REPLAY_CACHE_UNAVAILABLE:
            return BAF_REPLAY_RESULT_UNAVAILABLE;
        default:
            return BAF_REPLAY_RESULT_INTERNAL;
    }
}

static int
key_is_zero(const unsigned char key[REPLAY_CACHE_KEY_SIZE])
{
    size_t i;
    unsigned char value = 0;
    for (i = 0; i < REPLAY_CACHE_KEY_SIZE; ++i)
    {
        value |= key[i];
    }
    return value == 0;
}

static void
make_response(struct baf_replay_response *response, uint16_t operation,
              uint32_t result, uint32_t state)
{
    memset(response, 0, sizeof(*response));
    baf_replay_put_u16(response->version, BAF_REPLAY_PROTOCOL_VERSION);
    baf_replay_put_u16(response->operation, operation);
    baf_replay_put_u32(response->length, sizeof(*response));
    baf_replay_put_u32(response->result, result);
    baf_replay_put_u32(response->state, state);
}

static void
handle_request(struct replay_cache *cache, int64_t max_ttl,
               const struct baf_replay_request *request,
               struct baf_replay_response *response)
{
    enum replay_cache_status status;
    enum replay_cache_state state = 0;
    uint16_t operation = baf_replay_get_u16(request->operation);
    int64_t expiry = baf_replay_get_i64(request->expires_at);
    int64_t now = (int64_t)time(NULL);
    uint32_t result = BAF_REPLAY_RESULT_BAD_REQUEST;

    if (baf_replay_get_u16(request->version) != BAF_REPLAY_PROTOCOL_VERSION ||
            baf_replay_get_u32(request->length) != sizeof(*request) ||
            operation < BAF_REPLAY_OP_RESERVE || operation > BAF_REPLAY_OP_PING)
    {
        make_response(response, operation, result, 0);
        return;
    }
    if (operation != BAF_REPLAY_OP_PING &&
            operation != BAF_REPLAY_OP_CLEANUP_EXPIRED &&
            key_is_zero(request->key))
    {
        make_response(response, operation, result, 0);
        return;
    }
    switch (operation)
    {
        case BAF_REPLAY_OP_RESERVE:
            if (expiry <= now)
            {
                result = BAF_REPLAY_RESULT_EXPIRED;
            }
            else if (expiry - now > max_ttl)
            {
                result = BAF_REPLAY_RESULT_BAD_REQUEST;
            }
            else
            {
                status = replay_cache_reserve(cache, request->key, expiry, now);
                result = map_cache_status(status, 1);
            }
            break;
        case BAF_REPLAY_OP_MARK_CONSUMED:
            status = replay_cache_consume(cache, request->key, now);
            result = map_cache_status(status, 0);
            break;
        case BAF_REPLAY_OP_MARK_RELEASED:
            status = replay_cache_release(cache, request->key, now);
            result = map_cache_status(status, 0);
            break;
        case BAF_REPLAY_OP_STATUS:
            status = replay_cache_get_state(cache, request->key, now, &state);
            result = map_cache_status(status, 0);
            break;
        case BAF_REPLAY_OP_CLEANUP_EXPIRED:
        case BAF_REPLAY_OP_PING:
            result = BAF_REPLAY_RESULT_OK;
            break;
        default:
            break;
    }
    make_response(response, operation, result, (uint32_t)state);
}

int
baf_replay_service_run(const char *socket_path, size_t capacity,
                       int64_t max_ttl_seconds)
{
    struct sockaddr_un address;
    struct replay_cache *cache = NULL;
    int listen_fd = -1;
    int result = 1;

    if (capacity == 0 || max_ttl_seconds <= 0 ||
            socket_address(socket_path, &address) != 0 ||
            (cache = replay_cache_memory_create(capacity)) == NULL ||
            (listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    {
        replay_cache_free(cache);
        return 1;
    }
    unlink(socket_path);
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            chmod(socket_path, 0660) != 0 || listen(listen_fd, 64) != 0)
    {
        goto done;
    }
    result = 0;
    for (;;)
    {
        struct baf_replay_request request;
        struct baf_replay_response response;
        int client_fd = accept(listen_fd, NULL, NULL);
        ssize_t size;
        uint16_t operation = 0;
        if (client_fd < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            result = 1;
            break;
        }
        size = recv(client_fd, &request, sizeof(request), MSG_TRUNC);
        if (size == (ssize_t)sizeof(request))
        {
            operation = baf_replay_get_u16(request.operation);
            handle_request(cache, max_ttl_seconds, &request, &response);
        }
        else
        {
            make_response(&response, operation,
                          BAF_REPLAY_RESULT_BAD_REQUEST, 0);
        }
        (void)send(client_fd, &response, sizeof(response), MSG_NOSIGNAL);
        memset(&request, 0, sizeof(request));
        close(client_fd);
    }

done:
    if (listen_fd >= 0)
    {
        close(listen_fd);
    }
    unlink(socket_path);
    replay_cache_free(cache);
    return result;
}
