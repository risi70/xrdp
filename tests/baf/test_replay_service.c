#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "replay_cache.h"
#include "replay_cache_service.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 24

static int failures;

#define CHECK(condition, message) \
    do { if (!(condition)) { fprintf(stderr, "FAIL: %s\n", message); ++failures; } } while (0)

static void
make_key(unsigned char key[REPLAY_CACHE_KEY_SIZE], unsigned char value)
{
    memset(key, value, REPLAY_CACHE_KEY_SIZE);
}

static int
wait_ready(const char *path)
{
    int i;
    for (i = 0; i < 100; ++i)
    {
        if (replay_cache_service_request(path, 100, BAF_REPLAY_OP_PING,
                                         NULL, 0, NULL) == REPLAY_CACHE_OK)
        {
            return 1;
        }
        usleep(10000);
    }
    return 0;
}

static void
test_concurrent_same_key(const char *path)
{
    unsigned char key[REPLAY_CACHE_KEY_SIZE];
    pid_t pids[WORKERS];
    int i;
    int success = 0;
    int replay = 0;
    make_key(key, 0x41);
    for (i = 0; i < WORKERS; ++i)
    {
        pids[i] = fork();
        if (pids[i] == 0)
        {
            struct replay_cache *cache = replay_cache_service_create(path, 1000);
            enum replay_cache_status status = replay_cache_reserve(
                    cache, key, (int64_t)time(NULL) + 60,
                    (int64_t)time(NULL));
            replay_cache_free(cache);
            _exit(status == REPLAY_CACHE_OK ? 0 :
                  status == REPLAY_CACHE_EXISTS ? 10 : 20);
        }
        CHECK(pids[i] > 0, "fork worker");
    }
    for (i = 0; i < WORKERS; ++i)
    {
        int status = 0;
        if (pids[i] > 0 && waitpid(pids[i], &status, 0) == pids[i] &&
                WIFEXITED(status))
        {
            if (WEXITSTATUS(status) == 0)
            {
                ++success;
            }
            else if (WEXITSTATUS(status) == 10)
            {
                ++replay;
            }
        }
    }
    CHECK(success == 1, "exactly one cross-process reservation succeeds");
    CHECK(replay == WORKERS - 1, "all other workers receive replay");
}

static void
test_lifecycle(const char *path)
{
    struct replay_cache *cache = replay_cache_service_create(path, 1000);
    unsigned char key[REPLAY_CACHE_KEY_SIZE];
    unsigned char other[REPLAY_CACHE_KEY_SIZE];
    int64_t now = (int64_t)time(NULL);
    make_key(key, 0x52);
    make_key(other, 0x53);
    CHECK(cache != NULL, "create service replay backend");
    CHECK(replay_cache_reserve(cache, key, now + 60, now) == REPLAY_CACHE_OK,
          "reserve first distinct key");
    CHECK(replay_cache_reserve(cache, other, now + 60, now) == REPLAY_CACHE_OK,
          "reserve second distinct key");
    CHECK(replay_cache_release(cache, key, now) == REPLAY_CACHE_OK,
          "mark key released");
    CHECK(replay_cache_reserve(cache, key, now + 60, now) == REPLAY_CACHE_EXISTS,
          "released key remains unavailable");
    make_key(key, 0x54);
    CHECK(replay_cache_reserve(cache, key, now + 1, now) == REPLAY_CACHE_OK,
          "reserve short-lived key");
    sleep(2);
    now = (int64_t)time(NULL);
    CHECK(replay_cache_reserve(cache, key, now + 60, now) == REPLAY_CACHE_OK,
          "expired key is cleaned and may be reserved anew");
    replay_cache_free(cache);
}

static int
connect_raw(const char *path)
{
    struct sockaddr_un address;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0)
    {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path))
    {
        close(fd);
        return -1;
    }
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static void
test_malformed(const char *path)
{
    unsigned char oversized[BAF_REPLAY_REQUEST_SIZE + 1];
    struct baf_replay_response response;
    int fd = connect_raw(path);
    memset(oversized, 0xa5, sizeof(oversized));
    CHECK(fd >= 0, "connect malformed request client");
    if (fd >= 0)
    {
        CHECK(send(fd, oversized, sizeof(oversized), 0) ==
              (ssize_t)sizeof(oversized), "send oversized request");
        CHECK(recv(fd, &response, sizeof(response), 0) ==
              (ssize_t)sizeof(response), "receive malformed response");
        CHECK(baf_replay_get_u32(response.result) ==
              BAF_REPLAY_RESULT_BAD_REQUEST, "oversized request rejected");
        close(fd);
    }
}

int
main(void)
{
    char path[96];
    pid_t server;
    struct replay_cache *unavailable;
    unsigned char key[REPLAY_CACHE_KEY_SIZE];
    snprintf(path, sizeof(path), "/tmp/xrdp-baf-replay-%ld.sock",
             (long)getpid());
    unlink(path);
    server = fork();
    if (server == 0)
    {
        _exit(baf_replay_service_run(path, 256, 120));
    }
    CHECK(server > 0, "fork replay service");
    CHECK(wait_ready(path), "replay service ready");
    if (server > 0 && wait_ready(path))
    {
        test_concurrent_same_key(path);
        test_lifecycle(path);
        test_malformed(path);
    }
    if (server > 0)
    {
        kill(server, SIGTERM);
        waitpid(server, NULL, 0);
    }
    unlink(path);
    unavailable = replay_cache_service_create(path, 100);
    make_key(key, 0x71);
    CHECK(replay_cache_reserve(unavailable, key,
                              (int64_t)time(NULL) + 60,
                              (int64_t)time(NULL)) == REPLAY_CACHE_UNAVAILABLE,
          "unavailable service fails closed");
    replay_cache_free(unavailable);
    return failures == 0 ? 0 : 1;
}
