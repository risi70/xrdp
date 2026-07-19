#include "replay_cache.h"

#include <assert.h>
#include <pthread.h>
#include <string.h>

struct worker
{
    struct replay_cache *cache;
    const unsigned char *key;
    enum replay_cache_status status;
};

static void *
reserve_once(void *argument)
{
    struct worker *worker = (struct worker *)argument;
    worker->status = replay_cache_reserve(worker->cache, worker->key,
                                          200, 100);
    return NULL;
}

int
main(void)
{
    struct replay_cache *cache = replay_cache_memory_create(1);
    unsigned char key1[REPLAY_CACHE_KEY_SIZE];
    unsigned char key2[REPLAY_CACHE_KEY_SIZE];
    enum replay_cache_state state;
    struct replay_cache *race_cache;
    struct worker workers[64];
    pthread_t threads[64];
    size_t i;
    int successes = 0;

    assert(cache != NULL);
    assert(replay_cache_make_key("https://issuer.test", "0123456789abcdef",
                                 key1) == REPLAY_CACHE_OK);
    assert(replay_cache_make_key("https://issuer.test", "fedcba9876543210",
                                 key2) == REPLAY_CACHE_OK);
    assert(memcmp(key1, key2, sizeof(key1)) != 0);
    assert(replay_cache_reserve(cache, key1, 110, 100) == REPLAY_CACHE_OK);
    assert(replay_cache_reserve(cache, key1, 110, 100) ==
           REPLAY_CACHE_EXISTS);
    assert(replay_cache_reserve(cache, key2, 110, 100) == REPLAY_CACHE_FULL);
    assert(replay_cache_consume(cache, key1, 100) == REPLAY_CACHE_OK);
    assert(replay_cache_get_state(cache, key1, 100, &state) ==
           REPLAY_CACHE_OK);
    assert(state == REPLAY_CACHE_CONSUMED);
    assert(replay_cache_release(cache, key1, 100) == REPLAY_CACHE_OK);
    assert(replay_cache_get_state(cache, key1, 100, &state) ==
           REPLAY_CACHE_OK);
    assert(state == REPLAY_CACHE_RELEASED);
    assert(replay_cache_reserve(cache, key1, 110, 100) ==
           REPLAY_CACHE_EXISTS);
    assert(replay_cache_get_state(cache, key1, 110, &state) ==
           REPLAY_CACHE_NOT_FOUND);
    assert(replay_cache_reserve(cache, key1, 120, 110) == REPLAY_CACHE_OK);
    assert(replay_cache_reserve(cache, key2, 120, 110) == REPLAY_CACHE_FULL);
    assert(replay_cache_reserve(NULL, key1, 120, 110) ==
           REPLAY_CACHE_UNAVAILABLE);
    replay_cache_free(cache);

    race_cache = replay_cache_memory_create(64);
    assert(race_cache != NULL);
    for (i = 0; i < 64; ++i)
    {
        workers[i].cache = race_cache;
        workers[i].key = key1;
        assert(pthread_create(&threads[i], NULL, reserve_once,
                              &workers[i]) == 0);
    }
    for (i = 0; i < 64; ++i)
    {
        assert(pthread_join(threads[i], NULL) == 0);
        if (workers[i].status == REPLAY_CACHE_OK)
        {
            ++successes;
        }
        else
        {
            assert(workers[i].status == REPLAY_CACHE_EXISTS);
        }
    }
    assert(successes == 1);
    replay_cache_free(race_cache);
    return 0;
}
