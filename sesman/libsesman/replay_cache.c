#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "replay_cache.h"
#include "replay_cache_service.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct replay_entry
{
    unsigned char key[REPLAY_CACHE_KEY_SIZE];
    int64_t expires_at;
    enum replay_cache_state state;
    int used;
};

struct replay_cache
{
    int backend;
    pthread_mutex_t mutex;
    struct replay_entry *entries;
    size_t capacity;
    char *socket_path;
    int timeout_ms;
};

enum
{
    REPLAY_BACKEND_MEMORY = 1,
    REPLAY_BACKEND_SERVICE = 2
};

static void
purge_expired(struct replay_cache *cache, int64_t now)
{
    size_t i;
    for (i = 0; i < cache->capacity; ++i)
    {
        if (cache->entries[i].used && cache->entries[i].expires_at <= now)
        {
            memset(&cache->entries[i], 0, sizeof(cache->entries[i]));
        }
    }
}

static struct replay_entry *
find_entry(struct replay_cache *cache,
           const unsigned char key[REPLAY_CACHE_KEY_SIZE])
{
    size_t i;
    for (i = 0; i < cache->capacity; ++i)
    {
        if (cache->entries[i].used &&
                memcmp(cache->entries[i].key, key,
                       REPLAY_CACHE_KEY_SIZE) == 0)
        {
            return &cache->entries[i];
        }
    }
    return NULL;
}

struct replay_cache *
replay_cache_memory_create(size_t capacity)
{
    struct replay_cache *cache;
    if (capacity == 0)
    {
        return NULL;
    }
    cache = calloc(1, sizeof(*cache));
    if (cache == NULL)
    {
        return NULL;
    }
    cache->entries = calloc(capacity, sizeof(cache->entries[0]));
    if (cache->entries == NULL ||
            pthread_mutex_init(&cache->mutex, NULL) != 0)
    {
        free(cache->entries);
        free(cache);
        return NULL;
    }
    cache->backend = REPLAY_BACKEND_MEMORY;
    cache->capacity = capacity;
    return cache;
}

struct replay_cache *
replay_cache_service_create(const char *socket_path, int timeout_ms)
{
    struct replay_cache *cache;
    size_t length;
    if (socket_path == NULL || socket_path[0] == '\0' || timeout_ms <= 0)
    {
        return NULL;
    }
    cache = calloc(1, sizeof(*cache));
    length = strlen(socket_path) + 1;
    if (cache == NULL || (cache->socket_path = malloc(length)) == NULL)
    {
        free(cache);
        return NULL;
    }
    memcpy(cache->socket_path, socket_path, length);
    cache->backend = REPLAY_BACKEND_SERVICE;
    cache->timeout_ms = timeout_ms;
    return cache;
}

int
replay_cache_is_service(const struct replay_cache *cache)
{
    return cache != NULL && cache->backend == REPLAY_BACKEND_SERVICE;
}

void
replay_cache_free(struct replay_cache *cache)
{
    if (cache != NULL)
    {
        if (cache->backend == REPLAY_BACKEND_MEMORY)
        {
            pthread_mutex_destroy(&cache->mutex);
            free(cache->entries);
        }
        free(cache->socket_path);
        free(cache);
    }
}

enum replay_cache_status
replay_cache_make_key(const char *issuer, const char *jti,
                      unsigned char key[REPLAY_CACHE_KEY_SIZE])
{
    EVP_MD_CTX *ctx;
    unsigned int length = 0;
    static const unsigned char separator = 0;
    int ok;

    if (issuer == NULL || issuer[0] == '\0' || jti == NULL ||
            jti[0] == '\0' || key == NULL)
    {
        return REPLAY_CACHE_ERROR;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        return REPLAY_CACHE_ERROR;
    }
    ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
         EVP_DigestUpdate(ctx, issuer, strlen(issuer)) == 1 &&
         EVP_DigestUpdate(ctx, &separator, 1) == 1 &&
         EVP_DigestUpdate(ctx, jti, strlen(jti)) == 1 &&
         EVP_DigestFinal_ex(ctx, key, &length) == 1 &&
         length == REPLAY_CACHE_KEY_SIZE;
    EVP_MD_CTX_free(ctx);
    return ok ? REPLAY_CACHE_OK : REPLAY_CACHE_ERROR;
}

enum replay_cache_status
replay_cache_reserve(struct replay_cache *cache,
                     const unsigned char key[REPLAY_CACHE_KEY_SIZE],
                     int64_t expires_at, int64_t now)
{
    size_t i;
    if (cache != NULL && cache->backend == REPLAY_BACKEND_SERVICE)
    {
        return replay_cache_service_request(cache->socket_path,
                   cache->timeout_ms, BAF_REPLAY_OP_RESERVE, key,
                   expires_at, NULL);
    }
    if (cache == NULL)
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    if (key == NULL || expires_at <= now ||
            pthread_mutex_lock(&cache->mutex) != 0)
    {
        return REPLAY_CACHE_ERROR;
    }
    purge_expired(cache, now);
    if (find_entry(cache, key) != NULL)
    {
        pthread_mutex_unlock(&cache->mutex);
        return REPLAY_CACHE_EXISTS;
    }
    for (i = 0; i < cache->capacity; ++i)
    {
        if (!cache->entries[i].used)
        {
            memcpy(cache->entries[i].key, key, REPLAY_CACHE_KEY_SIZE);
            cache->entries[i].expires_at = expires_at;
            cache->entries[i].state = REPLAY_CACHE_RESERVED;
            cache->entries[i].used = 1;
            pthread_mutex_unlock(&cache->mutex);
            return REPLAY_CACHE_OK;
        }
    }
    pthread_mutex_unlock(&cache->mutex);
    return REPLAY_CACHE_FULL;
}

static enum replay_cache_status
set_state(struct replay_cache *cache,
          const unsigned char key[REPLAY_CACHE_KEY_SIZE], int64_t now,
          enum replay_cache_state state)
{
    struct replay_entry *entry;
    if (cache != NULL && cache->backend == REPLAY_BACKEND_SERVICE)
    {
        enum baf_replay_operation operation;
        if (state == REPLAY_CACHE_CONSUMED)
        {
            operation = BAF_REPLAY_OP_MARK_CONSUMED;
        }
        else if (state == REPLAY_CACHE_RELEASED)
        {
            operation = BAF_REPLAY_OP_MARK_RELEASED;
        }
        else
        {
            return REPLAY_CACHE_ERROR;
        }
        return replay_cache_service_request(cache->socket_path,
                   cache->timeout_ms, operation, key, 0, NULL);
    }
    if (cache == NULL)
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    if (key == NULL || pthread_mutex_lock(&cache->mutex) != 0)
    {
        return REPLAY_CACHE_ERROR;
    }
    purge_expired(cache, now);
    entry = find_entry(cache, key);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->mutex);
        return REPLAY_CACHE_NOT_FOUND;
    }
    entry->state = state;
    pthread_mutex_unlock(&cache->mutex);
    return REPLAY_CACHE_OK;
}

enum replay_cache_status
replay_cache_consume(struct replay_cache *cache,
                     const unsigned char key[REPLAY_CACHE_KEY_SIZE],
                     int64_t now)
{
    return set_state(cache, key, now, REPLAY_CACHE_CONSUMED);
}

enum replay_cache_status
replay_cache_release(struct replay_cache *cache,
                     const unsigned char key[REPLAY_CACHE_KEY_SIZE],
                     int64_t now)
{
    return set_state(cache, key, now, REPLAY_CACHE_RELEASED);
}

enum replay_cache_status
replay_cache_get_state(struct replay_cache *cache,
                       const unsigned char key[REPLAY_CACHE_KEY_SIZE],
                       int64_t now, enum replay_cache_state *state)
{
    struct replay_entry *entry;
    if (cache != NULL && cache->backend == REPLAY_BACKEND_SERVICE)
    {
        return replay_cache_service_request(cache->socket_path,
                   cache->timeout_ms, BAF_REPLAY_OP_STATUS, key, 0, state);
    }
    if (cache == NULL)
    {
        return REPLAY_CACHE_UNAVAILABLE;
    }
    if (key == NULL || state == NULL ||
            pthread_mutex_lock(&cache->mutex) != 0)
    {
        return REPLAY_CACHE_ERROR;
    }
    purge_expired(cache, now);
    entry = find_entry(cache, key);
    if (entry == NULL)
    {
        pthread_mutex_unlock(&cache->mutex);
        return REPLAY_CACHE_NOT_FOUND;
    }
    *state = entry->state;
    pthread_mutex_unlock(&cache->mutex);
    return REPLAY_CACHE_OK;
}
