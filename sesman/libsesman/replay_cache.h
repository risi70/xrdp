#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include <stddef.h>
#include <stdint.h>

#define REPLAY_CACHE_KEY_SIZE 32

enum replay_cache_status
{
    REPLAY_CACHE_OK = 0,
    REPLAY_CACHE_EXISTS,
    REPLAY_CACHE_NOT_FOUND,
    REPLAY_CACHE_FULL,
    REPLAY_CACHE_UNAVAILABLE,
    REPLAY_CACHE_ERROR
};

enum replay_cache_state
{
    REPLAY_CACHE_RESERVED = 1,
    REPLAY_CACHE_CONSUMED,
    REPLAY_CACHE_RELEASED
};

struct replay_cache;

struct replay_cache *replay_cache_memory_create(size_t capacity);
void replay_cache_free(struct replay_cache *cache);
enum replay_cache_status replay_cache_make_key(
    const char *issuer, const char *jti,
    unsigned char key[REPLAY_CACHE_KEY_SIZE]);
enum replay_cache_status replay_cache_reserve(
    struct replay_cache *cache,
    const unsigned char key[REPLAY_CACHE_KEY_SIZE],
    int64_t expires_at, int64_t now);
enum replay_cache_status replay_cache_consume(
    struct replay_cache *cache,
    const unsigned char key[REPLAY_CACHE_KEY_SIZE], int64_t now);
/**
 * Mark a reservation as released for audit/state reporting only.
 *
 * Phase 2 is consume-once: this does not delete the entry or permit the key
 * to be reserved again before its expiry.
 */
enum replay_cache_status replay_cache_release(
    struct replay_cache *cache,
    const unsigned char key[REPLAY_CACHE_KEY_SIZE], int64_t now);
enum replay_cache_status replay_cache_get_state(
    struct replay_cache *cache,
    const unsigned char key[REPLAY_CACHE_KEY_SIZE], int64_t now,
    enum replay_cache_state *state);

#endif
