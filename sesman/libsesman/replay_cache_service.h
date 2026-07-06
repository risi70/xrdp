#ifndef REPLAY_CACHE_SERVICE_H
#define REPLAY_CACHE_SERVICE_H

#include "replay_cache.h"
#include "replay_service_protocol.h"

enum replay_cache_status replay_cache_service_request(
    const char *socket_path, int timeout_ms,
    enum baf_replay_operation operation,
    const unsigned char key[REPLAY_CACHE_KEY_SIZE], int64_t expires_at,
    enum replay_cache_state *state);

int baf_replay_service_run(const char *socket_path, size_t capacity,
                           int64_t max_ttl_seconds);

#endif
