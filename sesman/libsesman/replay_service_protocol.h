#ifndef REPLAY_SERVICE_PROTOCOL_H
#define REPLAY_SERVICE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define BAF_REPLAY_PROTOCOL_VERSION 1
#define BAF_REPLAY_KEY_SIZE 32
#define BAF_REPLAY_CORRELATION_SIZE 16
#define BAF_REPLAY_REQUEST_SIZE 64
#define BAF_REPLAY_RESPONSE_SIZE 16
#define BAF_REPLAY_DEFAULT_SOCKET XRDP_SOCKET_ROOT_PATH "/baf-replay.sock"
#define BAF_REPLAY_DEFAULT_TIMEOUT_MS 1000
#define BAF_REPLAY_DEFAULT_CAPACITY 100000
#define BAF_REPLAY_DEFAULT_MAX_TTL 1020

enum baf_replay_operation
{
    BAF_REPLAY_OP_RESERVE = 1,
    BAF_REPLAY_OP_MARK_CONSUMED = 2,
    BAF_REPLAY_OP_MARK_RELEASED = 3,
    BAF_REPLAY_OP_STATUS = 4,
    BAF_REPLAY_OP_CLEANUP_EXPIRED = 5,
    BAF_REPLAY_OP_PING = 6
};

enum baf_replay_result
{
    BAF_REPLAY_RESULT_OK_RESERVED = 0,
    BAF_REPLAY_RESULT_OK = 1,
    BAF_REPLAY_RESULT_REPLAY = 2,
    BAF_REPLAY_RESULT_BAD_REQUEST = 3,
    BAF_REPLAY_RESULT_EXPIRED = 4,
    BAF_REPLAY_RESULT_CAPACITY = 5,
    BAF_REPLAY_RESULT_UNAVAILABLE = 6,
    BAF_REPLAY_RESULT_INTERNAL = 7,
    BAF_REPLAY_RESULT_NOT_FOUND = 8
};

struct baf_replay_request
{
    unsigned char version[2];
    unsigned char operation[2];
    unsigned char length[4];
    unsigned char key[BAF_REPLAY_KEY_SIZE];
    unsigned char expires_at[8];
    unsigned char correlation[BAF_REPLAY_CORRELATION_SIZE];
};

struct baf_replay_response
{
    unsigned char version[2];
    unsigned char operation[2];
    unsigned char length[4];
    unsigned char result[4];
    unsigned char state[4];
};

static inline void
baf_replay_put_u16(unsigned char out[2], uint16_t value)
{
    out[0] = (unsigned char)(value >> 8);
    out[1] = (unsigned char)value;
}

static inline uint16_t
baf_replay_get_u16(const unsigned char in[2])
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static inline void
baf_replay_put_u32(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static inline uint32_t
baf_replay_get_u32(const unsigned char in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | in[3];
}

static inline void
baf_replay_put_i64(unsigned char out[8], int64_t value)
{
    uint64_t v = (uint64_t)value;
    int i;
    for (i = 7; i >= 0; --i)
    {
        out[i] = (unsigned char)v;
        v >>= 8;
    }
}

static inline int64_t
baf_replay_get_i64(const unsigned char in[8])
{
    uint64_t value = 0;
    int i;
    for (i = 0; i < 8; ++i)
    {
        value = (value << 8) | in[i];
    }
    return (int64_t)value;
}

#endif
