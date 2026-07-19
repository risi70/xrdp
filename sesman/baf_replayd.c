#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "replay_cache_service.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
parse_positive(const char *text, long *value)
{
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed <= 0)
    {
        return 0;
    }
    *value = parsed;
    return 1;
}

static void
usage(const char *name)
{
    fprintf(stderr,
            "Usage: %s [-s socket] [-c capacity] [-t max-ttl-seconds]\n",
            name);
}

int
main(int argc, char **argv)
{
    const char *socket_path = BAF_REPLAY_DEFAULT_SOCKET;
    long capacity = BAF_REPLAY_DEFAULT_CAPACITY;
    long max_ttl = BAF_REPLAY_DEFAULT_MAX_TTL;
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (i + 1 >= argc)
        {
            usage(argv[0]);
            return 1;
        }
        if (strcmp(argv[i], "-s") == 0)
        {
            socket_path = argv[++i];
        }
        else if (strcmp(argv[i], "-c") == 0)
        {
            if (!parse_positive(argv[++i], &capacity))
            {
                usage(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-t") == 0)
        {
            if (!parse_positive(argv[++i], &max_ttl))
            {
                usage(argv[0]);
                return 1;
            }
        }
        else
        {
            usage(argv[0]);
            return 1;
        }
    }
    return baf_replay_service_run(socket_path, (size_t)capacity,
                                  (int64_t)max_ttl);
}
