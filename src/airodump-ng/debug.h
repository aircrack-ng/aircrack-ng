#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG

#if defined(DEBUG)

#include <stdio.h>

#define DPRINTF(format, ...) \
    do \
    { \
        fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#else

#define DPRINTF(format, ...) do {} while (0)

#endif

#endif /* __DEBUG_H__ */
