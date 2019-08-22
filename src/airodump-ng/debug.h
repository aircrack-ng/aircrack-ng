#ifndef __DEBUG_H__
#define __DEBUG_H__

#if defined(DEBUG)
#include "view_buffer.h"

#include <stdio.h>

#define DPRINTF(format, ...) \
    do \
    { \
        fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#define VIEW_BUFFER(desc, data, length) do { view_buffer((desc), (data), (length)); } while (0)

#else

#define DPRINTF(format, ...) do {} while (0)
#define VIEW_BUFFER(desc, data, length) do {} while (0)

#endif

#endif /* __DEBUG_H__ */
