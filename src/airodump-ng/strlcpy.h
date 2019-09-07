#ifndef __STRLCPY_H__
#define __STRLCPY_H__

#include <stddef.h>
#include <sys/cdefs.h>

/* FIXME - This is only required when strlcpy() isn't already provided. */
size_t
my_strlcpy(char * __restrict dst, const char * __restrict src, size_t dsize);

#endif /* __STRLCPY_H__ */
