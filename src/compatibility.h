/*
 * Copyright (C) Jan 2006 Mellanox Technologies Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *  compatibility.h - Miscellaneous systems compatibility issues
 *
 *  Version: $Id: compatibility.h 2752 2006-01-19 14:40:17Z mst $
 *
 */

#ifndef COMPATIBILITY_H
#define COMPATIBILITY_H

#if defined(__ia64__) || defined(__x86_64__)
 #define U64L       "l"
#else
 #define U64L       "ll"
#endif

/*
 * Only for architectures which can't do swab by themselves
 */
#define ___my_swab16(x) \
((u_int16_t)( \
        (((u_int16_t)(x) & (u_int16_t)0x00ffU) << 8) | \
        (((u_int16_t)(x) & (u_int16_t)0xff00U) >> 8) ))
#define ___my_swab32(x) \
((u_int32_t)( \
        (((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
        (((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
        (((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
        (((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))
#define ___my_swab64(x) \
((u_int64_t)( \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000000000ffULL) << 56) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000000000ff00ULL) << 40) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000000000ff0000ULL) << 24) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000ff000000ULL) <<  8) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000ff00000000ULL) >>  8) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000ff0000000000ULL) >> 24) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00ff000000000000ULL) >> 40) | \
        (u_int64_t)(((u_int64_t)(x) & (u_int64_t)0xff00000000000000ULL) >> 56) ))

/*
 * Linux
 */
#if defined(linux)
// #include <asm/byteorder.h>
#include <endian.h>
#include <unistd.h>

#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)


#endif

/*
 * Windows (CYGWIN)
 */
#if defined(__CYGWIN32__)
#include <asm/byteorder.h>
#include <unistd.h>

#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)

#endif

/*
 * Windows (DDK)
 */
#if defined(__WIN__)


#include <io.h>


#define __be64_to_cpu(x) ___my_swab64(x)
#define __be32_to_cpu(x) ___my_swab32(x)
#define __be16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_be64(x) ___my_swab64(x)
#define __cpu_to_be32(x) ___my_swab32(x)
#define __cpu_to_be16(x) ___my_swab16(x)
#define __le64_to_cpu(x) (x)
#define __le32_to_cpu(x) (x)
#define __le16_to_cpu(x) (x)
#define __cpu_to_le64(x) (x)
#define __cpu_to_le32(x) (x)
#define __cpu_to_le16(x) (x)

typedef unsigned __int8  u_int8_t;
typedef __int8           int8_t;
typedef unsigned __int16 u_int16_t;
typedef __int16          int16_t;
typedef unsigned __int32 u_int32_t;
typedef __int32          int32_t;
typedef unsigned __int64 u_int64_t;
typedef __int64          int64_t;

inline 
void    unsetenv(const char *e) {e = 0;}

#define strcasecmp    _stricmp
#define strtoll       _strtoi64
#define strtoull      _strtoui64
#define vsnprintf     _vsnprintf 


#define COMP_CDECL    __cdecl
#define COMP_OPEN     ::_open
#define COMP_CLOSE    ::_close
#define COMP_READ     ::_read
#define COMP_FSTAT    ::_fstat

typedef struct _stat  Stat;

#else 

#define COMP_CDECL
#define COMP_OPEN     ::open
#define COMP_CLOSE    ::close
#define COMP_READ     ::read
#define COMP_FSTAT    ::fstat


typedef struct stat  Stat;

#include <sys/time.h>
#include <strings.h>

#endif



/*
 * MAC (Darwin)
 */
#if defined(__APPLE_CC__)
#include <architecture/byte_order.h>

#define __swab64(x)      NXSwapLongLong(x)
#define __swab32(x)      NXSwapLong(x)
#define __swab16(x)      NXSwapShort(x)
#define __be64_to_cpu(x) NXSwapBigLongLongToHost(x)
#define __be32_to_cpu(x) NXSwapBigLongToHost(x)
#define __be16_to_cpu(x) NXSwapBigShortToHost(x)
#define __le64_to_cpu(x) NXSwapLittleLongLongToHost(x)
#define __le32_to_cpu(x) NXSwapLittleLongToHost(x)
#define __le16_to_cpu(x) NXSwapLittleShortToHost(x)
#define __cpu_to_be64(x) NXSwapHostLongLongToBig(x)
#define __cpu_to_be32(x) NXSwapHostLongToBig(x)
#define __cpu_to_be16(x) NXSwapHostShortToBig(x)
#define __cpu_to_le64(x) NXSwapHostLongLongToLittle(x)
#define __cpu_to_le32(x) NXSwapHostLongToLittle(x)
#define __cpu_to_le16(x) NXSwapHostShortToLittle(x)

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN    4321
#define __PDP_ENDIAN    3412
#define __BYTE_ORDER    __BIG_ENDIAN
#endif

/*
 * Solaris
 * -------
 */
#if defined(__sparc__)
#include <sys/byteorder.h>
#include <sys/types.h>
#include <unistd.h>

#define __be64_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be16_to_cpu(x) (x)
#define __cpu_to_be64(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be16(x) (x)
#define __le64_to_cpu(x) ___my_swab64(x)
#define __le32_to_cpu(x) ___my_swab32(x)
#define __le16_to_cpu(x) ___my_swab16(x)
#define __cpu_to_le64(x) ___my_swab64(x)
#define __cpu_to_le32(x) ___my_swab32(x)
#define __cpu_to_le16(x) ___my_swab16(x)

typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t  u_int8_t;

void    unsetenv(const char *e);

#endif

/*
 * Old GCC
 * -------
 */
#if !defined(__WIN__) && __GNUG__ < 3
#include <algo.h>
#endif

#endif
