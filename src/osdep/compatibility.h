/*
 * Copyright (C) 2009 Thomas d'Otreppe de Bouvette
 *
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

/*
TODO: Cleanup and only have the BYTE_ORDER define set so it will define the macros
      only once for all architectures with maybe a few exceptions.
      And thus only the includes for each OS will be left.
*/

#ifndef _AIRCRACK_NG__COMPATIBILITY_H_
#define _AIRCRACK_NG_COMPATIBILITY_H_

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

	#define be64_to_cpu(x) __be64_to_cpu(x)
	#define be32_to_cpu(x) __be32_to_cpu(x)
	#define be16_to_cpu(x) __be16_to_cpu(x)
	#define cpu_to_be64(x) __cpu_to_be64(x)
	#define cpu_to_be32(x) __cpu_to_be32(x)
	#define cpu_to_be16(x) __cpu_to_be16(x)
	#define le64_to_cpu(x) (x)
	#define le32_to_cpu(x) (x)
	#define le16_to_cpu(x) (x)
	#define cpu_to_le64(x) (x)
	#define cpu_to_le32(x) (x)
	#define cpu_to_le16(x) (x)

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

	#define be64_to_cpu(x) __be64_to_cpu(x)
	#define be32_to_cpu(x) __be32_to_cpu(x)
	#define be16_to_cpu(x) __be16_to_cpu(x)
	#define cpu_to_be64(x) __cpu_to_be64(x)
	#define cpu_to_be32(x) __cpu_to_be32(x)
	#define cpu_to_be16(x) __cpu_to_be16(x)
	#define le64_to_cpu(x) (x)
	#define le32_to_cpu(x) (x)
	#define le16_to_cpu(x) (x)
	#define cpu_to_le64(x) (x)
	#define cpu_to_le32(x) (x)
	#define cpu_to_le16(x) (x)

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

	#define be64_to_cpu(x) __be64_to_cpu(x)
	#define be32_to_cpu(x) __be32_to_cpu(x)
	#define be16_to_cpu(x) __be16_to_cpu(x)
	#define cpu_to_be64(x) __cpu_to_be64(x)
	#define cpu_to_be32(x) __cpu_to_be32(x)
	#define cpu_to_be16(x) __cpu_to_be16(x)
	#define le64_to_cpu(x) (x)
	#define le32_to_cpu(x) (x)
	#define le16_to_cpu(x) (x)
	#define cpu_to_le64(x) (x)
	#define cpu_to_le32(x) (x)
	#define cpu_to_le16(x) (x)

	typedef unsigned __int8  u_int8_t;
	typedef __int8           int8_t;
	typedef unsigned __int16 u_int16_t;
	typedef __int16          int16_t;
	typedef unsigned __int32 u_int32_t;
	typedef __int32          int32_t;
	typedef unsigned __int64 u_int64_t;
	typedef __int64          int64_t;

	#define strcasecmp    _stricmp
	#define strtoll       _strtoi64
	#define strtoull      _strtoui64
	#define vsnprintf     _vsnprintf

	#else

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

	#define swab64(x) __swab64(x)
	#define swab32(x) __swab32(x)
	#define swab16(x) __swab16(x)
	#define be64_to_cpu(x) __be64_to_cpu(x)
	#define be32_to_cpu(x) __be32_to_cpu(x)
	#define be16_to_cpu(x) __be16_to_cpu(x)
	#define le64_to_cpu(x) __le64_to_cpu(x)
	#define le32_to_cpu(x) __le32_to_cpu(x)
	#define le16_to_cpu(x) __le16_to_cpu(x)
	#define cpu_to_be64(x) __cpu_to_be64(x)
	#define cpu_to_be32(x) __cpu_to_be32(x)
	#define cpu_to_be16(x) __cpu_to_be16(x)
	#define cpu_to_le64(x) __cpu_to_le64(x)
	#define cpu_to_le32(x) __cpu_to_le32(x)
	#define cpu_to_le16(x) __cpu_to_le16(x)

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

	#define be64_to_cpu(x) __be64_to_cpu(x)
	#define be32_to_cpu(x) __be32_to_cpu(x)
	#define be16_to_cpu(x) __be16_to_cpu(x)
	#define cpu_to_be64(x) __cpu_to_be64(x)
	#define cpu_to_be32(x) __cpu_to_be32(x)
	#define cpu_to_be16(x) __cpu_to_be16(x)
	#define le64_to_cpu(x) (x)
	#define le32_to_cpu(x) (x)
	#define le16_to_cpu(x) (x)
	#define cpu_to_le64(x) (x)
	#define cpu_to_le32(x) (x)
	#define cpu_to_le16(x) (x)

	#endif


	/*
	 * Custom stuff
	 */
	#if  defined(__MACH__) && !defined(__APPLE_CC__)
		#include <libkern/OSByteOrder.h>
		#define __cpu_to_be64(x) = OSSwapHostToBigInt64(x)
		#define __cpu_to_be32(x) = OSSwapHostToBigInt32(x)

		#define cpu_to_be64(x) __cpu_to_be64(x)
		#define cpu_to_be32(x) __cpu_to_be32(x)
	#endif


	// FreeBSD
	#ifdef __FreeBSD__
		#include <machine/endian.h>
		#if BYTE_ORDER == BIG_ENDIAN

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

			#define be64_to_cpu(x) __be64_to_cpu(x)
			#define be32_to_cpu(x) __be32_to_cpu(x)
			#define be16_to_cpu(x) __be16_to_cpu(x)
			#define cpu_to_be64(x) __cpu_to_be64(x)
			#define cpu_to_be32(x) __cpu_to_be32(x)
			#define cpu_to_be16(x) __cpu_to_be16(x)
			#define le64_to_cpu(x) (x)
			#define le32_to_cpu(x) (x)
			#define le16_to_cpu(x) (x)
			#define cpu_to_le64(x) (x)
			#define cpu_to_le32(x) (x)
			#define cpu_to_le16(x) (x)
		#elif BYTE_ORDER == LITTLE_ENDIAN

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

			#define be64_to_cpu(x) __be64_to_cpu(x)
			#define be32_to_cpu(x) __be32_to_cpu(x)
			#define be16_to_cpu(x) __be16_to_cpu(x)
			#define cpu_to_be64(x) __cpu_to_be64(x)
			#define cpu_to_be32(x) __cpu_to_be32(x)
			#define cpu_to_be16(x) __cpu_to_be16(x)
			#define le64_to_cpu(x) (x)
			#define le32_to_cpu(x) (x)
			#define le16_to_cpu(x) (x)
			#define cpu_to_le64(x) (x)
			#define cpu_to_le32(x) (x)
			#define cpu_to_le16(x) (x)
		#endif
	#endif

	#ifndef MAX
	#define MAX(x,y) ( (x)>(y) ? (x) : (y) )
	#endif

	#ifndef MIN
	#define MIN(x,y) ( (x)>(y) ? (y) : (x) )
	#endif




	// Mac: Check http://www.opensource.apple.com/source/CF/CF-476.18/CFByteOrder.h
	//      http://developer.apple.com/DOCUMENTATION/CoreFoundation/Reference/CFByteOrderUtils/Reference/reference.html
	// Write to apple to ask what should be used.

	// Only for aircrack-ng
	#define CPUID_MMX_AVAILABLE 1
	#define CPUID_SSE2_AVAILABLE 2
	#define CPUID_NOTHING_AVAILABLE 0

	#if defined(__i386__) || defined(__x86_64__)
		#define CPUID() shasse2_cpuid()
	#else
		#define CPUID() CPUID_NOTHING_AVAILABLE
	#endif


	/*-
	 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
	 *
	 * pack structures
	 *
	 */

	#ifndef __packed
		#define __packed __attribute__ ((__packed__))
	#endif /* __packed */

	#ifndef __aligned
		#define __aligned(n)
	#endif
	/* End of pack structure */

#endif
