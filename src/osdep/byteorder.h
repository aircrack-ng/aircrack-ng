/*
 *  Compatibility header
 *
 *  Copyright (C) 2009-2016 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _AIRCRACK_NG_BYTEORDER_H_
#define _AIRCRACK_NG_BYTEORDER_H_

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
	#if defined(linux) || defined(Linux) || defined(__linux__) || defined(__linux) || defined(__gnu_linux__)
		#include <endian.h>
		#include <unistd.h>
		#include <stdint.h>

		#ifndef __int8_t_defined
			typedef uint64_t u_int64_t;
			typedef uint32_t u_int32_t;
			typedef uint16_t u_int16_t;
			typedef uint8_t  u_int8_t;
		#endif

	#endif

	/*
	 * Cygwin
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

		#define AIRCRACK_NG_BYTE_ORDER_DEFINED

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

		#define AIRCRACK_NG_BYTE_ORDER_DEFINED

	#endif

	/*
	 * MAC (Darwin)
	 */
	#if defined(__APPLE_CC__)
		#if defined(__x86_64__) && defined(__APPLE__)

			#include <libkern/OSByteOrder.h>

			#define __swab64(x)      (unsigned long long) OSSwapInt64((uint64_t)x)
			#define __swab32(x)      (unsigned long) OSSwapInt32((uint32_t)x)
			#define __swab16(x)      (unsigned short) OSSwapInt16((uint16_t)x)
			#define __be64_to_cpu(x) (unsigned long long) OSSwapBigToHostInt64((uint64_t)x)
			#define __be32_to_cpu(x) (unsigned long) OSSwapBigToHostInt32((uint32_t)x)
			#define __be16_to_cpu(x) (unsigned short) OSSwapBigToHostInt16((uint16_t)x)
			#define __le64_to_cpu(x) (unsigned long long) OSSwapLittleToHostInt64((uint64_t)x)
			#define __le32_to_cpu(x) (unsigned long) OSSwapLittleToHostInt32((uint32_t)x)
			#define __le16_to_cpu(x) (unsigned short) OSSwapLittleToHostInt16((uint16_t)x)
			#define __cpu_to_be64(x) (unsigned long long) OSSwapHostToBigInt64((uint64_t)x)
			#define __cpu_to_be32(x) (unsigned long) OSSwapHostToBigInt32((uint32_t)x)
			#define __cpu_to_be16(x) (unsigned short) OSSwapHostToBigInt16((uint16_t)x)
			#define __cpu_to_le64(x) (unsigned long long) OSSwapHostToLittleInt64((uint64_t)x)
			#define __cpu_to_le32(x) (unsigned long) OSSwapHostToLittleInt32((uint32_t)x)
			#define __cpu_to_le16(x) (unsigned short) OSSwapHostToLittleInt16((uint16_t)x)

		#else

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

		#endif

		#define __LITTLE_ENDIAN 1234
		#define __BIG_ENDIAN    4321
		#define __PDP_ENDIAN    3412
		#define __BYTE_ORDER    __BIG_ENDIAN

		#define AIRCRACK_NG_BYTE_ORDER_DEFINED

	#endif

	/*
	 * Solaris
	 * -------
	 */
	#if defined(__SVR4) && defined(__sun__)
	#include <sys/byteorder.h>
	#include <sys/types.h>
	#include <unistd.h>

	typedef uint64_t u_int64_t;
	typedef uint32_t u_int32_t;
	typedef uint16_t u_int16_t;
	typedef uint8_t  u_int8_t;

	#if defined(__sparc__)
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

		#define AIRCRACK_NG_BYTE_ORDER_DEFINED
	#else
		#define AIRCRACK_NG_BYTE_ORDER 1
		#define LITTLE_ENDIAN 1
	#endif
	#endif

	/*
	 * Custom stuff
	 */
	#if  defined(__MACH__) && !defined(__APPLE_CC__) && !defined(__GNU__)
		#include <libkern/OSByteOrder.h>
		#define __cpu_to_be64(x) = OSSwapHostToBigInt64(x)
		#define __cpu_to_be32(x) = OSSwapHostToBigInt32(x)

		#define AIRCRACK_NG_BYTE_ORDER_DEFINED
	#endif

	// FreeBSD
	#ifdef __FreeBSD__
		#undef ushort
		#undef uint
		#include <sys/types.h>
	#endif

	// XXX: Is there anything to include on OpenBSD/NetBSD/DragonFlyBSD/...?


	// XXX: Mac: Check http://www.opensource.apple.com/source/CF/CF-476.18/CFByteOrder.h
	//           http://developer.apple.com/DOCUMENTATION/CoreFoundation/Reference/CFByteOrderUtils/Reference/reference.html
	//           Write to apple to ask what should be used.

	#if defined(LITTLE_ENDIAN)
		#define AIRCRACK_NG_LITTLE_ENDIAN LITTLE_ENDIAN
	#elif defined(__LITTLE_ENDIAN)
		#define AIRCRACK_NG_LITTLE_ENDIAN __LITTLE_ENDIAN
	#elif defined(_LITTLE_ENDIAN)
		#define AIRCRACK_NG_LITTLE_ENDIAN _LITTLE_ENDIAN
	#endif

	#if defined(BIG_ENDIAN)
		#define AIRCRACK_NG_BIG_ENDIAN BIG_ENDIAN
	#elif defined(__BIG_ENDIAN)
		#define AIRCRACK_NG_BIG_ENDIAN __BIG_ENDIAN
	#elif defined(_BIG_ENDIAN)
		#define AIRCRACK_NG_BIG_ENDIAN _BIG_ENDIAN
	#endif

	#if !defined(AIRCRACK_NG_LITTLE_ENDIAN) && !defined(AIRCRACK_NG_BIG_ENDIAN)
		#error Impossible to determine endianness (Little or Big endian), please contact the author.
	#endif

	#if defined(BYTE_ORDER)
		#if (BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
		#elif (BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
		#endif
	#elif defined(__BYTE_ORDER)
		#if (__BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
		#elif (__BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
		#endif
	#elif defined(_BYTE_ORDER)
		#if (_BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_LITTLE_ENDIAN
		#elif (_BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
			#define AIRCRACK_NG_BYTE_ORDER AIRCRACK_NG_BIG_ENDIAN
		#endif
	#endif

	#ifndef AIRCRACK_NG_BYTE_ORDER
		#error Impossible to determine endianness (Little or Big endian), please contact the author.
	#endif

	#if (AIRCRACK_NG_BYTE_ORDER == AIRCRACK_NG_LITTLE_ENDIAN)

		#ifndef AIRCRACK_NG_BYTE_ORDER_DEFINED
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

		#ifndef htobe16
			#define htobe16 ___my_swab16
		#endif
		#ifndef htobe32
			#define htobe32 ___my_swab32
		#endif
                #ifndef htobe64
                        #define htobe64 ___my_swab64
                #endif
		#ifndef betoh16
			#define betoh16 ___my_swab16
		#endif
		#ifndef betoh32
			#define betoh32 ___my_swab32
		#endif
                #ifndef betoh64
                        #define betoh64 ___my_swab64
                #endif

		#ifndef htole16
			#define htole16(x) (x)
		#endif
		#ifndef htole32
			#define htole32(x) (x)
		#endif
                #ifndef htole64
                        #define htole64(x) (x)
                #endif
		#ifndef letoh16
			#define letoh16(x) (x)
		#endif
		#ifndef letoh32
			#define letoh32(x) (x)
		#endif
                #ifndef letoh64
                        #define letoh64(x) (x)
                #endif

	#endif

	#if (AIRCRACK_NG_BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)

		#ifndef AIRCRACK_NG_BYTE_ORDER_DEFINED
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
		#endif

		#ifndef htobe16
			#define htobe16(x) (x)
		#endif
		#ifndef htobe32
			#define htobe32(x) (x)
		#endif
                #ifndef htobe64
                        #define htobe64(x) (x)
                #endif
		#ifndef betoh16
			#define betoh16(x) (x)
		#endif
		#ifndef betoh32
			#define betoh32(x) (x)
		#endif
                #ifndef betoh64
                        #define betoh64(x) (x)
                #endif

		#ifndef htole16
			#define htole16 ___my_swab16
		#endif
		#ifndef htole32
			#define htole32 ___my_swab32
		#endif
                #ifndef htole64
                        #define htole64 ___my_swab64
                #endif
		#ifndef letoh16
			#define letoh16 ___my_swab16
		#endif
		#ifndef letoh32
			#define letoh32 ___my_swab32
		#endif
                #ifndef letoh64
                        #define letoh64 ___my_swab64
                #endif

	#endif

	// Common defines
	#define cpu_to_le64 __cpu_to_le64
	#define le64_to_cpu __le64_to_cpu
	#define cpu_to_le32 __cpu_to_le32
	#define le32_to_cpu __le32_to_cpu
	#define cpu_to_le16 __cpu_to_le16
	#define le16_to_cpu __le16_to_cpu
	#define cpu_to_be64 __cpu_to_be64
	#define be64_to_cpu __be64_to_cpu
	#define cpu_to_be32 __cpu_to_be32
	#define be32_to_cpu __be32_to_cpu
	#define cpu_to_be16 __cpu_to_be16
	#define be16_to_cpu __be16_to_cpu

	#ifndef le16toh
		#define le16toh le16_to_cpu
	#endif
	#ifndef be16toh
		#define be16toh be16_to_cpu
	#endif
	#ifndef le32toh
		#define le32toh le32_to_cpu
	#endif
	#ifndef be32toh
		#define be32toh be32_to_cpu
	#endif


	#ifndef htons
		#define htons be16_to_cpu
	#endif
	#ifndef htonl
		#define htonl cpu_to_be16
	#endif
	#ifndef ntohs
		#define ntohs cpu_to_be16
	#endif
	#ifndef ntohl
		#define ntohl cpu_to_be32
	#endif

#endif
