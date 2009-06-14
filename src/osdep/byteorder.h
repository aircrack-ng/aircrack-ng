/*
 *  Compatibility header
 *
 *  Copyright (C) 2009 Thomas d'Otreppe
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
	#if defined(linux)
		#include <endian.h>
		#include <unistd.h>

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

	#endif

	/*
	 * Custom stuff
	 */
	#if  defined(__MACH__) && !defined(__APPLE_CC__)
		#include <libkern/OSByteOrder.h>
		#define __cpu_to_be64(x) = OSSwapHostToBigInt64(x)
		#define __cpu_to_be32(x) = OSSwapHostToBigInt32(x)
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
		#endif
	#endif


	// Mac: Check http://www.opensource.apple.com/source/CF/CF-476.18/CFByteOrder.h
	//      http://developer.apple.com/DOCUMENTATION/CoreFoundation/Reference/CFByteOrderUtils/Reference/reference.html
	// Write to apple to ask what should be used.


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


	#if (BYTE_ORDER == LITTLE_ENDIAN || __BYTE_ORDER == LITTLE_ENDIAN || __BYTE_ORDER == __LITTLE_ENDIAN)

		#ifndef htobe16
			#define htobe16 ___my_swab16
		#endif
		#ifndef htobe32
			#define htobe32 ___my_swab32
		#endif
		#ifndef betoh16
			#define betoh16 ___my_swab16
		#endif
		#ifndef betoh32
			#define betoh32 ___my_swab32
		#endif

		#ifndef htole16
			#define htole16(x) (x)
		#endif
		#ifndef htole32
			#define htole32(x) (x)
		#endif
		#ifndef letoh16
			#define letoh16(x) (x)
		#endif
		#ifndef letoh32
			#define letoh32(x) (x)
		#endif

	#endif

	#if (BYTE_ORDER == BIG_ENDIAN || __BYTE_ORDER == BIG_ENDIAN || __BYTE_ORDER == __BIG_ENDIAN)

		#ifndef htobe16
			#define htobe16(x) (x)
		#endif
		#ifndef htobe32
			#define htobe32(x) (x)
		#endif
		#ifndef betoh16
			#define betoh16(x) (x)
		#endif
		#ifndef betoh32
			#define betoh32(x) (x)
		#endif

		#ifndef htole16
			#define htole16 ___my_swab16
		#endif
		#ifndef htole32
			#define htole32 ___my_swab32
		#endif
		#ifndef letoh16
			#define letoh16 ___my_swab16
		#endif
		#ifndef letoh32
			#define letoh32 ___my_swab32
		#endif

	#endif


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
