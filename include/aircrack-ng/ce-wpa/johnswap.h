/*
 * Based on John the Ripper and modified to integrate with aircrack
 *
 * 	John the Ripper copyright and license.
 *
 * John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * As a special exception to the GNU General Public License terms,
 * permission is hereby granted to link the code of this program, with or
 * without modification, with any version of the OpenSSL library and/or any
 * version of unRAR, and to distribute such linked combinations.  You must
 * obey the GNU GPL in all respects for all of the code used other than
 * OpenSSL and unRAR.  If you modify this program, you may extend this
 * exception to your version of the program, but you are not obligated to
 * do so.  (In other words, you may release your derived work under pure
 * GNU GPL version 2 or later as published by the FSF.)
 *
 * (This exception from the GNU GPL is not required for the core tree of
 * John the Ripper, but arguably it is required for -jumbo.)
 *
 * 	Relaxed terms for certain components.
 *
 * In addition or alternatively to the license above, many components are
 * available to you under more relaxed terms (most commonly under cut-down
 * BSD license) as specified in the corresponding source files.
 *
 * For more information on John the Ripper licensing please visit:
 *
 * http://www.openwall.com/john/doc/LICENSE.shtml
 *
 */
#if !defined __JOHN_SWAP_H__
#define __JOHN_SWAP_H__

/* reqired for the john_bswap_32 ARCH_WORD_32 declaration */
#include <aircrack-ng/ce-wpa/jcommon.h>

/* if x86 compatible cpu */
#if defined(i386) || defined(__i386__) || defined(__i486__)                    \
	|| defined(__i586__) || defined(__i686__) || defined(__pentium__)          \
	|| defined(__pentiumpro__) || defined(__pentium4__) || defined(__nocona__) \
	|| defined(prescott) || defined(__core2__) || defined(__k6__)              \
	|| defined(__k8__) || defined(__athlon__) || defined(__amd64)              \
	|| defined(__amd64__) || defined(__x86_64) || defined(__x86_64__)          \
	|| defined(_M_IX86) || defined(_M_AMD64) || defined(_M_IA64)               \
	|| defined(_M_X64)
/* detect if x86-64 instruction set is supported */
#if defined(_LP64) || defined(__LP64__) || defined(__x86_64)                   \
	|| defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#undef CPU_X64
#define CPU_X64 1
#else
#undef CPU_IA32
#define CPU_IA32 1
#endif
#undef CPU_INTEL_LE
#define CPU_INTEL_LE 1
#endif

#if defined __GNUC__                                                           \
	&& ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || (__GNUC__ > 4))
#define JOHNSWAP(x) __builtin_bswap32((x))
#define JOHNSWAP64(x) __builtin_bswap64((x))
#elif defined(__linux__)
#include <byteswap.h>
#define JOHNSWAP(x) bswap_32((x))
#define JOHNSWAP64(x) bswap_64((x))
#elif (_MSC_VER > 1300)                                                        \
	&& (_M_IX86 >= 400 || defined(CPU_IA32) || defined(CPU_X64)) /* MS VC */
#define JOHNSWAP(x) _byteswap_ulong((x))
#define JOHNSWAP64(x) _byteswap_uint64(((unsigned __int64) x))
#elif !defined(__STRICT_ANSI__)
#define JOHNSWAP(x) john_bswap_32((x))
#define JOHNSWAP64(x) john_bswap_64((x))
#define ROTATE_LEFT(x, n)                                                      \
	(x) = (((x) << (n)) | ((ARCH_WORD_32)(x) >> (32 - (n))))
#define ROTATE_LEFT64(x, n)                                                    \
	(x) = (((x) << (n)) | ((unsigned long long) (x) >> (64 - (n))))
#if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__)
/* for intel x86 CPU */
static inline ARCH_WORD_32 __attribute__((const))
john_bswap_32(ARCH_WORD_32 val)
{
	register ARCH_WORD_32 res;
	__asm("bswap\t%0" : "=r"(res) : "0"(val));
	return res;
}
#else
/* Note, the name bswap_32 clashed with a less efficient bswap_32 in gcc 3.4. */
/* Thus, we now call it john_bswap_32 to take 'ownership' */
static inline ARCH_WORD_32 john_bswap_32(ARCH_WORD_32 x)
{
	/* Since this is an inline function, we do not have to worry about */
	/* multiple reference of x.  Even though we are called from a macro */
	/* this inline hides problems even with usage like  n=SWAP(*cp++); */
	ROTATE_LEFT(x, 16);
	return ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
}
#endif
static inline unsigned long long john_bswap_64(unsigned long long x)
{
#if ARCH_BITS == 32
	union {
		unsigned long long ll;
		ARCH_WORD_32 l[2];
	} w, r;
	w.ll = x;
	r.l[0] = john_bswap_32(w.l[1]);
	r.l[1] = john_bswap_32(w.l[0]);
	return r.ll;
#else
	// Someone should write a 'proper' 64 bit bswap, for 64 bit arch
	// for now, I am using the '32 bit' version I wrote above.
	union {
		unsigned long long ll;
		ARCH_WORD_32 l[2];
	} w, r;
	w.ll = x;
	r.l[0] = john_bswap_32(w.l[1]);
	r.l[1] = john_bswap_32(w.l[0]);
	return r.ll;
#endif
}
#endif

#endif // __JOHN_SWAP_H__
