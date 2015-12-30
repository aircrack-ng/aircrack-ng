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
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2005,2009,2011,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Things common to many ciphertext formats.
 */

#ifndef _JCOMMON_H
#define _JCOMMON_H

#include "arch.h"
#include "memory.h"

#if ARCH_INT_GT_32
typedef unsigned short ARCH_WORD_32;
typedef unsigned int ARCH_WORD_64;
#else
typedef unsigned int ARCH_WORD_32;
typedef unsigned long long ARCH_WORD_64;
#endif

/* ONLY use this to check alignments of even power of 2 (2, 4, 8, 16, etc) byte counts (CNT).
   The cast to void* MUST be done, due to C spec. http://stackoverflow.com/a/1898487 */
#define is_aligned(PTR, CNT) ((((ARCH_WORD)(const void *)(PTR))&(CNT-1))==0)

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7) || defined(__INTEL_COMPILER)
#define MAYBE_INLINE __attribute__((always_inline)) inline
#elif __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define MAYBE_INLINE __attribute__((always_inline))
#else
#define MAYBE_INLINE __inline__
#endif
#elif __STDC_VERSION__ >= 199901L
#define MAYBE_INLINE inline
#else
#define MAYBE_INLINE
#endif

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_CACHE_ALIGN \
	__attribute__ ((aligned (MEM_ALIGN_CACHE)))
#else
#define CC_CACHE_ALIGN			/* nothing */
#endif

/*
 * This "shift" is the number of bytes that may be inserted between arrays the
 * size of which would be a multiple of cache line size (some power of two) and
 * that might be accessed simultaneously.  The purpose of the shift is to avoid
 * cache bank conflicts with such accesses, actually allowing them to proceed
 * simultaneously.  This number should be a multiple of the machine's word size
 * but smaller than cache line size.
 */
#define CACHE_BANK_SHIFT		ARCH_SIZE

/*
 * ASCII <-> binary conversion tables.
 */
//extern const char itoa64[64]; /* crypt(3) base64 - not MIME Base64! */
extern char atoi64[0x100];
extern const char itoa16[16];
extern char atoi16[0x100];
extern const char itoa16u[16]; // uppercase

/*
 * Initializes the tables.
 */
extern void common_init(void);

#endif
