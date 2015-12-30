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
 * Copyright (c) 1996-98,2003,2010-2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Memory allocation routines.
 */

#ifndef _MEMORY_H
#define _MEMORY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"

#if __AVX512F__
#define SIMD_COEF_32 16
#define SIMD_COEF_64 8
#elif __AVX2__
#define SIMD_COEF_32 8
#define SIMD_COEF_64 4
#elif __SSE2__
#define SIMD_COEF_32 4
#define SIMD_COEF_64 2
#elif __MMX__
#define SIMD_COEF_32 2
#define SIMD_COEF_64 1
#endif

/*
 * Standard alignments for mem_alloc_tiny().
 */
#define MEM_ALIGN_NONE			1
#define MEM_ALIGN_WORD			ARCH_SIZE
/*
 * These are hopefully suitable guesses.  They are right for only a subset of
 * the architectures/CPUs we support, yet our use of them does not require that
 * they be entirely correct.
 */
#ifdef _MSC_VER
#define MEM_ALIGN_CACHE			64
#else
#define MEM_ALIGN_CACHE			(ARCH_SIZE * 8)
#endif
#define MEM_ALIGN_PAGE			0x1000

/*
 * SIMD buffers need to be aligned to register size
 */
#if SIMD_COEF_32
#ifdef _MSC_VER
#define MEM_ALIGN_SIMD			16
#else
#define MEM_ALIGN_SIMD			(SIMD_COEF_32 * 4)
#endif
#else
#define MEM_ALIGN_SIMD			(16)
#endif

/*
 * Block size used by mem_alloc_tiny().
 */
#define MEM_ALLOC_SIZE			0x10000

/*
 * Use mem_alloc() instead of allocating a new block in mem_alloc_tiny()
 * if more than MEM_ALLOC_MAX_WASTE bytes would be lost.
 * This shouldn't be set too small, or mem_alloc_tiny() will keep calling
 * mem_alloc() for many allocations in a row, which might end up wasting even
 * more memory to malloc() overhead.
 */
#define MEM_ALLOC_MAX_WASTE		0xff

/*
 * Memory saving level, setting this high enough disables alignments (if the
 * architecture allows).
 */
extern unsigned int mem_saving_level;

/*
 * Allocates size bytes and returns a pointer to the allocated memory.
 * If an error occurs, the function does not return.
 */
extern void *mem_alloc_func(size_t size
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);
/*
 * this version same as mem_alloc, but initialized the memory
 * to NULL bytes, like CALLOC(3) function does
 */
extern void *mem_calloc_func(size_t count, size_t size
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

#if defined (MEMDBG_ON)
#define mem_alloc(a) mem_alloc_func(a,__FILE__,__LINE__)
#define mem_calloc(a,b) mem_calloc_func(a,b,__FILE__,__LINE__)
#define mem_alloc_tiny(a,b) mem_alloc_tiny_func(a,b,__FILE__,__LINE__)
#define mem_calloc_tiny(a,b) mem_calloc_tiny_func(a,b,__FILE__,__LINE__)
#define mem_alloc_copy(a,b,c) mem_alloc_copy_func(a,b,c,__FILE__,__LINE__)
#define str_alloc_copy(a) str_alloc_copy_func(a,__FILE__,__LINE__)
#define mem_alloc_align(a,b) mem_alloc_align_func(a,b,__FILE__,__LINE__)
#define mem_calloc_align(a,b,c) mem_calloc_align_func(a,b,c,__FILE__,__LINE__)
#else
#define mem_alloc(a) mem_alloc_func(a)
#define mem_calloc(a,b) mem_calloc_func(a,b)
#define mem_alloc_tiny(a,b) mem_alloc_tiny_func(a,b)
#define mem_calloc_tiny(a,b) mem_calloc_tiny_func(a,b)
#define mem_alloc_copy(a,b,c) mem_alloc_copy_func(a,b,c)
#define str_alloc_copy(a) str_alloc_copy_func(a)
#define mem_alloc_align(a,b) mem_alloc_align_func(a,b)
#define mem_calloc_align(a,b,c) mem_calloc_align_func(a,b,c)
#endif

/* These allow alignment and are wrappers to system-specific functions */
void *mem_alloc_align_func(size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

void *mem_calloc_align_func(size_t count, size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

/*
 * Frees memory allocated with mem_alloc() and sets the pointer to NULL.
 * Does nothing if the pointer is already NULL.
 */
#undef MEM_FREE

#ifdef _MSC_VER
#if !defined (MEMDBG_ON)
#define strdup(a) strdup_MSVC(a)
char *strdup_MSVC(const char *str);
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		_aligned_free((ptr)); \
		(ptr) = NULL; \
	} \
}
#else
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		MEMDBG_free(((const void*)ptr),__FILE__,__LINE__); \
		(ptr) = NULL; \
	} \
}
#endif

#else
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		free((ptr)); \
		(ptr) = NULL; \
	} \
}
#endif

/*
 * Similar to the above function, except the memory can't be freed.
 * This one is used to reduce the overhead.
 */
extern void *mem_alloc_tiny_func(size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

/*
 * this version same as mem_alloc_tiny, but initialized the memory
 * to NULL bytes, like CALLOC(3) function does
 */
extern void *mem_calloc_tiny_func(size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

/*
 * Uses mem_alloc_tiny() to allocate the memory, and copies src in there.
 */
extern void *mem_alloc_copy_func(void *src, size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

/*
 * Similar to the above function, but for ASCIIZ strings.
 */
extern char *str_alloc_copy_func(char *src
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	);

/*
 * This will 'cleanup' the memory allocated by mem_alloc_tiny().  All
 * of that memory was 'blindly' allocated, and not freed up during
 * the run of john.  Now, it is 'cleaned' up.
 */
extern void cleanup_tiny_memory();


void dump_text(void *in, int len);
void dump_stuff(void *x, unsigned int size);
void dump_stuff_msg(const void *msg, void *x, unsigned int size);
void dump_stuff_noeol(void *x, unsigned int size);
void dump_stuff_msg_sepline(const void *msg, void *x, unsigned int size);
void dump_stuff_be(void *x, unsigned int size);
void dump_stuff_be_msg(const void *msg, void *x, unsigned int size);
void dump_stuff_be_noeol(void *x, unsigned int size);
void dump_stuff_be_msg_sepline(const void *msg, void *x, unsigned int size);

#if defined (SIMD_COEF_32) || defined(NT_X86_64) || defined (SIMD_PARA_MD5) || defined (SIMD_PARA_MD4) || defined (SIMD_PARA_SHA1)
void dump_stuff_mmx(void *x, unsigned int size, unsigned int index);
void dump_stuff_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_stuff_mmx_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_mmx_msg_sepline(const void *msg, void *buf, unsigned int size, unsigned int index);
// for flat input, we do want to see SHA512 without byte swapping.
void dump_stuff_mmx64(void *buf, unsigned int size, unsigned int index);
void dump_stuff_mmx64_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_mmx(void *x, unsigned int size, unsigned int index);
void dump_out_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_out_mmx_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_mmx_msg_sepline(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_shammx(void *x, unsigned int size, unsigned int index);
void dump_stuff_shammx_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_shammx(void *x, unsigned int size, unsigned int index);
void dump_out_shammx_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_shammx64(void *x, unsigned int size, unsigned int index);
void dump_stuff_shammx64_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_shammx64(void *x, unsigned int size, unsigned int index);
void dump_out_shammx64_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
#endif

#if defined (SIMD_PARA_MD5)
// these functions help debug arrays of contigious MD5 prepared PARA buffers. Seen in sunmd5 at the current time.
void dump_stuff_mpara_mmx(void *x, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_msg(const void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_msg_sepline(const void *msg, void *buf, unsigned int size, unsigned int index);
// a 'getter' to help debugging.  Returns a flat buffer, vs printing it out.
void getbuf_stuff_mpara_mmx(unsigned char *oBuf, void *buf, unsigned int size, unsigned int index);
#endif

/*
 * here, a stack buffer that is at least align-1 bytes LARGER than required, can be
 * properly aligned to 'align' bytes. So:   char tmpbuf[256+15], *aligned_buf=mem_align(tmpbuf,16);
 * will give you a stack buffer, aligned to 16 bytes.  There are bugs in some compilers which cause
 * JTR_ALIGN(x) to fail properly (such as a bug in bitcoin OMP mode for linux32)
 * Switched to a define macro for performance.
 */
#define mem_align(a,b) (void*)(((char*)(a))+(((b)-1)-(((size_t)((char*)(a))-1)&((b)-1))))


/*
 * 32-bit endian-swap a memory buffer in place. Size is in octets (so should
 * be a multiple of 4). From now on, this function may be used on any arch.
 */
void alter_endianity(void * x, unsigned int size);

/* 32-bit endian-swap a memory buffer in place. Count is in 32-bit words */
void alter_endianity_w(void *x, unsigned int count);

/* 64-bit endian-swap a memory buffer in place. Count is in 64-bit words */
void alter_endianity_w64(void *x, unsigned int count);

#if ARCH_ALLOWS_UNALIGNED
// we can inline these, to always use JOHNSWAP/JOHNSWAP64
// NOTE, more portable to use #defines to inline, than the MAYBE_INLINE within header files.
#if (ARCH_LITTLE_ENDIAN==0)
#define alter_endianity_to_BE(a,b)
#define alter_endianity_to_BE64(a,b)
#define alter_endianity_to_LE(ptr,word32_cnt) do{ \
    int i; \
    for (i=0;i<word32_cnt; i++) \
        ((ARCH_WORD_32*)ptr)[i] = JOHNSWAP(((ARCH_WORD_32*)ptr)[i]); \
}while(0)
#define alter_endianity_to_LE64(ptr,word64_cnt) do{ \
    int i; \
    for (i=0;i<word64_cnt; i++) \
        ((ARCH_WORD_64*)ptr)[i] = JOHNSWAP64(((ARCH_WORD_64*)ptr)[i]); \
}while(0)
#else
#define alter_endianity_to_LE(a,b)
#define alter_endianity_to_LE64(a,b)
#define alter_endianity_to_BE(ptr,word32_cnt) do{ \
    int i; \
    for (i=0;i<word32_cnt; i++) \
        ((ARCH_WORD_32*)ptr)[i] = JOHNSWAP(((ARCH_WORD_32*)ptr)[i]); \
}while(0)
#define alter_endianity_to_BE64(ptr,word64_cnt) do{ \
    int i; \
    for (i=0;i<word64_cnt; i++) \
        ((ARCH_WORD_64*)ptr)[i] = JOHNSWAP64(((ARCH_WORD_64*)ptr)[i]); \
}while(0)
#endif
#else
#if (ARCH_LITTLE_ENDIAN==0)
#define alter_endianity_to_BE(a,b)
#define alter_endianity_to_LE(a,b) do{alter_endianity_w(a,b);}while(0)
#define alter_endianity_to_BE64(a,b)
#define alter_endianity_to_LE64(a,b) do{alter_endianity_w64(a,b);}while(0)
#else
#define alter_endianity_to_BE(a,b) do{alter_endianity_w(a,b);}while(0)
#define alter_endianity_to_LE(a,b)
#define alter_endianity_to_BE64(a,b) do{alter_endianity_w64(a,b);}while(0)
#define alter_endianity_to_LE64(a,b)
#endif
#endif

#endif
