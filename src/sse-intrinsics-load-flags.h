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
 * New flags added for sha2 by JimF 2013. This change, and
 * all other modifications to this file by Jim are released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#ifndef __SSE_INTRINS_LOAD_FLAGS__
#define __SSE_INTRINS_LOAD_FLAGS__

/***************************************************************
 * WARNING!!!! any changes to these numbers requires a new
 * build of sse-intrinsics-32.S and sse-intrinsics-64.S
 ***************************************************************/

typedef enum {
	SSEi_MIXED_IN=0x0,           // input is an array of 16 __m128i ints that are properly SSE interleaved.  This is for 4 passwords (or 2 for 64 bit crypts). The data will be copied into a on the stack workspace
	SSEi_FLAT_IN=0x1,            // input is an array of 4 64 (2 128 for 64 bit crypts) byte 'flat' values, instead of a properly SSE 'mixed' 64 uint32's.
	/****  NOTE, only 1 of the above 2 can be used, AND the buffer must properly match.  ****/
	SSEi_RELOAD=0x2,             // crypt key will be results of last crypt
	SSEi_RELOAD_INP_FMT=0x6,     // (note contains SSEi_RELOAD bit also, it is 2&4) crypt key will be results of last crypt, however, it is in 'INPUT' format. Will not matter, unless PARA > 1
	SSEi_OUTPUT_AS_INP_FMT=0x8,  // Write final output, using 'INPUT' format. Will not matter, unless PARA > 1
	SSEi_SWAP_FINAL=0x10,        // swap results into machine native endianity.  Normally, results are left in crypt endianity
	SSEi_SKIP_FINAL_ADD=0x20,    // do NOT do a=a+init. ONLY valid if not doing reload, AND if format did out[0]-=init in binary.
	SSEi_2BUF_INPUT=0x40,        // input array is 2x in size.
	SSEi_2BUF_INPUT_FIRST_BLK=(0x40|0x80),  // input array 2x in size.  This is the first block, so we MUST rotate element 14/15 if in flat mode.
	SSEi_4BUF_INPUT=0x100,        // input array is 4x in size (This is seen in the dynamic type, for sha256. We have 256 byte input buffers there).
	SSEi_4BUF_INPUT_FIRST_BLK=(0x100|0x200),  // input array 4x in size.  This is the first block, so we MUST rotate element 14/15 if in flat mode.

	// this are specific to SHA2 hashes. Can be the same bit, since only 1 will be used (i.e. it is not valid to do SSE_CRYPT_SHA224|SSE_CRYPT_SHA224 and expect both to be loaded)
	// WARNING, SHA224 requires a FULL SHA256 width output buffer, and SHA384 requires a full SHA512 width output buffer.  This is to allow proper reloading and doing multi-limb crypts.
	SSEi_CRYPT_SHA224=0x1000,     // use SHA224 IV.
	SSEi_CRYPT_SHA384=0x1000      // use SHA384 IV.
} SSEi_FLAGS;


#endif /* __SSE_INTRINS_LOAD_FLAGS__  */
