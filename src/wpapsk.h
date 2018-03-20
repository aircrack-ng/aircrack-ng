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
 * This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
 * and Copyright (c) 2012-2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * hccap format was introduced by oclHashcat-plus, and it is described here: http://hashcat.net/wiki/hccap
 * Code is based on  Aircrack-ng source
 */
#ifndef _WPAPSK_H
#define _WPAPSK_H

#include <string.h>
#include <assert.h>
#ifdef USE_GCRYPT
#include "gcrypt-openssl-wrapper.h"
#else
#include <openssl/hmac.h>
#endif
#include <stdint.h>
#include "arch.h"
#include "jcommon.h"
#include "johnswap.h"
#include "aircrack-ng.h"

extern unsigned char *xpmk1[MAX_THREADS];
extern unsigned char *xpmk2[MAX_THREADS];
extern unsigned char *xpmk3[MAX_THREADS];
extern unsigned char *xpmk4[MAX_THREADS];
extern unsigned char *xpmk5[MAX_THREADS];
extern unsigned char *xpmk6[MAX_THREADS];
extern unsigned char *xpmk7[MAX_THREADS];
extern unsigned char *xpmk8[MAX_THREADS];
extern unsigned char *xsse_hash1[MAX_THREADS];
extern unsigned char *xsse_crypt1[MAX_THREADS];
extern unsigned char *xsse_crypt2[MAX_THREADS];

#define PLAINTEXT_LENGTH	63 /* We can do 64 but spec. says 63 */

int threadxnt;
void init_atoi();
void init_ssecore(int);
void free_ssecore(int);
int init_wpapsk(char (*key)[MAX_THREADS], char *essid, int threadid);

struct wpapsk_password {
	uint32_t length;
	uint8_t  v[PLAINTEXT_LENGTH + 1];
};

typedef struct {
	uint32_t length;
	uint8_t  v[PLAINTEXT_LENGTH + 1];
} wpapsk_password;

extern wpapsk_password *wpapass[MAX_THREADS];

int count;

#if 0
static MAYBE_INLINE void prf_512(uint32_t * key, uint8_t * data, uint32_t * ret)
{
	HMAC_CTX ctx;
	char *text = (char*)"Pairwise key expansion";
	unsigned char buff[100];

	memcpy(buff, text, 22);
	memcpy(buff + 23, data, 76);
	buff[22] = 0;
	buff[76 + 23] = 0;
	HMAC_Init(&ctx, key, 32, EVP_sha1());
	HMAC_Update(&ctx, buff, 100);
	HMAC_Final(&ctx, (unsigned char *) ret, NULL);
	HMAC_CTX_cleanup(&ctx);
}
#endif

#endif /* _WPAPSK_H */
