// clang-format off
/**
 * \file      sha1.c
 *
 * \brief     The SHA-1 cryptographic hash function
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined
 * in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
 *
 * \author    Joseph Benden <joe@benden.us>
 * \author    Jouni Malinen <j@wl.fi>
 *
 * \license   BSD-3-CLAUSE
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
 *  Portions Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *  SPDX-License-Identifier: BSD-3-CLAUSE
 *
 ******************************************************************************
 * \endcond
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/crypto/sha1.h"
// clang-format on

API_EXPORT
int Digest_SHA1_Vector(size_t num_elem,
					   const uint8_t * addr[static num_elem],
					   const size_t len[static num_elem],
					   uint8_t mac[static DIGEST_SHA1_MAC_LEN])
{
	Digest_SHA1_CTX * ctx = Digest_SHA1_Create();
	size_t i;

	if (!ctx) return -1;

	Digest_SHA1_Init(ctx);
	for (i = 0; i < num_elem; i++) Digest_SHA1_Update(ctx, addr[i], len[i]);
	Digest_SHA1_Finish(ctx, mac);
	Digest_SHA1_Destroy(ctx);

	return 0;
}

static int pbkdf2_sha1_f(const uint8_t * passphrase,
						 const uint8_t * ssid,
						 size_t ssid_len,
						 size_t iterations,
						 size_t count,
						 uint8_t digest[static DIGEST_SHA1_MAC_LEN])
{
	unsigned char tmp[DIGEST_SHA1_MAC_LEN], tmp2[DIGEST_SHA1_MAC_LEN];
	size_t i, j;
	unsigned char count_buf[4];
	const uint8_t * addr[2];
	size_t len[2];
	size_t passphrase_len = ustrlen(passphrase);

	addr[0] = ssid;
	len[0] = ssid_len;
	addr[1] = count_buf;
	len[1] = 4;

	/* F(P, S, c, i) = U1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 */

	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8) & 0xff;
	count_buf[3] = count & 0xff;
	if (MAC_HMAC_SHA1_Vector(passphrase_len, passphrase, 2, addr, len, tmp))
		return -1;
	memcpy(digest, tmp, DIGEST_SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++)
	{
		if (MAC_HMAC_SHA1(
				passphrase_len, passphrase, DIGEST_SHA1_MAC_LEN, tmp, tmp2))
			return -1;
		memcpy(tmp, tmp2, DIGEST_SHA1_MAC_LEN);
		for (j = 0; j < DIGEST_SHA1_MAC_LEN; j++) digest[j] ^= tmp2[j];
	}

	return 0;
}

API_EXPORT
int KDF_PBKDF2_SHA1(const uint8_t * passphrase,
					const uint8_t * ssid,
					size_t ssid_len,
					size_t iterations,
					uint8_t * buf,
					size_t buflen)
{
	unsigned int count = 0;
	unsigned char * pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[DIGEST_SHA1_MAC_LEN];

	while (left > 0)
	{
		count++;
		if (pbkdf2_sha1_f(
				passphrase, ssid, ssid_len, iterations, count, digest))
			return -1;
		plen = left > DIGEST_SHA1_MAC_LEN ? DIGEST_SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}

	return 0;
}

API_EXPORT
int SHA1_PRF(const uint8_t * key,
			 size_t key_len,
			 const uint8_t * label,
			 const uint8_t * data,
			 size_t data_len,
			 uint8_t * buf,
			 size_t buf_len)
{
	uint8_t counter = 0;
	size_t pos, plen;
	uint8_t hash[DIGEST_SHA1_MAC_LEN];
	size_t label_len = ustrlen(label) + 1;
	const uint8_t * addr[3];
	size_t len[3];

	// clang-format off
	addr[0] = label;
	len[0]  = label_len;
	addr[1] = data;
	len[1]  = data_len;
	addr[2] = &counter;
	len[2]  = 1;
	// clang-format on

	pos = 0;
	while (pos < buf_len)
	{
		plen = buf_len - pos;
		if (plen >= DIGEST_SHA1_MAC_LEN)
		{
			if (MAC_HMAC_SHA1_Vector(key_len, key, 3, addr, len, &buf[pos]))
				return -1;
			pos += DIGEST_SHA1_MAC_LEN;
		}
		else
		{
			if (MAC_HMAC_SHA1_Vector(key_len, key, 3, addr, len, hash))
				return -1;
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}

	return 0;
}
