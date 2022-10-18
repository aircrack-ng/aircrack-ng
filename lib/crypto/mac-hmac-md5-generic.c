// clang-format off
/**
 * \file      mac-hmac-md5-generic.c
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
#include "aircrack-ng/crypto/md5.h"
// clang-format on

API_EXPORT
int MAC_HMAC_MD5_Vector(size_t key_len,
						const uint8_t key[static key_len],
						size_t count,
						const uint8_t * addr[],
						const size_t * len,
						uint8_t mac[static DIGEST_MD5_MAC_LEN])
{
	// clang-format off
	uint8_t          k_pad[64]; /* padding - key XORd with ipad/opad */
	uint8_t          tk[DIGEST_MD5_MAC_LEN];
	const uint8_t   *_addr[6];
	size_t           i, _len[6];
	int              res;
	// clang-format on

	if (count > 5)
	{
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

	/* if key is longer than 64 bytes reset it to key = MD5(key) */
	if (key_len > 64)
	{
		if (Digest_MD5_Vector(1, &key, &key_len, tk)) return -1;
		key = tk;
		key_len = DIGEST_MD5_MAC_LEN;
	}

	/* the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);

	/* XOR key with ipad values */
	for (i = 0; i < 64; i++) k_pad[i] ^= 0x36;

	/* perform inner MD5 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < count; i++)
	{
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (Digest_MD5_Vector(1 + count, _addr, _len, mac)) return -1;

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);

	/* XOR key with opad values */
	for (i = 0; i < 64; i++) k_pad[i] ^= 0x5c;

	/* perform outer MD5 */
	// clang-format off
	_addr[0] = k_pad;
	_len[0]  = 64;
	_addr[1] = mac;
	_len[1]  = DIGEST_MD5_MAC_LEN;
	// clang-format on

	res = Digest_MD5_Vector(2, _addr, _len, mac);

	return res;
}

API_EXPORT
int MAC_HMAC_MD5(size_t key_len,
				 const uint8_t key[static key_len],
				 size_t data_len,
				 const uint8_t data[static data_len],
				 uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	return MAC_HMAC_MD5_Vector(key_len, key, 1, &data, &data_len, output);
}
