// clang-format off
/**
 * \file      sha256.c
 *
 * \brief     The SHA-2-256 cryptographic hash function and PRF (IEEE 802.11r)
 *
 * The Secure Hash Algorithm 2 (256-bit) cryptographic hash function is
 * defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
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
#include "aircrack-ng/crypto/sha256.h"

API_EXPORT
int Digest_SHA256_Vector( size_t	 num_elem,
						  const uint8_t	*addr[static num_elem],
						  const size_t	len[static num_elem],
						  uint8_t	 mac[static DIGEST_SHA256_MAC_LEN] )
{
	Digest_SHA256_CTX * ctx = Digest_SHA256_Create();
	size_t i;

	if (!ctx) return -1;

	Digest_SHA256_Init(ctx);
	for (i = 0; i < num_elem; i++)
		Digest_SHA256_Update(ctx, addr[i], len[i]);
	Digest_SHA256_Finish(ctx, mac);
	Digest_SHA256_Destroy(ctx);

	return 0;
}

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86)               \
	|| defined(_M_X64) || defined(__ppc__) || defined(__ppc64__)               \
	|| defined(__powerpc__) || defined(__powerpc64__) || defined(__s390__)     \
	|| defined(__s390x__)
static inline
void WPA_PUT_LE16(uint8_t * a, uint_fast16_t val)
{
	a[1] = (uint8_t)(val >> 8u);
	a[0] = (uint8_t)(val & 0xff);
}
#else
void WPA_PUT_LE16(uint8_t * a, uint_fast16_t val)
{
	a[0] = (uint8_t)(val >> 8u);
	a[1] = (uint8_t)(val & 0xff);
}
#endif

void Digest_SHA256_PRF_Bits(const uint8_t	*key,
							size_t			 key_len,
							const uint8_t	*label,
							const uint8_t	*data,
							size_t			 data_len,
							uint8_t			*buf,
							size_t			 buf_len_bits)
{
	uint16_t		 counter = 1;
	size_t			 pos;
	size_t			 plen;
	uint8_t			 hash[DIGEST_SHA256_MAC_LEN];
	const uint8_t	*addr[4];
	size_t			 len[4];
	uint8_t			 counter_le[2];
	uint8_t			 length_le[2];
	size_t			 buf_len = (buf_len_bits + 7) / 8;

	addr[0] = counter_le;
	len[0]  = 2;
	addr[1] = label;
	len[1]  = ustrlen(label);
	addr[2] = data;
	len[2]  = data_len;
	addr[3] = length_le;
	len[3]  = sizeof(length_le);

	WPA_PUT_LE16(length_le, (uint_fast16_t) buf_len_bits);
	pos = 0;

	while (pos < buf_len)
	{
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= DIGEST_SHA256_MAC_LEN)
		{
			MAC_HMAC_SHA256_Vector(key_len, key, 4, addr, len, &buf[pos]);
			pos += DIGEST_SHA256_MAC_LEN;
		}
		else
		{
			MAC_HMAC_SHA256_Vector(key_len, key, 4, addr, len, hash);
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8)
	{
		const uint8_t mask = (uint8_t)(0xff << (8u - buf_len_bits % 8));

		buf[pos - 1] &= mask;
	}
}
// clang-format on
