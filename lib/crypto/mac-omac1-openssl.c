// clang-format off
/**
 * \file      mac-omac1-openssl.c
 *
 * \brief     One-Key CBC MAC (OMAC1) hash with AES.
 *
 * \author    Joseph Benden <joe@benden.us>
 * \author    Jouni Malinen <j@w1.fi>
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
#include <config.h>
#endif

#include <stddef.h>                                                   // size_t
#include <stdint.h>                               // [u]int{8,16,32,64}_t types

#include <aircrack-ng/defs.h>
#include <aircrack-ng/crypto/crypto.h>
// clang-format on

API_EXPORT
int MAC_OMAC1_AES_Vector(size_t key_len,
						 const uint8_t key[static key_len],
						 size_t num_elem,
						 const uint8_t * addr[],
						 const size_t * len,
						 uint8_t * mac)
{
	int ret = -1;
	size_t outlen, i;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC * cmac = EVP_MAC_fetch(NULL, "cmac", NULL);
	OSSL_PARAM params[3];
	size_t params_n = 0;

	memset(params, 0, sizeof(params));
	if (key_len == 16)
		params[params_n++]
			= OSSL_PARAM_construct_utf8_string("cipher", "aes-128-cbc", 0);
	else if (key_len == 32)
		params[params_n++]
			= OSSL_PARAM_construct_utf8_string("cipher", "aes-256-cbc", 0);
	else
		return (-1);

	EVP_MAC_CTX * c = EVP_MAC_CTX_new(cmac);
	EVP_MAC_init(c, key, key_len, params);
	for (i = 0; i < num_elem; i++)
	{
		EVP_MAC_update(c, addr[i], len[i]);
	}
	EVP_MAC_final(c, mac, &outlen, 20);

	EVP_MAC_CTX_free(c);

	ret = 0;
#else
	CMAC_CTX * ctx;

	ctx = CMAC_CTX_new();
	if (ctx == NULL) return -1;

	if (key_len == 32)
	{
		if (!CMAC_Init(ctx, key, 32, EVP_aes_256_cbc(), NULL)) goto fail;
	}
	else if (key_len == 16)
	{
		if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) goto fail;
	}
	else
	{
		goto fail;
	}
	for (i = 0; i < num_elem; i++)
	{
		if (!CMAC_Update(ctx, addr[i], len[i])) goto fail;
	}
	if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16) goto fail;

	ret = 0;
fail:
	CMAC_CTX_free(ctx);
#endif

	return ret;
}
