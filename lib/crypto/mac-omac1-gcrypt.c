// clang-format off
/**
 * \file      mac-omac1-gcrypt.c
 *
 * \brief     One-Key CBC MAC (OMAC1) hash with AES.
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
#include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include <err.h>                                            // warn{,s} err{,x}
#include <gcrypt.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/crypto/mac.h"

API_EXPORT
int MAC_OMAC1_AES_Vector(size_t key_len,
						 const uint8_t key[static key_len],
						 size_t num_elem,
						 const uint8_t * addr[],
						 const size_t * len,
						 uint8_t * mac)
{
	gcry_mac_hd_t ctx;
	int ret = -1;
	size_t outlen = 16, i;

	if (gcry_mac_open(&ctx, GCRY_MAC_CMAC_AES, 0, NULL) != GPG_ERR_NO_ERROR)
	{
		errx(1, "Failed to open CMAC-AES-128-CBC");
		goto fail;
	}
	if (gcry_mac_setkey(ctx, key, key_len) != GPG_ERR_NO_ERROR)
	{
		warnx("Failed to setkey for CMAC-AES-128-CBC");
		goto fail;
	}

	for (i = 0; i < num_elem; i++)
	{
		if (gcry_mac_write(ctx, addr[i], len[i]) != GPG_ERR_NO_ERROR)
		{
			warnx("Failed to write CMAC-AES-128-CBC");
			goto fail;
		}
	}
	if (gcry_mac_read(ctx, mac, &outlen) != GPG_ERR_NO_ERROR || outlen != 16)
	{
		warnx("Failed to read CMAC-AES-128-CBC (got %zd)", outlen);
		goto fail;
	}

	ret = 0;

fail:
	gcry_mac_close(ctx);
	return (ret);
}
