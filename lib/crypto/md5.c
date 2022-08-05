// clang-format off
/**
 * \file      md5.c
 *
 * \brief     The MD5 message digest algorithm (hash function)
 *
 * \warning   MD5 is considered a weak digest and its use constitutes a
 *            security risk. We recommend considering stronger digests instead.
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
int Digest_MD5_Vector(size_t num_elem,
					  const uint8_t * addr[static num_elem],
					  const size_t len[static num_elem],
					  uint8_t mac[static DIGEST_MD5_MAC_LEN])
{
	Digest_MD5_CTX * ctx = Digest_MD5_Create();
	size_t i;

	if (!ctx) return -1;

	Digest_MD5_Init(ctx);
	for (i = 0; i < num_elem; i++) Digest_MD5_Update(ctx, addr[i], len[i]);
	Digest_MD5_Finish(ctx, mac);

	Digest_MD5_Destroy(ctx);

	return 0;
}
