// clang-format off
/**
 * \file      mac-omac1-generic.c
 *
 * \brief     One-Key CBC MAC (OMAC1) hash with AES.
 *
 * \author    Joseph Benden <joe@benden.us>
 *
 * \license   BSD-3-CLAUSE
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
 *  SPDX-License-Identifier: BSD-3-CLAUSE
 *
 ******************************************************************************
 * \endcond
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stddef.h>                                                   // size_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/crypto.h"
// clang-format on

API_EXPORT
int MAC_OMAC1_AES_Vector(size_t key_len,
						 const uint8_t key[static key_len],
						 size_t num_elem,
						 const uint8_t * addr[],
						 const size_t * len,
						 uint8_t * mac)
{
	UNUSED_PARAM(key);
	UNUSED_PARAM(num_elem);
	UNUSED_PARAM(addr);
	UNUSED_PARAM(len);
	UNUSED_PARAM(mac);

	fprintf(stderr,
			"OMAC1 is only supported when OpenSSL (or similar) "
			"supports CMAC.\n");

	return (-1);
}
