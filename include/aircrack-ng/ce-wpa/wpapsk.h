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
 * This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail
 * dot com>
 * and Copyright (c) 2012-2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * hccap format was introduced by oclHashcat-plus, and it is described here:
 * http://hashcat.net/wiki/hccap
 * Code is based on  Aircrack-ng source
 */
#ifndef _WPAPSK_H
#define _WPAPSK_H

#include <assert.h>
#include <string.h>
#include <stdint.h>

#include <aircrack-ng/crypto/crypto.h>
#include <aircrack-ng/ce-wpa/arch.h>
#include <aircrack-ng/ce-wpa/jcommon.h>
#include <aircrack-ng/ce-wpa/johnswap.h>
#include <aircrack-ng/ce-wpa/crypto_engine.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_atoi(void);

int init_wpapsk(ac_crypto_engine_t * engine,
				const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
				int nparallel,
				int threadid);

#ifdef __cplusplus
}
#endif

#endif /* _WPAPSK_H */
