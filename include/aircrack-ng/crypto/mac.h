// clang-format off
/**
 * \file      mac.h
 *
 * \brief     Message Authenication Code algorithms
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

#ifndef LIB_CRYPTO_MAC_H
#define LIB_CRYPTO_MAC_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>                                                   // size_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#ifndef API_IMPORT
# define API_IMPORT
#endif

#ifdef GCRYPT_WITH_CMAC
# define Cipher_AES_CTX gcry_cipher_hd_t
#endif

#ifdef OPENSSL_WITH_CMAC
# define MAC_OMAC_CTX CMAC_CTX
#endif

#if !defined(GCRYPT_WITH_CMAC) && !defined(OPENSSL_WITH_CMAC)
// # warning "Missing an implementation of the CMAC algorithm."
#endif

#define CMAC_AES_128_MAC_LEN 16

/**
 * \brief               One-Key CBC MAC (OMAC1) hash with AES.
 *
 * This is a mode for using block cipher (AES in this case) for authentication.
 * OMAC1 was standardized with the name CMAC by NIST in a Special Publication
 * (SP) 800-38B.
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addr     array holding pointers to buffers holding data
 * \param[in]  len      array holding lengths of the buffers holding data
 * \param[out] mac      MAC (128-bits, i.e. 16 bytes) checksum result
 *
 * \return              0 if successful
 */
API_IMPORT
int	MAC_OMAC1_AES_Vector(size_t			 key_len,
					     const uint8_t	 key[static key_len],
					     size_t			 count,
					     const uint8_t	*addr[],
					     const size_t	*len,
					     uint8_t		*mac);

#endif /* LIB_CRYPTO_MAC_H */
// clang-format on
