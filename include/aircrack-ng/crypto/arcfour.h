// clang-format off
/**
 * \file      arcfour.h
 *
 * \brief     The ARCFOUR stream cipher
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
 *  Portitions are Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************
 * \endcond
 */

#ifndef LIB_CRYPTO_ARCFOUR_H
#define LIB_CRYPTO_ARCFOUR_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#ifndef API_IMPORT
# define API_IMPORT
#endif

#ifdef GCRYPT_WITH_ARCFOUR
# define Cipher_RC4_KEY gcry_cipher_hd_t
# define DEFINE_ARCFOUR_API 1
#endif

#ifdef OPENSSL_WITH_ARCFOUR
# if OPENSSL_VERSION_NUMBER < 0x30000000L
#  define Cipher_RC4_KEY RC4_KEY
#  define Cipher_RC4_set_key RC4_set_key
#  define Cipher_RC4 RC4
# else
#  define Cipher_RC4_KEY EVP_CIPHER_CTX
#  define DEFINE_ARCFOUR_API 1
# endif
#endif

#if !defined(GCRYPT_WITH_ARCFOUR) && !defined(OPENSSL_WITH_ARCFOUR)
# define DEFINE_ARCFOUR_API 1
# define DEFINE_ARCFOUR_CONTEXT 1
#endif

#ifdef DEFINE_ARCFOUR_CONTEXT

/**
 * \brief     ARC4 context structure
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 *
 */
typedef struct Cipher_RC4_KEY
{
	int			x;		/*!< permutation index */
	int			y;		/*!< permutation index */
	uint8_t		m[256];		/*!< permutation table */
} Cipher_RC4_KEY;

#endif

#ifdef DEFINE_ARCFOUR_API
/**
 * \brief              ARC4 key schedule
 *
 * \param[in] ctx      ARC4 context to be setup
 * \param[in] keylen   length of the key, in bytes
 * \param[in] key      the secret key
 *
 * \warning            ARC4 is considered a weak cipher and its use constitutes
 *                     a security risk. We recommend considering stronger
 *                     ciphers instead.
 */
API_IMPORT
void Cipher_RC4_set_key( Cipher_RC4_KEY *ctx, size_t keylen,
                         const uint8_t key[static keylen] );

/**
 * \brief               ARC4 cipher function
 *
 * \param[in]  ctx      ARC4 context
 * \param[in]  length   length of the input data
 * \param[in]  input    buffer holding the input data
 * \param[out] output   buffer for the output data
 *
 * \return              0 if successful
 *
 * \warning             ARC4 is considered a weak cipher and its use constitutes
 *                      a security risk. We recommend considering stronger
 *                      ciphers instead.
 */
API_IMPORT
int Cipher_RC4( Cipher_RC4_KEY *ctx, size_t length,
                const uint8_t input[static length],
                uint8_t output[static length] );

#endif

#endif /* LIB_CRYPTO_ARCFOUR_H */
// clang-format on
