// clang-format off
/**
 * \file      aes.h
 *
 * \brief     The Advanced Encryption Standard
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

#ifndef LIB_CRYPTO_AES_H
#define LIB_CRYPTO_AES_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#ifndef API_IMPORT
# define API_IMPORT
#endif

#ifdef GCRYPT_WITH_AES
# include <gcrypt.h>
# define Cipher_AES_CTX gcry_cipher_hd_t
#endif

#ifdef OPENSSL_WITH_AES
# include <openssl/evp.h>
# define Cipher_AES_CTX EVP_CIPHER_CTX
#endif

#if !defined(GCRYPT_WITH_AES) && !defined(OPENSSL_WITH_AES)
// # error "Missing an implementation of AES-128-CBC encryption."
#define Cipher_AES_CTX void
#endif

/**
 * \brief               AES encryption initialization function
 *
 * \param[in] key_len   length of the key, in bytes
 * \param[in] key       the secret key
 */
API_IMPORT
Cipher_AES_CTX *	Cipher_AES_Encrypt_Init(size_t			key_len,
											const uint8_t	key[static key_len]);

/**
 * \brief               AES encryption function
 *
 * \param[in]  ctx      AES context
 * \param[in]  plain    buffer holding the input data
 * \param[out] crypt    buffer for the output data
 *
 * \return              0 if successful
 */
API_IMPORT
int					Cipher_AES_Encrypt(Cipher_AES_CTX	*ctx,
									   const uint8_t	*plain,
									   uint8_t			*crypt);

/**
 * \brief               AES context destruction and resource clean-up
 *
 * \param[in]  ctx      AES context
 */
API_IMPORT
void				Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX *ctx);

#endif /* LIB_CRYPTO_AES_H */
// clang-format on
