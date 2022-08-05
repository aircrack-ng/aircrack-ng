// clang-format off
/**
 * \file      sha256.h
 *
 * \brief     The SHA-256 cryptographic hash function and PRF (IEEE 802.11r)
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

#ifndef LIB_CRYPTO_SHA256_H
#define LIB_CRYPTO_SHA256_H

#include <stddef.h>                                                   // size_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#ifndef API_IMPORT
# define API_IMPORT
#endif

#ifdef GCRYPT_WITH_SHA256
# define Digest_SHA256_CTX gcry_md_hd_t
# define DEFINE_SHA256_API 1
#endif

#ifdef OPENSSL_WITH_SHA256
# define Digest_SHA256_CTX EVP_MD_CTX
# define DEFINE_SHA256_API 1
#endif

#if !defined(GCRYPT_WITH_SHA256) && !defined(OPENSSL_WITH_SHA256)
# define DEFINE_SHA256_API 1
# define DEFINE_SHA256_CONTEXT 1
// # error "Must have a working SHA-2-256 algorithm implemented."
# define Digest_SHA256_CTX void
#endif

#define DIGEST_SHA256_MAC_LEN	32
#define DIGEST_SHA256_BLK_LEN	64

#ifdef DEFINE_SHA256_API

/**
 * \brief          SHA-2-256 context allocation
 *
 * \return         0 if unsuccessful, else a pointer to an allocated
 *                 SHA-2-256 context.
 */
API_IMPORT
Digest_SHA256_CTX * Digest_SHA256_Create( void );

/**
 * \brief          SHA-2-256 context deallocation
 *
 * \param[in] ctx  context to be destroyed
 */
API_IMPORT
void Digest_SHA256_Destroy( Digest_SHA256_CTX *ctx );

/**
 * \brief               SHA-2-256 context bit cloning
 *
 * \param[in,out]  dst  destination context for copy
 * \param[in]      src  source context for copy
 */
API_IMPORT
void Digest_SHA256_Clone( Digest_SHA256_CTX **dst, const Digest_SHA256_CTX *src );

/**
 * \brief          SHA-2-256 context setup
 *
 * \param[in] ctx  context to be initialized
 *
 * \return         0 if successful
 */
API_IMPORT
int Digest_SHA256_Init( Digest_SHA256_CTX *ctx );

/**
 * \brief            SHA-2-256 process buffer
 *
 * \param[in] ctx    SHA-2-256 context
 * \param[in] input  buffer holding the data
 * \param[in] ilen   length of the input data
 *
 * \return           0 if successful
 */
API_IMPORT
int Digest_SHA256_Update( Digest_SHA256_CTX		*ctx,
						  const uint8_t	        *input,
						  size_t				 ilen );

/**
 * \brief              SHA-2-256 final digest
 *
 * \param[in]  ctx     SHA-2-256 context
 * \param[out] output  SHA-2-256 checksum result
 *
 * \return             0 if successful
 */
API_IMPORT
int Digest_SHA256_Finish( Digest_SHA256_CTX *ctx,
						  uint8_t output[static DIGEST_SHA256_MAC_LEN] );

/**
 * \brief              Output = SHA-2-256( input buffer )
 *
 * \param[in]  input   buffer holding the data
 * \param[in]  ilen    length of the input data
 * \param[out] output  SHA-2-256 checksum result
 *
 * \return             0 if successful
 */
API_IMPORT
int Digest_SHA256( const uint8_t	*input,
				   size_t			 ilen,
				   uint8_t			 output[static DIGEST_SHA256_MAC_LEN] );

#endif

/**
 * \brief               Output = SHA-2-256( for all elements' data buffer )
 *
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addrs    array holding pointers to buffers holding data
 * \param[in]  lengths  array holding lengths of the buffers holding data
 * \param[out] output   SHA-2-256 checksum result
 *
 * \return              0 if successful
 */
API_IMPORT
int Digest_SHA256_Vector( size_t    		  count,
						  const uint8_t		 *addrs[static count],
						  const size_t		  lengths[static count],
						  uint8_t			  output[static DIGEST_SHA256_MAC_LEN] );

/**
 * \brief               Output = HMAC-SHA-2-256(vector of buffer data)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addr     array holding pointers to buffers holding data
 * \param[in]  len      array holding lengths of the buffers holding data
 * \param[out] mac      SHA-2-256 checksum result
 *
 * \return              0 if successful
 */
API_IMPORT
int MAC_HMAC_SHA256_Vector( size_t			 key_len,
							const uint8_t	 key[static key_len],
							size_t			 num_elem,
							const uint8_t	*addr[],
							const size_t	*len,
							uint8_t			 mac[static DIGEST_SHA256_MAC_LEN] );

/**
 * \brief               Output = HMAC-SHA-2-256(buffer data)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  data_len length of the buffers holding data
 * \param[in]  data     buffer holding data
 * \param[out] output   SHA-2-256 checksum result
 *
 * \return              0 if successful
 */
API_IMPORT
int MAC_HMAC_SHA256( size_t			key_len,
					 const uint8_t	key[static key_len],
					 size_t			data_len,
					 const uint8_t	data[static data_len],
					 uint8_t		output[static DIGEST_SHA256_MAC_LEN] );

/**
 * \brief IEEE Std 802.11-2012, 11.6.1.7.2 Key Derivation Function
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key. If the requested buf_len is not divisible by eight, the least
 * significant 1-7 bits of the last octet in the output are not part of the
 * requested output.
 *
 * \param[in]  key      Key for KDF
 * \param[in]  key_len  Length of the key in bytes
 * \param[in]  label    A unique label for each purpose of the PRF
 * \param[in]  data     Extra data to bind into the key
 * \param[in]  data_len Length of the data
 * \param[out] buf      Buffer for the generated pseudo-random key
 * \param[in]  buf_len  Number of bits of key to generate
 *
 * \return              0 if successful; otherwise, an error occurred.
 */
void Digest_SHA256_PRF_Bits( const uint8_t	*key,
						     size_t			 key_len,
						     const uint8_t	*label,
						     const uint8_t	*data,
						     size_t			 data_len,
						     uint8_t		*buf,
						     size_t			 buf_len_bits );

#endif /* LIB_CRYPTO_SHA256_H */
// clang-format on
