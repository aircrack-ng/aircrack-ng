// clang-format off
/**
 * \file      sha1.h
 *
 * \brief     The SHA-1 cryptographic hash functions
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined
 * in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
 *
 * \author    Joseph Benden <joe@benden.us>
 *
 * \license   Apache-2.0
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
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

#ifndef LIB_CRYPTO_SHA1_H
#define LIB_CRYPTO_SHA1_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

// {{{ wpapsk.c SHA-1 support
#include "sha1-git.h"

#define wpapsk_SHA1_CTX		blk_SHA_CTX
#define wpapsk_SHA1_Init	blk_SHA1_Init
#define wpapsk_SHA1_Update	blk_SHA1_Update
#define wpapsk_SHA1_Final	blk_SHA1_Final
#define wpapsk_SHA1_Clone(d,s)	do { memmove(d, s, sizeof(blk_SHA_CTX)); } while(0)
// }}}

#ifdef GCRYPT_WITH_SHA1
# define Digest_SHA1_CTX gcry_md_hd_t
# define DEFINE_SHA1_API 1
#endif

#ifdef OPENSSL_WITH_SHA1
# define Digest_SHA1_CTX EVP_MD_CTX
# define DEFINE_SHA1_API 1
#endif

#if !defined(GCRYPT_WITH_SHA1) && !defined(OPENSSL_WITH_SHA1)
# define DEFINE_SHA1_API 1
# define DEFINE_SHA1_CONTEXT 1
#endif

#define DIGEST_SHA1_MAC_LEN	20
#define DIGEST_SHA1_BLK_LEN	64

#ifdef DEFINE_SHA1_CONTEXT

/**
 * \brief     SHA-1 context structure
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
 */
typedef struct Digest_SHA1_CTX
{
	uint32_t	total[2];	/*!< The number of bytes processed  */
	uint32_t	state[5];	/*!< The intermediate digest state  */
	uint8_t		buffer[DIGEST_SHA1_BLK_LEN];	/*!< The data block being processed */
} Digest_SHA1_CTX;

#endif

#ifdef DEFINE_SHA1_API

/**
 * \brief          SHA-1 context allocation
 *
 * \return         0 if unsuccessful, else a pointer to an allocated
 *                 SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
Digest_SHA1_CTX * Digest_SHA1_Create( void );

/**
 * \brief          SHA-1 context destruction
 *
 * \param[in] ctx  context to be destroyed
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
void Digest_SHA1_Destroy( Digest_SHA1_CTX *ctx );

/**
 * \brief               SHA-1 context bit cloning
 *
 * \param[in,out]  dst  destination context for copy
 * \param[in]      src  source context for copy
 *
 * \warning             SHA-1 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
void Digest_SHA1_Clone( Digest_SHA1_CTX **dst, const Digest_SHA1_CTX *src );

/**
 * \brief          SHA-1 context setup
 *
 * \param[in] ctx  context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
int Digest_SHA1_Init( Digest_SHA1_CTX *ctx );

/**
 * \brief            SHA-1 process buffer
 *
 * \param[in] ctx    SHA-1 context
 * \param[in] input  buffer holding the data
 * \param[in] iLen   length of the input data
 *
 * \return           0 if successful
 *
 * \warning          SHA-1 is considered a weak message digest and its use
 *                   constitutes a security risk. We recommend considering
 *                   stronger message digests instead.
 */
int Digest_SHA1_Update( Digest_SHA1_CTX	*ctx,
                        const uint8_t	*input,
                        size_t			 iLen );

/**
 * \brief              SHA-1 final digest
 *
 * \param[in]  ctx     SHA-1 context
 * \param[out] output  SHA-1 checksum result
 *
 * \return             0 if successful
 *
 * \warning            SHA-1 is considered a weak message digest and its use
 *                     constitutes a security risk. We recommend considering
 *                     stronger message digests instead.
 */
int Digest_SHA1_Finish( Digest_SHA1_CTX	*ctx,
                        uint8_t			 output[static DIGEST_SHA1_MAC_LEN] );

/**
 * \brief          SHA-1 process data block (internal use only)
 *
 * \param[in] ctx  SHA-1 context
 * \param[in] data buffer holding one block of data
 *
 * \return         0 if successful
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
int Digest_Internal_SHA1_Process( Digest_SHA1_CTX	*ctx,
                                  const uint8_t	 	 data[static DIGEST_SHA1_BLK_LEN] );

/**
 * \brief              Output = SHA-1( input buffer )
 *
 * \param[in]  input   buffer holding the data
 * \param[in]  iLen    length of the input data
 * \param[out] output  SHA-1 checksum result
 *
 * \return             0 if successful
 *
 * \warning            SHA-1 is considered a weak message digest and its use
 *                     constitutes a security risk. We recommend considering
 *                     stronger message digests instead.
 */
int Digest_SHA1( const uint8_t	*input,
                 size_t		 	 iLen,
                 uint8_t		 output[static DIGEST_SHA1_MAC_LEN] );

#endif

/**
 * \brief               Output = SHA-1( for all elements' data buffer )
 *
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addrs    array holding pointers to buffers holding data
 * \param[in]  lengths  array holding lengths of the buffers holding data
 * \param[out] output   SHA-1 checksum result
 *
 * \return              0 if successful
 *
 * \warning             SHA-1 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int Digest_SHA1_Vector( size_t			 count,
                        const uint8_t	*addrs[static count],
	                const size_t		 lengths[static count],
	                uint8_t	 			 output[static DIGEST_SHA1_MAC_LEN] );

/**
 * \brief               Output = HMAC-SHA-1(vector of buffer data) (See: RFC 2104)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addr     array holding pointers to buffers holding data
 * \param[in]  len      array holding lengths of the buffers holding data
 * \param[out] mac      SHA-1 checksum result
 *
 * \return              0 if successful
 *
 * \warning             SHA-1 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int MAC_HMAC_SHA1_Vector( size_t			 key_len,
                          const uint8_t	 	 key[static key_len],
                          size_t			 num_elem,
                          const uint8_t		*addr[],
                          const size_t		*len,
                          uint8_t			 mac[static DIGEST_SHA1_MAC_LEN] );

/**
 * \brief               Output = HMAC-SHA-1(buffer data) (See: RFC 2104)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  data_len length of the buffers holding data
 * \param[in]  data     buffer holding data
 * \param[out] output   SHA-1 checksum result
 *
 * \return              0 if successful
 *
 * \warning             SHA-1 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int MAC_HMAC_SHA1( size_t			key_len,
                   const uint8_t	key[static key_len],
                   size_t			data_len,
                   const uint8_t	data[static data_len],
                   uint8_t			output[static DIGEST_SHA1_MAC_LEN] );

 /**
  * \brief SHA1-based key derivation function (PBKDF2) for IEEE 802.11i
  *
  * This function is used to derive PSK for WPA-PSK. For this protocol,
  * iterations is set to 4096 and buf_len to 32. This function is described in
  * IEEE Std 802.11-2004, Clause H.4. The main construction is from PKCS#5 v2.0.
  *
  * \param[in]  passphrase  ASCII passphrase
  * \param[in]  ssid        Station Set IDentifier
  * \param[in]  ssid_len    length of the buffer holding the SSID, in bytes
  * \param[in]  iterations  The number of iterations to run
  * \param[out] buf         buffer holding the generated key
  * \param[in]  buf_len     length of the buffer in bytes
  *
  * \return                 0 if successful
  *
  * \warning             SHA-1 is considered a weak message digest and its use
  *                      constitutes a security risk. We recommend considering
  *                      stronger message digests instead.
  */
 API_IMPORT
 int KDF_PBKDF2_SHA1( const uint8_t	*passphrase,
		      const uint8_t	*ssid,
		      size_t		 ssid_len,
		      size_t		 iterations,
		      uint8_t		*buf,
		      size_t		 buflen );

/**
 * \brief SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1)
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key (e.g., PMK in IEEE 802.11i).
 *
 * \param[in]   key       Key for PRF
 * \param[in]   key_len   Length of the key in bytes
 * \param[in]   label     A unique label for each purpose of the PRF
 * \param[in]   data      Extra data to bind into the key
 * \param[in]   data_len  Length of the data
 * \param[out]  buf       Buffer for the generated pseudo-random key
 * \param[in]   buf_len   Number of bytes of key to generate
 *
 * \return                0 if successful
 *
 * \warning               SHA-1 is considered a weak message digest and its use
 *                        constitutes a security risk. We recommend considering
 *                        stronger message digests instead.
 */
API_EXPORT
int SHA1_PRF( const uint8_t		*key,
              size_t			 key_len,
              const uint8_t 	*label,
              const uint8_t 	*data,
              size_t			 data_len,
              uint8_t			*buf,
              size_t			 buf_len );

#endif /* LIB_CRYPTO_SHA1_H */
// clang-format on
