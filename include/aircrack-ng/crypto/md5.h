// clang-format off
/**
 * \file      md5.h
 *
 * \brief     The MD5 message digest algorithm (hash function)
 *
 * \warning   MD5 is considered a weak digest and its use constitutes a
 *            security risk. We recommend considering stronger digests instead.
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

#ifndef LIB_CRYPTO_MD5_H
#define LIB_CRYPTO_MD5_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef GCRYPT_WITH_MD5
# define Digest_MD5_CTX gcry_md_hd_t
# define DEFINE_MD5_API 1
#endif

#ifdef OPENSSL_WITH_MD5
# define Digest_MD5_CTX EVP_MD_CTX
# define DEFINE_MD5_API 1
#endif

#if !defined(GCRYPT_WITH_MD5) && !defined(OPENSSL_WITH_MD5)
# define DEFINE_MD5_API 1
# define DEFINE_MD5_CONTEXT 1
#endif

#define DIGEST_MD5_MAC_LEN	16
#define DIGEST_MD5_BLK_LEN	64

#ifdef DEFINE_MD5_CONTEXT

/**
 * \brief     MD5 context structure
 *
 * \warning   MD5 is considered a weak digest and its use constitutes a
 *            security risk. We recommend considering stronger digests instead.
 */
typedef struct Digest_MD5_CTX
{
	uint32_t	total[2];	/*!< The number of bytes processed  */
	uint32_t	state[4];	/*!< The intermediate digest state  */
	uint8_t		buffer[DIGEST_MD5_BLK_LEN];	/*!< The data block being processed */
} Digest_MD5_CTX;

#endif

#ifdef DEFINE_MD5_API

/**
 * \brief          MD5 context allocation
 *
 * \return         0 if unsuccessful, else a pointer to an allocated
 *                 MD5 context.
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
API_IMPORT
Digest_MD5_CTX * Digest_MD5_Create( void );

/**
 * \brief          MD5 context deallocation
 *
 * \param[in] ctx  context to be destroyed
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
API_IMPORT
void Digest_MD5_Destroy( Digest_MD5_CTX *ctx );

/**
 * \brief          MD5 context setup
 *
 * \param[in] ctx  context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
API_IMPORT
int Digest_MD5_Init( Digest_MD5_CTX *ctx );

/**
 * \brief            MD5 process buffer
 *
 * \param[in] ctx    MD5 context
 * \param[in] input  buffer holding the data
 * \param[in] ilen   length of the input data
 *
 * \return           0 if successful
 *
 * \warning          MD5 is considered a weak message digest and its use
 *                   constitutes a security risk. We recommend considering
 *                   stronger message digests instead.
 */
API_IMPORT
int Digest_MD5_Update( Digest_MD5_CTX	*ctx,
					   const uint8_t	*input,
					   size_t			 ilen );

/**
 * \brief              MD5 final digest
 *
 * \param[in]  ctx     MD5 context
 * \param[out] output  MD5 checksum result
 *
 * \return             0 if successful
 *
 * \warning            MD5 is considered a weak message digest and its use
 *                     constitutes a security risk. We recommend considering
 *                     stronger message digests instead.
 */
API_IMPORT
int Digest_MD5_Finish( Digest_MD5_CTX	*ctx,
					   uint8_t			 output[static DIGEST_MD5_MAC_LEN] );

/**
 * \brief          MD5 process data block (internal use only)
 *
 * \param[in] ctx  MD5 context
 * \param[in] data buffer holding one block of data
 *
 * \return         0 if successful
 *
 * \warning        MD5 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
API_IMPORT
int Digest_Internal_MD5_Process( Digest_MD5_CTX		*ctx,
								 const uint8_t		 data[static DIGEST_MD5_BLK_LEN] );

/**
 * \brief              Output = MD5( input buffer )
 *
 * \param[in]  input   buffer holding the data
 * \param[in]  ilen    length of the input data
 * \param[out] output  MD5 checksum result
 *
 * \return             0 if successful
 *
 * \warning            MD5 is considered a weak message digest and its use
 *                     constitutes a security risk. We recommend considering
 *                     stronger message digests instead.
 */
API_IMPORT
int Digest_MD5( const uint8_t	*input,
				size_t			 ilen,
				uint8_t			 output[static DIGEST_MD5_MAC_LEN] );

#endif

/**
 * \brief               Output = MD5( for all elements' data buffer )
 *
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addrs    array holding pointers to buffers holding data
 * \param[in]  lengths  array holding lengths of the buffers holding data
 * \param[out] output   MD5 checksum result
 *
 * \return              0 if successful
 *
 * \warning             MD5 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int Digest_MD5_Vector( size_t			 count,
					   const uint8_t	*addrs[static count],
					   const size_t		 lengths[static count],
					   uint8_t			 output[static DIGEST_MD5_MAC_LEN] );

/**
 * \brief               Output = HMAC-MD5(vector of buffer data) (See: RFC 2104)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  count    number of elements in both addrs and lengths arrays
 * \param[in]  addr     array holding pointers to buffers holding data
 * \param[in]  len      array holding lengths of the buffers holding data
 * \param[out] mac      MD5 checksum result
 *
 * \return              0 if successful
 *
 * \warning             MD5 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int MAC_HMAC_MD5_Vector( size_t			 key_len,
						 const uint8_t	 key[static key_len],
						 size_t			 num_elem,
						 const uint8_t	*addr[],
						 const size_t	*len,
						 uint8_t		 mac[static DIGEST_MD5_MAC_LEN] );

/**
 * \brief               Output = HMAC-MD5(buffer data) (See: RFC 2104)
 *
 * \param[in]  key_len  length of the key in bytes
 * \param[in]  key      buffer holding the key data
 * \param[in]  data_len length of the buffers holding data
 * \param[in]  data     buffer holding data
 * \param[out] output   MD5 checksum result
 *
 * \return              0 if successful
 *
 * \warning             MD5 is considered a weak message digest and its use
 *                      constitutes a security risk. We recommend considering
 *                      stronger message digests instead.
 */
API_IMPORT
int MAC_HMAC_MD5( size_t		key_len,
				  const uint8_t	key[static key_len],
				  size_t		data_len,
				  const uint8_t	data[static data_len],
				  uint8_t		output[static DIGEST_MD5_MAC_LEN] );

#endif /* LIB_CRYPTO_MD5_H */
// clang-format on
