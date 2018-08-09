/*
 * Copyright (C) 2018 Joseph Benden <joe@benden.us>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include "simd-intrinsics.h"
#include "wpapsk.h"
#ifdef USE_GCRYPT
#include "gcrypt-openssl-wrapper.h"
#include "sha1-git.h"
#else
#include <openssl/hmac.h>
#include <openssl/sha.h>
// We don't use EVP. Bite me
#include <openssl/rc4.h>
#include <openssl/aes.h>
#if HAVE_OPENSSL_CMAC_H
#include <openssl/cmac.h>
#endif
#endif

#include "aircrack-util/trampoline.h"

#include "crypto_engine.h"

// #define XDEBUG

#if defined(HAVE_OPENSSL_CMAC_H) || defined(GCRYPT_WITH_CMAC_AES)

/* Code borrowed from https://w1.fi/wpa_supplicant/ starts */

#define CMAC_AES_128_MAC_LEN 16
#define SHA256_MAC_LEN 32
typedef uint16_t u16;
typedef uint8_t u8;

static inline void WPA_PUT_LE16(u8 *a, u16 val)
{
	a[1] = (u8) (val >> 8u);
	a[0] = (u8) (val & 0xff);
}

static void sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA256_CTX ctx;
	size_t i;

	SHA256_Init(&ctx);
	for (i = 0; i < num_elem; i++) {
		SHA256_Update(&ctx, addr[i], len[i]);
	}

	SHA256_Final(mac, &ctx);
}

static void hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
                               const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	const u8 *_addr[6];
	size_t _len[6], i;

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	sha256_vector(1 + num_elem, _addr, _len, mac);

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	sha256_vector(2, _addr, _len, mac);
}

static void sha256_prf_bits(const u8 *key, size_t key_len, const char *label,
                            const u8 *data, size_t data_len, u8 *buf, size_t buf_len_bits)
{
	u16 counter = 1;
	size_t pos, plen;
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];
	u8 counter_le[2], length_le[2];
	size_t buf_len = (buf_len_bits + 7) / 8;

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (u8 *) label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, (u16) buf_len_bits);
	pos = 0;

	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_MAC_LEN) {
			hmac_sha256_vector(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA256_MAC_LEN;
		} else {
			hmac_sha256_vector(key, key_len, 4, addr, len, hash);
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		u8 mask = (u8) (0xff << (8u - buf_len_bits % 8));
		buf[pos - 1] &= mask;
	}
}
#endif /* HAVE_OPENSSL_CMAC_H || GCRYPT_WITH_CMAC_AES */

EXPORT int ac_crypto_engine_supported_features(void)
{
#if defined(JOHN_AVX512F)
	return SIMD_SUPPORTS_AVX512F;
#elif defined(JOHN_AVX2)
	return SIMD_SUPPORTS_AVX2;
#elif defined(JOHN_AVX)
	return SIMD_SUPPORTS_AVX;
#elif defined(JOHN_SSE2)
	return SIMD_SUPPORTS_SSE2;
#elif defined(JOHN_NEON)
	return SIMD_SUPPORTS_NEON;
#elif defined(JOHN_ASIMD)
	return SIMD_SUPPORTS_ASIMD;
#elif defined(JOHN_POWER8)
	return SIMD_SUPPORTS_POWER8;
#elif defined(JOHN_ALTIVEC)
	return SIMD_SUPPORTS_ALTIVEC;
#else
	return SIMD_SUPPORTS_NONE;
#endif
}

EXPORT int ac_crypto_engine_simd_width()
{
#ifdef SIMD_COEF_32
	return SIMD_COEF_32;
#else
	return 1;
#endif
}

EXPORT int ac_crypto_engine_init(ac_crypto_engine_t *engine)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_init(%p)\n", engine);
#endif

	init_atoi();

	engine->essid =
		mem_calloc_align(1, ESSID_LENGTH + 1, MEM_ALIGN_SIMD);

	engine->essid_length = 0;

	for (int i = 0; i < MAX_THREADS; ++i)
		engine->thread_data[i] = NULL;

	return 0;
}

EXPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_destroy(%p)\n", engine);
#endif

	MEM_FREE(engine->essid);
	engine->essid = NULL;
}

EXPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine,
									   const uint8_t *essid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_set_essid(%p, %s)\n", engine, essid);
#endif
	memccpy(engine->essid, essid, 0, ESSID_LENGTH);
	engine->essid_length = (uint32_t) strlen((char*) essid);
}

EXPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine,
										int threadid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_thread_init(%p, %d)\n", engine, threadid);
#endif

	// allocate per-thread data.
	engine->thread_data[threadid] = mem_calloc_align(1, sizeof(struct ac_crypto_engine_perthread), MEM_ALIGN_SIMD);

	return 0;
}

EXPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t *engine,
											int threadid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(
		stderr, "ac_crypto_engine_thread_destroy(%p, %d)\n", engine, threadid);
#endif

	if (engine->thread_data[threadid] != NULL)
	{
		MEM_FREE(engine->thread_data[threadid]);
		engine->thread_data[threadid] = NULL;
	}
}

EXPORT uint8_t* ac_crypto_engine_get_pmk(ac_crypto_engine_t *engine, int threadid, int index)
{
	return (uint8_t*) engine->thread_data[threadid]->pmk + (sizeof(wpapsk_hash) * index);
}

EXPORT uint8_t* ac_crypto_engine_get_ptk(ac_crypto_engine_t *engine, int threadid, int index)
{
	return (uint8_t*) engine->thread_data[threadid]->ptk + (20 * index);
}

EXPORT void ac_crypto_engine_calc_pke(ac_crypto_engine_t *engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid)
{
	uint8_t *pke = engine->thread_data[threadid]->pke;

	assert(pke != NULL);

	/* pre-compute the key expansion buffer */
	memcpy(pke, "Pairwise key expansion", 23);
	if (memcmp(stmac, bssid, 6) < 0)
	{
		memcpy(pke + 23, stmac, 6);
		memcpy(pke + 29, bssid, 6);
	}
	else
	{
		memcpy(pke + 23, bssid, 6);
		memcpy(pke + 29, stmac, 6);
	}
	if (memcmp(snonce, anonce, 32) < 0)
	{
		memcpy(pke + 35, snonce, 32);
		memcpy(pke + 67, anonce, 32);
	}
	else
	{
		memcpy(pke + 35, anonce, 32);
		memcpy(pke + 67, snonce, 32);
	}
}

/* derive the PMK from the passphrase and the essid */
EXPORT void ac_crypto_engine_calc_one_pmk(const uint8_t *key,
										  const uint8_t *essid_pre,
										  uint32_t essid_pre_len,
										  uint8_t pmk[40])
{
	int i, j, slen;
	unsigned char buffer[65];
	char essid[33 + 4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	assert(essid_pre != NULL);

	if (essid_pre_len > 32)
	{
		essid_pre_len = 32;
	}

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, essid_pre_len);
	slen = (int) essid_pre_len + 4;

	/* setup the inner and outer contexts */

	memset(buffer, 0, sizeof(buffer));
	strncpy((char *) buffer, (char*) key, sizeof(buffer) - 1);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x36;

	SHA1_Init(&ctx_ipad);
	SHA1_Update(&ctx_ipad, buffer, 64);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x6A;

	SHA1_Init(&ctx_opad);
	SHA1_Update(&ctx_opad, buffer, 64);

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(),
		 key,
		 (int) strlen((char*) key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk,
		 NULL);
	memcpy(buffer, pmk, 20);

	for (i = 1; i < 4096; i++)
	{
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	HMAC(EVP_sha1(),
		 (unsigned char *) key,
		 (int) strlen((char*) key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk + 20,
		 NULL);
	memcpy(buffer, pmk + 20, 20);

	for (i = 1; i < 4096; i++)
	{
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j + 20] ^= buffer[j];
	}
}

EXPORT void
ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine,
						  const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
						  const int nparallel,
						  const int threadid)
{
	wpapsk_hash *pmk = engine->thread_data[threadid]->pmk;

	// PMK calculation
#ifdef SIMD_CORE
	if (nparallel >= 4)
	{
		init_wpapsk(engine, key, nparallel, threadid);
	}
	else
#endif
		for (int j = 0; j < nparallel; ++j)
		{
#ifdef XDEBUG
			printf("%lu: Trying: %s\n", pthread_self(), (char *) key[j].v);
#endif
			ac_crypto_engine_calc_one_pmk(
				key[j].v,
				(uint8_t*) engine->essid,
				engine->essid_length,
				(uint8_t*) (&pmk[j]));
		}
}

EXPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine,
                                      const uint8_t keyver,
									  int vectorIdx,
									  int threadid)
{
	uint8_t *ptk = engine->thread_data[threadid]->ptk;
	wpapsk_hash *pmk = engine->thread_data[threadid]->pmk;

	if (keyver < 3) {
		for (int i = 0; i < 4; i++) {
			*(engine->thread_data[threadid]->pke + 99) = (unsigned char) i;

			HMAC(EVP_sha1(),
			     (&pmk[vectorIdx]),
			     32,
			     engine->thread_data[threadid]->pke,
			     100,
			     &ptk[vectorIdx] + i * 20,
			     NULL);
		}
	}
#if defined(HAVE_OPENSSL_CMAC_H) || defined(GCRYPT_WITH_CMAC_AES)
	else
	{
		uint8_t data[64 + 12];

		uint8_t *pke = &engine->thread_data[threadid]->pke[23];

		memset(data, 0, sizeof(data));
		memcpy(data, pke, 6);
		memcpy(data + 6, pke + 6, 6);
		memcpy(data + 12, pke + 35 - 23, 64);

		sha256_prf_bits((unsigned char*)(pmk[vectorIdx].v), 32, "Pairwise key expansion", data, 76, ptk, 48 * 8);
	}
#endif
}

EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine,
									  const uint8_t eapol[256],
									  const uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
									  const uint8_t keyver,
									  const int vectorIdx,
									  const int threadid)
{
	uint8_t *ptk = engine->thread_data[threadid]->ptk;

	if (keyver == 1)
		HMAC(EVP_md5(),
			 &ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
	else if (keyver == 2)
		HMAC(EVP_sha1(),
			 &ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
#if defined(HAVE_OPENSSL_CMAC_H) || defined(GCRYPT_WITH_CMAC_AES)
	else if (keyver == 3)
	{
		size_t miclen = CMAC_AES_128_MAC_LEN;
		CMAC_CTX *ctx = NULL;

		// Compute MIC
		ctx = CMAC_CTX_new();
		CMAC_Init(ctx, ptk, 16, EVP_aes_128_cbc(), 0);
		CMAC_Update(ctx, eapol, eapol_size);
		CMAC_Final(ctx, mic[vectorIdx], &miclen);
		CMAC_CTX_free(ctx);
	}
#else
	else if (keyver == 3)
	{
		fprintf(stderr, "Key version %d is only supported when OpenSSL (or similar) supports CMAC.\n", keyver);
		abort();
	}
#endif /* HAVE_OPENSSL_CMAC_H */
	else
	{
		fprintf(stderr, "Unsupported key version %d encountered.\n", keyver);
		abort();
	}
}

EXPORT int
ac_crypto_engine_wpa_crack(ac_crypto_engine_t *engine,
						   const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
						   const uint8_t eapol[256],
						   const uint32_t eapol_size,
						   uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
						   const uint8_t keyver,
						   const uint8_t cmpmic[20],
						   const int nparallel,
						   const int threadid)
{
	ac_crypto_engine_calc_pmk(engine, key, nparallel, threadid);

	for (int j = 0; j < nparallel; ++j)
	{
		/* compute the pairwise transient key and the frame MIC */

		ac_crypto_engine_calc_ptk(engine, keyver, j, threadid);

		ac_crypto_engine_calc_mic(
			engine, eapol, eapol_size, mic, keyver, j, threadid);

		/* did we successfully crack it? */
		if (memcmp(mic[j], cmpmic, 16) == 0)
		{
			return j;
		}
	}

	return -1;
}