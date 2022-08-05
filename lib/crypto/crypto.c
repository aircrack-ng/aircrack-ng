/*
 *  MD5, SHA-1, RC4 and AES implementations
 *
 *  Copyright (C) 2001-2004  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <err.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/crypto/crctable.h"
#include "aircrack-ng/aircrack-ng.h"
#include "aircrack-ng/support/common.h"

#define UBTOUL(b) ((unsigned long) (b))

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/provider.h>
#endif /* OpenSSL version >= 3.0 */

// libgcrypt thread callback definition for libgcrypt < 1.6.0
#ifdef USE_GCRYPT
#if GCRYPT_VERSION_NUMBER < 0x010600
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
#endif

API_EXPORT
void ac_crypto_init(void)
{
#ifdef USE_GCRYPT
// Register callback functions to ensure proper locking in the sensitive parts
// of libgcrypt < 1.6.0
#if GCRYPT_VERSION_NUMBER < 0x010600
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
	// Disable secure memory.
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	// Tell Libgcrypt that initialization has completed.
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#else
# if OPENSSL_VERSION_NUMBER >= 0x30000000L
      static bool loaded = false;
      OSSL_PROVIDER *legacy;

      if (loaded)
          return;

      legacy = OSSL_PROVIDER_load(NULL, "legacy");

      if (legacy) {
          OSSL_PROVIDER_load(NULL, "default");
          loaded = true;
      }
# endif /* OpenSSL version >= 3.0 */
#endif
}

/* RC4 encryption/ WEP decryption check */

/*  SSL decryption */

int
encrypt_wep(unsigned char * data, int len, unsigned char * key, int keylen)
{
	Cipher_RC4_KEY S;

	memset(&S, 0, sizeof(S));

	Cipher_RC4_set_key(&S, keylen, key);
	Cipher_RC4(&S, (size_t) len, data, data);

	return (0);
}

int
decrypt_wep(unsigned char * data, int len, unsigned char * key, int keylen)
{
	encrypt_wep(data, len, key, keylen);

	return (check_crc_buf(data, len - 4));
}

void calc_pmk(const uint8_t * key,
			  const uint8_t * essid_pre,
			  uint8_t pmk[static PMK_LEN])
{
	REQUIRE(key != NULL);
	REQUIRE(essid_pre != NULL);

	if (KDF_PBKDF2_SHA1(key, essid_pre, ustrlen(essid_pre), 4096, pmk, PMK_LEN)
		!= 0)
		errx(1, "Failed to compute PBKDF2 HMAC-SHA1");
}

void calc_mic(struct AP_info * ap,
			  unsigned char pmk[static 32],
			  unsigned char ptk[static 80],
			  unsigned char mic[static 20])
{
	REQUIRE(ap != NULL);

	int i;
	unsigned char pke[100];

	memcpy(pke, "Pairwise key expansion", 23);

	if (memcmp(ap->wpa.stmac, ap->bssid, 6) < 0)
	{
		memcpy(pke + 23, ap->wpa.stmac, 6);
		memcpy(pke + 29, ap->bssid, 6);
	}
	else
	{
		memcpy(pke + 23, ap->bssid, 6);
		memcpy(pke + 29, ap->wpa.stmac, 6);
	}

	if (memcmp(ap->wpa.snonce, ap->wpa.anonce, 32) < 0)
	{
		memcpy(pke + 35, ap->wpa.snonce, 32);
		memcpy(pke + 67, ap->wpa.anonce, 32);
	}
	else
	{
		memcpy(pke + 35, ap->wpa.anonce, 32);
		memcpy(pke + 67, ap->wpa.snonce, 32);
	}

	for (i = 0; i < 4; i++)
	{
		pke[99] = i;
		MAC_HMAC_SHA1(32, pmk, 100, pke, ptk + i * DIGEST_SHA1_MAC_LEN);
	}

	if (ap->wpa.keyver == 1)
	{
		MAC_HMAC_MD5(16, ptk, ap->wpa.eapol_size, ap->wpa.eapol, mic);
	}
	else
	{
		MAC_HMAC_SHA1(16, ptk, ap->wpa.eapol_size, ap->wpa.eapol, mic);
	}
}

static inline unsigned long calc_crc(const unsigned char * buf, int len)
{
	REQUIRE(buf != NULL);

	unsigned long crc = 0xFFFFFFFF;

	for (; len > 0; len--, buf++)
		crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

	return (~crc);
}

// without inversion, must be used for bit flipping attacks
static inline unsigned long calc_crc_plain(unsigned char * buf, int len)
{
	REQUIRE(buf != NULL);

	unsigned long crc = 0x00000000;

	for (; len > 0; len--, buf++)
		crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ (crc >> 8);

	return (crc);
}

/* CRC checksum verification routine */

int check_crc_buf(const unsigned char * buf, int len)
{
	REQUIRE(buf != NULL);

	unsigned long crc;

	crc = calc_crc(buf, len);
	buf += len;
	return (((crc) &0xFF) == buf[0] && ((crc >> 8) & 0xFF) == buf[1]
			&& ((crc >> 16) & 0xFF) == buf[2]
			&& ((crc >> 24) & 0xFF) == buf[3]);
}

/* Add CRC32 */

int add_crc32(unsigned char * data, int length)
{
	REQUIRE(data != NULL);

	unsigned long crc;

	crc = calc_crc(data, length);

	data[length] = (uint8_t)((crc) &0xFF);
	data[length + 1] = (uint8_t)((crc >> 8) & 0xFF);
	data[length + 2] = (uint8_t)((crc >> 16) & 0xFF);
	data[length + 3] = (uint8_t)((crc >> 24) & 0xFF);

	return (0);
}

int add_crc32_plain(unsigned char * data, int length)
{
	REQUIRE(data != NULL);

	unsigned long crc;

	crc = calc_crc_plain(data, length);

	data[length] = (uint8_t)((crc) &0xFF);
	data[length + 1] = (uint8_t)((crc >> 8) & 0xFF);
	data[length + 2] = (uint8_t)((crc >> 16) & 0xFF);
	data[length + 3] = (uint8_t)((crc >> 24) & 0xFF);

	return (0);
}

int calc_crc_buf(const unsigned char * buf, int len)
{
	REQUIRE(buf != NULL);

	return (int) (calc_crc(buf, len));
}

static void * get_da(unsigned char * wh)
{
	REQUIRE(wh != NULL);

	if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
		return (wh + 4);
	else
		return (wh + 4 + 6 * 2);
}

static void * get_sa(unsigned char * wh)
{
	REQUIRE(wh != NULL);

	if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
		return (wh + 4 + 6 * 2);
	else
		return (wh + 4 + 6);
}

int is_ipv6(void * wh)
{
	REQUIRE(wh != NULL);

	if (memcmp((char *) wh + 4, "\x33\x33", 2) == 0
		|| memcmp((char *) wh + 16, "\x33\x33", 2) == 0)
		return (1);

	return (0);
}

int is_dhcp_discover(void * wh, size_t len)
{
	REQUIRE(wh != NULL);

	if ((memcmp((char *) wh + 4, BROADCAST, 6) == 0
		 || memcmp((char *) wh + 16, BROADCAST, 6) == 0)
		&& (len >= 360 - 24 - 4 - 4 && len <= 380 - 24 - 4 - 4))
		return (1);

	return (0);
}

static inline int is_arp(void * wh, size_t len)
{
	UNUSED_PARAM(wh);

	const size_t arpsize = 8 + 8 + 10 * 2;

	/* remove non BROADCAST frames? could be anything, but
		 * chances are good that we got an arp response tho.   */

	if (len == arpsize || len == 54) return (1);

	return (0);
}

static inline int is_wlccp(void * wh, size_t len)
{
	UNUSED_PARAM(wh);

	const size_t wlccpsize = 58;

	if (len == wlccpsize) return (1);

	return (0);
}

int is_qos_arp_tkip(void * wh, int len)
{
	REQUIRE(wh != NULL);

	unsigned char * packet = (unsigned char *) wh;
	const int qosarpsize
		= (24 + 2) + 8 + (8 + (8 + 10 * 2)) + 8 + 4; // 82 in total

	if ((packet[1] & 3) == 1) // to ds
	{
		if (len == qosarpsize) // always wireless
			return (1);
	}

	if ((packet[1] & 3) == 2) // from ds
	{
		if (len == qosarpsize
			|| len == qosarpsize + 18) // wireless or padded wired
			return (1);
	}

	return (0);
}

static int is_spantree(void * wh)
{
	REQUIRE(wh != NULL);

	if (memcmp((char *) wh + 4, SPANTREE, 6) == 0
		|| memcmp((char *) wh + 16, SPANTREE, 6) == 0)
		return (1);

	return (0);
}

static int is_cdp_vtp(void * wh)
{
	REQUIRE(wh != NULL);

	if (memcmp((char *) wh + 4, CDP_VTP, 6) == 0
		|| memcmp((char *) wh + 16, CDP_VTP, 6) == 0)
		return (1);

	return (0);
}

/* weight is used for guesswork in PTW.  Can be null if known_clear is not for
 * PTW, but just for getting known clear-text.
 */
int known_clear(
	void * clear, int * clen, int * weight, unsigned char * wh, size_t len)
{
	REQUIRE(clear != NULL);
	REQUIRE(clen != NULL);
	REQUIRE(wh != NULL);

	unsigned char * ptr = clear;
	int num;

	if (is_arp(wh, len)) /*arp*/
	{
		len = sizeof(S_LLC_SNAP_ARP) - 1;
		memcpy(ptr, S_LLC_SNAP_ARP, len);
		ptr += len;

		/* arp hdr */
		len = 6;
		memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
		ptr += len;

		/* type of arp */
		len = 2;
		if (memcmp(get_da(wh), "\xff\xff\xff\xff\xff\xff", 6) == 0)
			memcpy(ptr, "\x00\x01", len);
		else
			memcpy(ptr, "\x00\x02", len);
		ptr += len;

		/* src mac */
		len = 6;
		memcpy(ptr, get_sa(wh), len);
		ptr += len;

		len = ptr - ((unsigned char *) clear);
		*clen = (int) len;
		if (weight) weight[0] = 256;
		return (1);
	}
	else if (is_wlccp(wh, len)) /*wlccp*/
	{
		len = sizeof(S_LLC_SNAP_WLCCP) - 1;
		memcpy(ptr, S_LLC_SNAP_WLCCP, len);
		ptr += len;

		/* wlccp hdr */
		len = 4;
		memcpy(ptr, "\x00\x32\x40\x01", len);
		ptr += len;

		/* dst mac */
		len = 6;
		memcpy(ptr, get_da(wh), len);
		ptr += len;

		len = ptr - ((unsigned char *) clear);
		*clen = (int) len;
		if (weight) weight[0] = 256;
		return (1);
	}
	else if (is_spantree(wh)) /*spantree*/
	{
		len = sizeof(S_LLC_SNAP_SPANTREE) - 1;
		memcpy(ptr, S_LLC_SNAP_SPANTREE, len);
		ptr += len;

		len = ptr - ((unsigned char *) clear);
		*clen = (int) len;
		if (weight) weight[0] = 256;
		return (1);
	}
	else if (is_cdp_vtp(wh)) /*spantree*/
	{
		len = sizeof(S_LLC_SNAP_CDP) - 1;
		memcpy(ptr, S_LLC_SNAP_CDP, len);
		ptr += len;

		len = ptr - ((unsigned char *) clear);
		*clen = (int) len;
		if (weight) weight[0] = 256;
		return (1);
	}
	else /* IP */
	{
		unsigned short iplen = htons((uint16_t)(len - 8));

		len = sizeof(S_LLC_SNAP_IP) - 1;
		memcpy(ptr, S_LLC_SNAP_IP, len);
		ptr += len;

		// version=4; header_length=20; services=0
		len = 2;
		memcpy(ptr, "\x45\x00", len);
		ptr += len;

		// ip total length
		memcpy(ptr, &iplen, len);
		ptr += len;

		/* no guesswork */
		if (!weight)
		{
			*clen = (int) (ptr - ((unsigned char *) clear));
			return (1);
		}
		/* setting IP ID 0 is ok, as we
				 * bruteforce it later
		 */
		// ID=0
		/*  len = 2; */
		memcpy(ptr, "\x00\x00", len);
		ptr += len;

		// ip flags=don't fragment
		/* len = 2; */
		memcpy(ptr, "\x40\x00", len);
		ptr += len;

		len = ptr - ((unsigned char *) clear);
		*clen = (int) len;

		memmove((char *) clear + 32, clear, len);
		memcpy((char *) clear + 32 + 14, "\x00\x00", 2); // ip flags=none

		num = 2;
		ALLEGE(weight);
		weight[0] = 220;
		weight[1] = 36;

		return (num);
	}
}

/* derive the pairwise transcient keys from a bunch of stuff */

int calc_ptk(struct WPA_ST_info * wpa, unsigned char pmk[static 32])
{
	REQUIRE(wpa != NULL);

	int i;
	unsigned char pke[100];
	unsigned char mic[20];

	memcpy(pke, "Pairwise key expansion", 23);

	if (memcmp(wpa->stmac, wpa->bssid, 6) < 0)
	{
		memcpy(pke + 23, wpa->stmac, 6);
		memcpy(pke + 29, wpa->bssid, 6);
	}
	else
	{
		memcpy(pke + 23, wpa->bssid, 6);
		memcpy(pke + 29, wpa->stmac, 6);
	}

	if (memcmp(wpa->snonce, wpa->anonce, 32) < 0)
	{
		memcpy(pke + 35, wpa->snonce, 32);
		memcpy(pke + 67, wpa->anonce, 32);
	}
	else
	{
		memcpy(pke + 35, wpa->anonce, 32);
		memcpy(pke + 67, wpa->snonce, 32);
	}

	for (i = 0; i < 4; i++)
	{
		pke[99] = (uint8_t) i;
		MAC_HMAC_SHA1(32, pmk, 100, pke, wpa->ptk + i * DIGEST_SHA1_MAC_LEN);
	}

	/* check the EAPOL frame MIC */

	if ((wpa->keyver & 0x07) == 1)
		MAC_HMAC_MD5(16, wpa->ptk, wpa->eapol_size, wpa->eapol, mic);
	else
		MAC_HMAC_SHA1(16, wpa->ptk, wpa->eapol_size, wpa->eapol, mic);

	return (memcmp(mic, wpa->keymic, 16) == 0); //-V512
}

static int init_michael(struct Michael * mic, const unsigned char key[static 8])
{
	REQUIRE(mic != NULL);

	mic->key0 = UBTOUL(key[0]) << 0UL | UBTOUL(key[1]) << 8UL
				| UBTOUL(key[2]) << 16UL | UBTOUL(key[3] << 24UL);
	mic->key1 = UBTOUL(key[4]) << 0UL | UBTOUL(key[5]) << 8UL
				| UBTOUL(key[6]) << 16UL | UBTOUL(key[7] << 24UL);

	// and reset the message
	mic->left = mic->key0;
	mic->right = mic->key1;
	mic->nBytesInM = 0UL;
	mic->message = 0UL;

	return (0);
}

static int michael_append_byte(struct Michael * mic, unsigned char byte)
{
	REQUIRE(mic != NULL);

	mic->message |= (UBTOUL(byte) << (8UL * mic->nBytesInM));
	mic->nBytesInM++;

	// Process the word if it is full.
	if (mic->nBytesInM >= 4UL)
	{
		mic->left ^= mic->message;
		mic->right ^= ROL32(mic->left, 17);
		mic->left += mic->right;
		mic->right ^= ((mic->left & 0xff00ff00) >> 8UL)
					  | ((mic->left & 0x00ff00ff) << 8UL);
		mic->left += mic->right;
		mic->right ^= ROL32(mic->left, 3);
		mic->left += mic->right;
		mic->right ^= ROR32(mic->left, 2);
		mic->left += mic->right;
		// Clear the buffer
		mic->message = 0UL;
		mic->nBytesInM = 0UL;
	}

	return (0);
}

static int michael_remove_byte(struct Michael * mic,
							   const unsigned char bytes[static 4])
{
	REQUIRE(mic != NULL);

	if (mic->nBytesInM == 0)
	{
		// Clear the buffer
		mic->message = UBTOUL(bytes[0]) << 0UL | UBTOUL(bytes[1]) << 8UL
					   | UBTOUL(bytes[2]) << 16UL | UBTOUL(bytes[3]) << 24UL;
		mic->nBytesInM = 4;
		mic->left -= mic->right;
		mic->right ^= ROR32(mic->left, 2);
		mic->left -= mic->right;
		mic->right ^= ROL32(mic->left, 3);
		mic->left -= mic->right;
		mic->right ^= ((mic->left & 0xff00ff00) >> 8UL)
					  | ((mic->left & 0x00ff00ff) << 8UL);
		mic->left -= mic->right;
		mic->right ^= ROL32(mic->left, 17);
		mic->left ^= mic->message;
	}
	mic->nBytesInM--;
	mic->message &= ~(0xFFUL << (8UL * mic->nBytesInM));

	return (0);
}

static int
michael_append(struct Michael * mic, unsigned char * bytes, int length)
{
	while (length > 0)
	{
		michael_append_byte(mic, *bytes++);
		length--;
	}
	return (0);
}

static int
michael_remove(struct Michael * mic, unsigned char * bytes, int length)
{
	while (length >= 4)
	{
		michael_remove_byte(mic, (bytes + length - 4));
		length--;
	}
	return (0);
}

static int michael_finalize(struct Michael * mic)
{
	REQUIRE(mic != NULL);

	// Append the minimum padding
	michael_append_byte(mic, 0x5a);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	// and then zeroes until the length is a multiple of 4
	while (mic->nBytesInM != 0)
	{
		michael_append_byte(mic, 0);
	}
	// The appendByte function has already computed the result.
	mic->mic[0] = (uint8_t)((mic->left >> 0) & 0xff);
	mic->mic[1] = (uint8_t)((mic->left >> 8) & 0xff);
	mic->mic[2] = (uint8_t)((mic->left >> 16) & 0xff);
	mic->mic[3] = (uint8_t)((mic->left >> 24) & 0xff);
	mic->mic[4] = (uint8_t)((mic->right >> 0) & 0xff);
	mic->mic[5] = (uint8_t)((mic->right >> 8) & 0xff);
	mic->mic[6] = (uint8_t)((mic->right >> 16) & 0xff);
	mic->mic[7] = (uint8_t)((mic->right >> 24) & 0xff);

	return (0);
}

static int michael_finalize_zero(struct Michael * mic)
{
	REQUIRE(mic != NULL);

	// Append the minimum padding
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	michael_append_byte(mic, 0);
	// and then zeroes until the length is a multiple of 4
	while (mic->nBytesInM != 0)
	{
		michael_append_byte(mic, 0);
	}
	// The appendByte function has already computed the result.
	mic->mic[0] = (uint8_t)((mic->left >> 0) & 0xff);
	mic->mic[1] = (uint8_t)((mic->left >> 8) & 0xff);
	mic->mic[2] = (uint8_t)((mic->left >> 16) & 0xff);
	mic->mic[3] = (uint8_t)((mic->left >> 24) & 0xff);
	mic->mic[4] = (uint8_t)((mic->right >> 0) & 0xff);
	mic->mic[5] = (uint8_t)((mic->right >> 8) & 0xff);
	mic->mic[6] = (uint8_t)((mic->right >> 16) & 0xff);
	mic->mic[7] = (uint8_t)((mic->right >> 24) & 0xff);

	return (0);
}

int michael_test(unsigned char key[static 8],
				 unsigned char * message,
				 int length,
				 unsigned char out[static 8])
{
	int i = 0;
	struct Michael mic0;
	struct Michael mic1;
	struct Michael mic2;
	struct Michael mic;

	init_michael(&mic0, (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00");
	init_michael(&mic1, (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00");
	init_michael(&mic2, (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00");

	michael_append_byte(&mic0, 0x02);
	michael_append_byte(&mic1, 0x01);
	michael_append_byte(&mic2, 0x03);

	michael_finalize(&mic0);
	michael_finalize_zero(&mic1);
	michael_finalize(&mic2);

	printf("Blub 2:");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", mic0.mic[i]);
	}
	printf("\n");

	printf("Blub 1:");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", mic1.mic[i]);
	}
	printf("\n");

	printf("Blub 3:");
	for (i = 0; i < 8; i++)
	{
		printf("%02X ", mic2.mic[i]);
	}
	printf("\n");

	init_michael(&mic, key);
	michael_append(&mic, message, length);
	michael_finalize(&mic);

	return (memcmp(mic.mic, out, 8) == 0);
}

int calc_tkip_mic_key(unsigned char * packet,
					  int length,
					  unsigned char key[static 8])
{
	REQUIRE(packet != NULL);

	int z, is_qos = 0;
	unsigned char smac[6], dmac[6], bssid[6];
	unsigned char prio[4];
	unsigned char message[4096];
	unsigned char * ptr;
	struct Michael mic;

	memset(message, 0, 4096);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length < z) return (0);

	/* Check if 802.11e (QoS) */
	if ((packet[0] & 0x80) == 0x80)
	{
		z += 2;
		is_qos = 1;
	}

	memset(prio, 0, 4);
	if (is_qos)
	{
		prio[0] = (uint8_t)(packet[z - 2] & 0x0f);
	}

	switch (packet[1] & 3)
	{
		case 0:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 1:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 2:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 16, 6);
			break;
		default:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 24, 6);
			break;
	}

	ptr = message;
	memcpy(ptr, dmac, 6);
	ptr += 6;
	memcpy(ptr, smac, 6);
	ptr += 6;
	memcpy(ptr, prio, 4);
	ptr += 4;
	memcpy(ptr, packet + z, length - z - 8UL);
	ptr += length - z - 8;
	memcpy(ptr, "\x5a", 1);
	ptr += 1;
	memcpy(ptr, ZERO, 4);
	ptr += 4;
	if ((ptr - message) % 4 > 0)
	{
		memcpy(ptr, ZERO, 4 - ((ptr - message) % 4));
		ptr += 4 - ((ptr - message) % 4);
	}

	init_michael(&mic, packet + length - 8);
	michael_remove(&mic, message, (int) (ptr - message));

	mic.mic[0] = (uint8_t)((mic.left >> 0) & 0xFF);
	mic.mic[1] = (uint8_t)((mic.left >> 8) & 0xFF);
	mic.mic[2] = (uint8_t)((mic.left >> 16) & 0xFF);
	mic.mic[3] = (uint8_t)((mic.left >> 24) & 0xFF);
	mic.mic[4] = (uint8_t)((mic.right >> 0) & 0xFF);
	mic.mic[5] = (uint8_t)((mic.right >> 8) & 0xFF);
	mic.mic[6] = (uint8_t)((mic.right >> 16) & 0xFF);
	mic.mic[7] = (uint8_t)((mic.right >> 24) & 0xFF);

	memcpy(key, mic.mic, 8);
	return (0);
}

int calc_tkip_mic(unsigned char * packet,
				  int length,
				  unsigned char ptk[static 80],
				  unsigned char value[static 8])
{
	REQUIRE(packet != NULL);

	int z, koffset = 0, is_qos = 0;
	unsigned char smac[6], dmac[6], bssid[6];
	unsigned char prio[4];
	struct Michael mic;

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length < z) return (0);

	/* Check if 802.11e (QoS) */
	if ((packet[0] & 0x80) == 0x80)
	{
		z += 2;
		is_qos = 1;
	}

	switch (packet[1] & 3)
	{
		case 0:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 1:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			koffset = 48 + 8;
			break;
		case 2:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 16, 6);
			koffset = 48;
			break;
		default:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 24, 6);
			break;
	}

	if (koffset != 48 && koffset != 48 + 8) return (1);

	init_michael(&mic, ptk + koffset);

	michael_append(&mic, dmac, 6);
	michael_append(&mic, smac, 6);

	memset(prio, 0, 4);
	if (is_qos)
	{
		prio[0] = (uint8_t)(packet[z - 2] & 0x0f);
	}
	michael_append(&mic, prio, 4);

	michael_append(&mic, packet + z, length - z);

	michael_finalize(&mic);

	memcpy(value, mic.mic, 8);

	return (0);
}

static const unsigned short TkipSbox[2][256]
	= {{0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154, 0x6050,
		0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A, 0x8F45, 0x1F9D,
		0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B, 0x41EC, 0xB367, 0x5FFD,
		0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B, 0x75C2, 0xE11C, 0x3DAE, 0x4C6A,
		0x6C5A, 0x7E41, 0xF502, 0x834F, 0x685C, 0x51F4, 0xD134, 0xF908, 0xE293,
		0xAB73, 0x6253, 0x2A3F, 0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1,
		0x0A0F, 0x2FB5, 0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD,
		0xEA9F, 0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
		0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397, 0xA6F5,
		0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED, 0xD4BE, 0x8D46,
		0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A, 0xBB6B, 0xC52A, 0x4FE5,
		0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194, 0x8ACF, 0xE910, 0x0406, 0xFE81,
		0xA0F0, 0x7844, 0x25BA, 0x4BE3, 0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD,
		0x21BC, 0x7048, 0xF104, 0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A,
		0xFD0E, 0xBF6D, 0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC,
		0x2E39, 0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
		0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83, 0x8CCA,
		0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76, 0xDB3B, 0x6456,
		0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4, 0x9F5D, 0xBD6E, 0x43EF,
		0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B, 0xD532, 0x8B43, 0x6E59, 0xDAB7,
		0x018C, 0xB164, 0x9CD2, 0x49E0, 0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF,
		0xF48E, 0x47E9, 0x1018, 0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1,
		0x73C7, 0x9751, 0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86,
		0x0F85, 0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
		0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9, 0xD938,
		0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7, 0x2DB6, 0x3C22,
		0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A, 0x038F, 0x59F8, 0x0980,
		0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8, 0x82C3, 0x29B0, 0x5A77, 0x1E11,
		0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A},
	   {0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491, 0x5060,
		0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC, 0x458F, 0x9D1F,
		0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB, 0xEC41, 0x67B3, 0xFD5F,
		0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B, 0xC275, 0x1CE1, 0xAE3D, 0x6A4C,
		0x5A6C, 0x417E, 0x02F5, 0x4F83, 0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2,
		0x73AB, 0x5362, 0x3F2A, 0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137,
		0x0F0A, 0xB52F, 0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F,
		0x9FEA, 0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
		0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713, 0xF5A6,
		0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6, 0xBED4, 0x468D,
		0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85, 0x6BBB, 0x2AC5, 0xE54F,
		0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411, 0xCF8A, 0x10E9, 0x0604, 0x81FE,
		0xF0A0, 0x4478, 0xBA25, 0xE34B, 0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F,
		0xBC21, 0x4870, 0x04F1, 0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5,
		0x0EFD, 0x6DBF, 0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88,
		0x392E, 0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
		0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B, 0xCA8C,
		0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD, 0x3BDB, 0x5664,
		0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8, 0x5D9F, 0x6EBD, 0xEF43,
		0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2, 0x32D5, 0x438B, 0x596E, 0xB7DA,
		0x8C01, 0x64B1, 0xD29C, 0xE049, 0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA,
		0x8EF4, 0xE947, 0x1810, 0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157,
		0xC773, 0x5197, 0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D,
		0x850F, 0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
		0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927, 0x38D9,
		0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733, 0xB62D, 0x223C,
		0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5, 0x8F03, 0xF859, 0x8009,
		0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0, 0xC382, 0xB029, 0x775A, 0x111E,
		0xCB7B, 0xFCA8, 0xD66D, 0x3A2C}};

/* TKIP (RC4 + key mixing) decryption routine */

#define ROTR1(x) ((((x) >> 1) & 0x7FFF) ^ (((x) &1) << 15))
#define LO8(x) ((x) &0x00FF)
#define LO16(x) ((x) &0xFFFF)
#define HI8(x) (((x) >> 8) & 0x00FF)
#define HI16(x) (((x) >> 16) & 0xFFFF)
#define MK16(hi, lo) ((lo) ^ (LO8(hi) << 8))
#define TK16(N) MK16(TK1[2 * (N) + 1], TK1[2 * (N)])
#define _S_(x) (TkipSbox[0][LO8(x)] ^ TkipSbox[1][HI8(x)])

int calc_tkip_ppk(unsigned char * h80211,
				  int caplen,
				  unsigned char TK1[static 16],
				  unsigned char key[static 16])
{
	UNUSED_PARAM(caplen);
	REQUIRE(h80211 != NULL);

	int i, z;
	uint32_t IV32;
	uint16_t IV16;
	uint16_t PPK[6];

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
	{
		z += 2;
	}
	IV16 = (uint16_t) MK16(h80211[z], h80211[z + 2]);

	IV32 = (h80211[z + 4]) | (h80211[z + 5] << 8) | (h80211[z + 6] << 16)
		   | (h80211[z + 7] << 24);

	PPK[0] = (uint16_t) LO16(IV32);
	PPK[1] = (uint16_t) HI16(IV32);
	PPK[2] = (uint16_t) MK16(h80211[11], h80211[10]);
	PPK[3] = (uint16_t) MK16(h80211[13], h80211[12]);
	PPK[4] = (uint16_t) MK16(h80211[15], h80211[14]);

	for (i = 0; i < 8; i++)
	{
		PPK[0] += _S_(PPK[4] ^ TK16((i & 1) + 0));
		PPK[1] += _S_(PPK[0] ^ TK16((i & 1) + 2));
		PPK[2] += _S_(PPK[1] ^ TK16((i & 1) + 4));
		PPK[3] += _S_(PPK[2] ^ TK16((i & 1) + 6));
		PPK[4] += _S_(PPK[3] ^ TK16((i & 1) + 0)) + i;
	}

	PPK[5] = PPK[4] + IV16;

	PPK[0] += _S_(PPK[5] ^ TK16(0));
	PPK[1] += _S_(PPK[0] ^ TK16(1));
	PPK[2] += _S_(PPK[1] ^ TK16(2));
	PPK[3] += _S_(PPK[2] ^ TK16(3));
	PPK[4] += _S_(PPK[3] ^ TK16(4));
	PPK[5] += _S_(PPK[4] ^ TK16(5));

	PPK[0] += ROTR1(PPK[5] ^ TK16(6));
	PPK[1] += ROTR1(PPK[0] ^ TK16(7));
	PPK[2] += ROTR1(PPK[1]);
	PPK[3] += ROTR1(PPK[2]);
	PPK[4] += ROTR1(PPK[3]);
	PPK[5] += ROTR1(PPK[4]);

	key[0] = (uint8_t) HI8(IV16);
	key[1] = (uint8_t)((HI8(IV16) | 0x20) & 0x7F);
	key[2] = (uint8_t) LO8(IV16);
	key[3] = (uint8_t) LO8((PPK[5] ^ TK16(0)) >> 1);

	for (i = 0; i < 6; i++)
	{
		key[4 + (2 * i)] = (uint8_t) LO8(PPK[i]);
		key[5 + (2 * i)] = (uint8_t) HI8(PPK[i]);
	}

	return (0);
}

static int calc_tkip_mic_skip_eiv(unsigned char * packet,
								  int length,
								  unsigned char ptk[static 80],
								  unsigned char value[static 8])
{
	REQUIRE(packet != NULL);

	int z, koffset = 0, is_qos = 0;
	unsigned char smac[6], dmac[6], bssid[6];
	unsigned char prio[4] = {0};
	struct Michael mic;

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length < z) return (0);

	/* Check if 802.11e (QoS) */
	if ((packet[0] & 0x80) == 0x80)
	{
		z += 2;
		is_qos = 1;
	}

	switch (packet[1] & 3)
	{
		case 0:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 1:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			koffset = 48 + 8;
			break;
		case 2:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 16, 6);
			koffset = 48;
			break;
		default:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 24, 6);
			break;
	}

	if (koffset != 48 && koffset != 48 + 8) return (1);

	init_michael(&mic, ptk + koffset);

	michael_append(&mic, dmac, 6);
	michael_append(&mic, smac, 6);

	// memset(prio, 0, 4);
	if (is_qos)
	{
		prio[0] = (uint8_t)(packet[z - 2] & 0x0f);
	}
	michael_append(&mic, prio, 4);

	michael_append(&mic, packet + z + 8, length - z - 8);

	michael_finalize(&mic);

	memcpy(value, mic.mic, 8);

	return (0);
}

void encrypt_tkip(unsigned char * h80211,
				  int caplen,
				  unsigned char ptk[static 80])
{
	REQUIRE(h80211 != NULL);

	unsigned char * TK1 = ptk + 32;
	unsigned char K[16];
	int z;

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
	{
		z += 2;
	}
	// Update the MIC in the frame...
	// Had to mod calc_tkip_mic to skip extended IV to avoid memmoves
	unsigned char micval[8] = {0};
	calc_tkip_mic_skip_eiv(h80211, caplen - 12, ptk, micval);
	unsigned char * mic_in_packet = h80211 + caplen - 12;
	memcpy(mic_in_packet, micval, 8);

	// Update the CRC in the frame before encrypting
	uint32_t crc = (uint32_t) calc_crc(h80211 + z + 8, caplen - z - 8 - 4);

	unsigned char * buf = h80211 + z + 8;
	buf += caplen - z - 8 - 4;
	buf[0] = (uint8_t)((crc) &0xFF);
	buf[2] = (uint8_t)((crc >> 16) & 0xFF);
	buf[1] = (uint8_t)((crc >> 8) & 0xFF);
	buf[3] = (uint8_t)((crc >> 24) & 0xFF);

	calc_tkip_ppk(h80211, caplen, TK1, K);

	decrypt_wep(h80211 + z + 8, caplen - z - 8, K, 16);
}

int decrypt_tkip(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16])
{
	REQUIRE(h80211 != NULL);

	unsigned char K[16];
	int z;

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
	{
		z += 2;
	}

	calc_tkip_ppk(h80211, caplen, TK1, K);

	return (decrypt_wep(h80211 + z + 8, caplen - z - 8, K, 16));
}

/* CCMP (AES-CTR-MAC) decryption routine */

static inline void XOR(unsigned char * dst, unsigned char * src, int len)
{
	REQUIRE(dst != NULL);
	REQUIRE(src != NULL);

	for (int i = 0; i < len; i++) dst[i] ^= src[i];
}

// Important documents for the implementation of encrypt_ccmp() and
// decrypt_ccmp():
//
//  * RFC 3610 Counter with CBC-MAC (CCM)
//    https://www.ietf.org/rfc/rfc3610.txt
//
//  * IEEE 802.11(TM)-2012
//    http://standards.ieee.org/about/get/802/802.11.html
//
// Note: RFC uses the abbreviation MAC (Message Authentication Code, or
//       value U in the RFC). It is the same as IEEE's MIC (Message
//       Integrity Code)

// encrypt_ccmp() takes an h80211 frame and encrypts it in-place using CCMP.
// This results in a frame that is 16 bytes longer than the original, take this
// into account when allocating h80211! encrypt() returns the new length (and
// thus the offset where the caller needs to write the FCS).
// caplen is the combined length of the 802.11 header and data, not the FCS!
int encrypt_ccmp(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16],
				 unsigned char PN[static 6])
{
	REQUIRE(h80211 != NULL);

	int is_a4, i, z, blocks, is_qos;
	int data_len, last, offset;
	unsigned char B0[16], B[16], MIC[16];
	unsigned char AAD[32];
	Cipher_AES_CTX * aes_ctx;

	is_a4 = (h80211[1] & 3) == 3;
	is_qos = (h80211[0] & 0x8C) == 0x88;
	z = 24 + 6 * is_a4;
	z += 2 * is_qos;

	// Insert CCMP header
	memmove(h80211 + z + 8, h80211 + z, (size_t) caplen - z);
	h80211[z + 0] = PN[5];
	h80211[z + 1] = PN[4];
	h80211[z + 2] = 0x00; // Reserved -> 0
	h80211[z + 3] = 0x20; // ExtIV=1, KeyID=0
	h80211[z + 4] = PN[3];
	h80211[z + 5] = PN[2];
	h80211[z + 6] = PN[1];
	h80211[z + 7] = PN[0];

	data_len = caplen - z;

	// B_0 := B0
	B0[0] = 0x59; // Flags
	B0[1] = 0; // Nonce := CCM Nonce: - Nonce flags
	memcpy(B0 + 2, h80211 + 10, 6); //                     - A2
	memcpy(B0 + 8, PN, 6); //                     - PN
	B0[14] = (uint8_t)((data_len >> 8) & 0xFF); // l(m)
	B0[15] = (uint8_t)(data_len & 0xFF); // l(m)

	// B_1 := AAD[ 0..15]
	// B_2 := AAD[16..31]
	//        AAD[ 0.. 1] = l(a)
	//        AAD[ 2..31] = a
	memset(AAD, 0, sizeof(AAD));
	AAD[2] = (uint8_t)(h80211[0] & 0x8F); // AAD[2..3]  = FC
	AAD[3] = (uint8_t)(h80211[1] & 0xC7); //
	memcpy(AAD + 4, h80211 + 4, 3 * 6); // AAD[4..21] = [A1,A2,A3]
	AAD[22] = (uint8_t)(h80211[22] & 0x0F); // AAD[22]    = SC

	if (is_a4)
	{
		memcpy(AAD + 24, h80211 + 24, 6); // AAD[24..29] = A4

		if (is_qos)
		{
			AAD[30] = (uint8_t)(h80211[z - 2] & 0x0F); // AAD[30..31] = QC
			AAD[31] = 0; //
			B0[1] = AAD[30]; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 2 + 6; // AAD[ 0.. 1] = l(a)
		}
		else
		{
			memset(&AAD[30], 0, 2); // AAD[30..31] = QC
			B0[1] = 0; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 6; // AAD[ 0.. 1] = l(a)
		}
	}
	else
	{
		if (is_qos)
		{
			AAD[24] = (uint8_t)(h80211[z - 2] & 0x0F); // AAD[24..25] = QC
			AAD[25] = 0; //
			B0[1] = AAD[24]; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 2; // AAD[ 0.. 1] = l(a)
		}
		else
		{
			memset(&AAD[24], 0, 2); // AAD[24..25] = QC
			B0[1] = 0; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22; // AAD[ 0.. 1] = l(a)
		}
	}

	aes_ctx = Cipher_AES_Encrypt_Init(16, TK1);
	REQUIRE(aes_ctx != NULL);
	Cipher_AES_Encrypt(aes_ctx, B0, MIC); // X_1 := E( K, B_0 )
	XOR(MIC, AAD, 16); // X_2 := E( K, X_1 XOR B_1 )
	Cipher_AES_Encrypt(aes_ctx, MIC, MIC);
	XOR(MIC, AAD + 16, 16); // X_3 := E( K, X_2 XOR B_2 )
	Cipher_AES_Encrypt(aes_ctx, MIC, MIC);

	// A_i := B0
	//        B0[     0] = Flags
	//        B0[ 1..13] = Nonce := CCM Nonce
	//        B0[14..15] = i
	B0[0] &= 0x07;
	B0[14] = B0[15] = 0;
	Cipher_AES_Encrypt(aes_ctx, B0, B); // S_0 := E( K, A_i )
	memcpy(h80211 + z + 8 + data_len, B, 8); //-V512
	//      ^^^^^^^^^^^^^^^^^^^  ^
	//      S_0[0..7]/future U   S_0

	blocks = (data_len + 16 - 1) / 16;
	last = data_len % 16;
	offset = z + 8;

	for (i = 1; i <= blocks; i++)
	{
		int n = (last > 0 && i == blocks) ? last : 16;

		XOR(MIC, h80211 + offset, n); // X_i+3 := E( K, X_i+2 XOR B_i+2 )
		Cipher_AES_Encrypt(aes_ctx, MIC, MIC);
		//    (X_i+2 ^^^)(^^^ X_i+3)

		// The message is encrypted by XORing the octets of message m with the
		// first l(m) octets of the concatenation of S_1, S_2, S_3, ... .
		B0[14] = (uint8_t)((i >> 8) & 0xFF); // A_i[14..15] = i
		B0[15] = (uint8_t)(i & 0xFF); //
		Cipher_AES_Encrypt(aes_ctx, B0, B); // S_i := E( K, A_i )
		XOR(h80211 + offset, B, n);
		// [B_3, ..., B_n] := m

		offset += n;
	}

	Cipher_AES_Encrypt_Deinit(aes_ctx);
	aes_ctx = NULL;

	// T :=     X_i+3[ 0.. 7]
	// U := T XOR S_0[ 0.. 7]
	XOR(h80211 + offset, MIC, 8);

	return (z + 8 + data_len + 8);
}

int decrypt_ccmp(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16])
{
	REQUIRE(h80211 != NULL);

	int is_a4, i, z, blocks, is_qos;
	int data_len, last, offset;
	unsigned char B0[16], B[16], MIC[16];
	unsigned char PN[6], AAD[32];
	Cipher_AES_CTX * aes_ctx;

	is_a4 = (h80211[1] & 3) == 3;
	is_qos = (h80211[0] & 0x8C) == 0x88;
	z = 24 + 6 * is_a4;
	z += 2 * is_qos;

	PN[0] = h80211[z + 7];
	PN[1] = h80211[z + 6];
	PN[2] = h80211[z + 5];
	PN[3] = h80211[z + 4];
	PN[4] = h80211[z + 1];
	PN[5] = h80211[z + 0];

	data_len = caplen - z - 8 - 8;

	// B_0 := B0
	B0[0] = 0x59; // Flags
	B0[1] = 0; // Nonce := CCM Nonce: - Nonce flags
	memcpy(B0 + 2, h80211 + 10, 6); //                     - A2
	memcpy(B0 + 8, PN, 6); //                     - PN
	B0[14] = (uint8_t)((data_len >> 8) & 0xFF); // l(m)
	B0[15] = (uint8_t)(data_len & 0xFF); // l(m)

	// B_1 := AAD[ 0..15]
	// B_2 := AAD[16..31]
	//        AAD[ 0.. 1] = l(a)
	//        AAD[ 2..31] = a
	memset(AAD, 0, sizeof(AAD));
	AAD[2] = (uint8_t)(h80211[0] & 0x8F); // AAD[2..3]  = FC
	AAD[3] = (uint8_t)(h80211[1] & 0xC7); //
	memcpy(AAD + 4, h80211 + 4, 3 * 6); // AAD[4..21] = [A1,A2,A3]
	AAD[22] = (uint8_t)(h80211[22] & 0x0F); // AAD[22]    = SC

	if (is_a4)
	{
		memcpy(AAD + 24, h80211 + 24, 6); // AAD[24..29] = A4

		if (is_qos)
		{
			AAD[30] = (uint8_t)(h80211[z - 2] & 0x0F); // AAD[30..31] = QC
			AAD[31] = 0; //
			B0[1] = AAD[30]; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 2 + 6; // AAD[ 0.. 1] = l(a)
		}
		else
		{
			memset(&AAD[30], 0, 2); // AAD[30..31] = QC
			B0[1] = 0; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 6; // AAD[ 0.. 1] = l(a)
		}
	}
	else
	{
		if (is_qos)
		{
			AAD[24] = (uint8_t)(h80211[z - 2] & 0x0F); // AAD[24..25] = QC
			AAD[25] = 0; //
			B0[1] = AAD[24]; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22 + 2; // AAD[ 0.. 1] = l(a)
		}
		else
		{
			memset(&AAD[24], 0, 2); // AAD[24..25] = QC
			B0[1] = 0; //  B0[     1] = CCM Nonce flags
			AAD[1] = 22; // AAD[ 0.. 1] = l(a)
		}
	}

	aes_ctx = Cipher_AES_Encrypt_Init(16, TK1);
	REQUIRE(aes_ctx != NULL);
	Cipher_AES_Encrypt(aes_ctx, B0, MIC); // X_1 := E( K, B_0 )
	XOR(MIC, AAD, 16); // X_2 := E( K, X_1 XOR B_1 )
	Cipher_AES_Encrypt(aes_ctx, MIC, MIC);
	XOR(MIC, AAD + 16, 16); // X_3 := E( K, X_2 XOR B_2 )
	Cipher_AES_Encrypt(aes_ctx, MIC, MIC);

	// A_i := B0
	//        B0[     0] = Flags
	//        B0[ 1..13] = Nonce := CCM Nonce
	//        B0[14..15] = i
	B0[0] &= 0x07;
	B0[14] = B0[15] = 0;
	Cipher_AES_Encrypt(aes_ctx, B0, B); // S_0 := E( K, A_i )
	XOR(h80211 + caplen - 8, B, 8); // T   := U XOR S_0[0..7]
	//   ^^^^^^^^^^^^^^^      ^
	//     U:=MIC -> T       S_0

	blocks = (data_len + 16 - 1) / 16;
	last = data_len % 16;
	offset = z + 8;

	for (i = 1; i <= blocks; i++)
	{
		int n = (last > 0 && i == blocks) ? last : 16;

		B0[14] = (uint8_t)((i >> 8) & 0xFF); // A_i[14..15] = i
		B0[15] = (uint8_t)(i & 0xFF); //

		Cipher_AES_Encrypt(aes_ctx, B0, B); // S_i := E( K, A_i )
		// The message is encrypted by XORing the octets of message m with the
		// first l(m) octets of the concatenation of S_1, S_2, S_3, ... .
		XOR(h80211 + offset, B, n);
		// [B_3, ..., B_n] := m
		XOR(MIC, h80211 + offset, n); // X_i+3 := E( K, X_i+2 XOR B_i+2 )
		Cipher_AES_Encrypt(aes_ctx, MIC, MIC);
		//    (X_i+2 ^^^)(^^^ X_i+3)

		offset += n;
	}

	Cipher_AES_Encrypt_Deinit(aes_ctx);
	aes_ctx = NULL;

	// T := X_n[ 0.. 7]
	// Note: Decryption is successful if calculated T is the same as the one
	//       that was sent with the message.
	return (memcmp(h80211 + offset, MIC, 8) == 0); //-V512
}
