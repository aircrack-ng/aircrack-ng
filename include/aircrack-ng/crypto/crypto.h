/*
 *  MD5, SHA-1, RC4 and AES implementations
 *
 *  Copyright (C) 2001-2004  Christophe Devine
 *  Copyright (C) 2017-2022  Joseph Benden <joe@benden.us>
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <limits.h>
#include <errno.h>

#ifdef USE_GCRYPT
#include <gcrypt.h>
#endif

#ifndef USE_GCRYPT
#include <openssl/hmac.h>
#if defined(OPENSSL_WITH_SHA1) || defined(OPENSSL_WITH_SHA256)
#include <openssl/sha.h>
#endif
#ifdef OPENSSL_WITH_ARCFOUR
#include <openssl/rc4.h>
#endif
#ifdef OPENSSL_WITH_MD5
#include <openssl/md5.h>
#endif
#include <openssl/aes.h>
#if HAVE_OPENSSL_CMAC_H
#include <openssl/cmac.h>
#endif
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include <aircrack-ng/defs.h>
#include <aircrack-ng/crypto/aes.h>
#include <aircrack-ng/crypto/arcfour.h>
#include <aircrack-ng/crypto/mac.h>
#include <aircrack-ng/crypto/md5.h>
#include <aircrack-ng/crypto/sha1.h>
#include <aircrack-ng/crypto/sha256.h>

#define PMK_LEN 32
#define PMK_LEN_MAX 64

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define CRYPT_NONE 0
#define CRYPT_WEP 1
#define CRYPT_WPA 2

#define S_LLC_SNAP "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_WLCCP "\xAA\xAA\x03\x00\x40\x96\x00\x00"
#define S_LLC_SNAP_IP (S_LLC_SNAP "\x08\x00")
#define S_LLC_SNAP_SPANTREE "\x42\x42\x03\x00\x00\x00\x00\x00"
#define S_LLC_SNAP_CDP "\xAA\xAA\x03\x00\x00\x0C\x20"
#define IEEE80211_FC1_DIR_FROMDS 0x02 /* AP ->STA */

#define TYPE_ARP 0
#define TYPE_IP 1

#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE (unsigned char *) "\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP (unsigned char *) "\x01\x00\x0C\xCC\xCC\xCC"

#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT 4

/* for TYPE_DATA (bit combination) */
#define IEEE80211_FC0_SUBTYPE_QOS 0x80
#define IEEE80211_FC0_SUBTYPE_QOS_NULL 0xc0

#define GET_SUBTYPE(fc)                                                        \
	(((fc) &IEEE80211_FC0_SUBTYPE_MASK) >> IEEE80211_FC0_SUBTYPE_SHIFT)        \
		<< IEEE80211_FC0_SUBTYPE_SHIFT

#define ROL32(A, n) (((A) << (n)) | (((A) >> (32 - (n))) & ((1UL << (n)) - 1)))
#define ROR32(A, n) ROL32((A), 32 - (n))

struct WPA_ST_info
{
	struct WPA_ST_info * next; /* next supplicant              */
	unsigned char stmac[6]; /* supplicant MAC               */
	unsigned char bssid[6]; /* authenticator MAC            */
	unsigned char snonce[32]; /* supplicant nonce             */
	unsigned char anonce[32]; /* authenticator nonce          */
	unsigned char keymic[20]; /* eapol frame MIC              */
	unsigned char eapol[256]; /* eapol frame contents         */
	unsigned char ptk[80]; /* pairwise transcient key      */
	unsigned eapol_size; /* eapol frame size             */
	unsigned long t_crc; /* last ToDS   frame CRC        */
	unsigned long f_crc; /* last FromDS frame CRC        */
	int keyver, valid_ptk;
	unsigned char pn[6]; /* Packet Number (WPA-CCMP) */
};

struct Michael
{
	unsigned long key0;
	unsigned long key1;
	unsigned long left;
	unsigned long right;
	unsigned long nBytesInM;
	unsigned long message;
	unsigned char mic[8];
};

/* Used for own RC4 implementation */
struct rc4_state
{
	int x, y, m[256];
};

struct AP_info;

void calc_pmk(const uint8_t * key,
			  const uint8_t * essid,
			  uint8_t pmk[static PMK_LEN]);
int decrypt_wep(unsigned char * data, int len, unsigned char * key, int keylen);
int encrypt_wep(unsigned char * data, int len, unsigned char * key, int keylen);
int check_crc_buf(const unsigned char * buf, int len);
int calc_crc_buf(const unsigned char * buf, int len);
void calc_mic(struct AP_info * ap,
			  unsigned char pmk[static 32],
			  unsigned char ptk[static 80],
			  unsigned char mic[static 20]);
int known_clear(
	void * clear, int * clen, int * weight, unsigned char * wh, size_t len);
int add_crc32(unsigned char * data, int length);
int add_crc32_plain(unsigned char * data, int length);
int is_ipv6(void * wh);
int is_dhcp_discover(void * wh, size_t len);
int is_qos_arp_tkip(void * wh, int len);
int calc_tkip_ppk(unsigned char * h80211,
				  int caplen,
				  unsigned char TK1[static 16],
				  unsigned char key[static 16]);
void encrypt_tkip(unsigned char * h80211,
				  int caplen,
				  unsigned char PTK[static 80]);
int decrypt_tkip(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16]);
int encrypt_ccmp(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16],
				 unsigned char PN[static 6]);
int decrypt_ccmp(unsigned char * h80211,
				 int caplen,
				 unsigned char TK1[static 16]);
int calc_ptk(struct WPA_ST_info * wpa, unsigned char pmk[static 32]);
int calc_tkip_mic(unsigned char * packet,
				  int length,
				  unsigned char ptk[static 80],
				  unsigned char value[static 8]);
int michael_test(unsigned char key[static 8],
				 unsigned char * message,
				 int length,
				 unsigned char out[static 8]);
int calc_tkip_mic_key(unsigned char * packet,
					  int length,
					  unsigned char key[static 8]);

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

static inline void add_icv(unsigned char * input, int len, int offset)
{
	REQUIRE(input != NULL);
	REQUIRE(len > 0 && len < (INT_MAX - 4));
	REQUIRE(offset >= 0 && offset <= len);

	unsigned long crc = 0xFFFFFFFF;

	for (int n = offset; n < len; n++)
		crc = crc_tbl[(crc ^ input[n]) & 0xFF] ^ (crc >> 8);

	crc = ~crc;

	input[len] = (uint8_t)((crc) &0xFF);
	input[len + 1] = (uint8_t)((crc >> 8) & 0xFF);
	input[len + 2] = (uint8_t)((crc >> 16) & 0xFF);
	input[len + 3] = (uint8_t)((crc >> 24) & 0xFF);
}

static inline int eapol_handshake_step(const unsigned char * eapol,
									   const int len)
{
	REQUIRE(eapol != NULL);

	const int eapol_size = 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2;

	if (len < eapol_size) return (0);

	/* not pairwise */
	if ((eapol[6] & 0x08) == 0) return (0);

	/* 1: has no mic */
	if ((eapol[5] & 1) == 0) return (1);

	/* 3: has ack */
	if ((eapol[6] & 0x80) != 0) return (3);

	if (*((uint16_t *) &eapol[eapol_size - 2]) == 0) return (4);

	return (2);
}

/// Initialize the system cryptography librar(ies).
API_IMPORT
void ac_crypto_init(void);

#endif /* crypto.h */
