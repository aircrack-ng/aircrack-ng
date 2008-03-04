#ifndef _CRYPTO_H
#define _CRYPTO_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

#include <openssl/hmac.h>
#include <openssl/sha.h>
// We don't use EVP. Bite me
#include <openssl/rc4.h>
#include <openssl/aes.h>

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define S_LLC_SNAP_SPANTREE   "\x42\x42\x03\x00\x00\x00\x00\x00"
#define S_LLC_SNAP_CDP  "\xAA\xAA\x03\x00\x00\x0C\x20"
#define IEEE80211_FC1_DIR_FROMDS                0x02    /* AP ->STA */

#define TYPE_ARP    0
#define TYPE_IP     1

#define NULL_MAC  (uchar*)"\x00\x00\x00\x00\x00\x00"
#define BROADCAST (uchar*)"\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE  (uchar*)"\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP   (uchar*)"\x01\x00\x0C\xCC\xCC\xCC"

/* Used for own RC4 implementation */
struct rc4_state
{
    int x, y, m[256];
};

struct AP_info;

void calc_pmk( char *key, char *essid, unsigned char pmk[40] );
int decrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen );
int encrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen );
int check_crc_buf( unsigned char *buf, int len );
int calc_crc_buf( unsigned char *buf, int len );
void calc_mic(struct AP_info *ap, unsigned char *pmk, unsigned char *ptk,
	      unsigned char *mic);
int known_clear(void *clear, int *clen, int *weight, unsigned char *wh, int len);
int add_crc32(unsigned char* data, int length);
int add_crc32_plain(unsigned char* data, int length);

#endif /* crypto.h */
