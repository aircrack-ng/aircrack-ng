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

/* Used for own RC4 implementation */
struct rc4_state
{
    int x, y, m[256];
};

void calc_pmk( char *key, char *essid, unsigned char pmk[40] );
int decrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen );
int encrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen );
int check_crc_buf( unsigned char *buf, int len );
int calc_crc_buf( unsigned char *buf, int len );

#endif /* crypto.h */
