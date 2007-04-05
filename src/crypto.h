#ifndef _CRYPTO_H
#define _CRYPTO_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
    uint32 total[2];
    uint32 state[4];
    uint8 buffer[64];
}
md5_context;

void md5_starts( md5_context *ctx );
void md5_update( md5_context *ctx, uint8 *input, uint32 length );
void md5_finish( md5_context *ctx, uint8 digest[16] );
void hmac_md5( uint8 *key, int keylen, uint8 *buffer, int length,
               uint8 digest[16] );

typedef struct
{
    uint32 total[2];
    uint32 state[5];
    uint8 buffer[64];
}
sha1_context;

void sha1_starts( sha1_context *ctx );
void sha1_update( sha1_context *ctx, uint8 *input, uint32 length );
void sha1_finish( sha1_context *ctx, uint8 digest[20] );
void hmac_sha1( uint8 *key, int keylen, uint8 *buffer, int length,
                uint8 digest[20] );

struct rc4_state
{
    int x, y, m[256];
};

void rc4_setup( struct rc4_state *s, unsigned char *key,  int length );
void rc4_crypt( struct rc4_state *s, unsigned char *data, int length );

typedef struct
{
    uint32 erk[64];     /* encryption round keys */
    uint32 drk[64];     /* decryption round keys */
    int nr;             /* number of rounds */
}
aes_context;

int  aes_set_key( aes_context *ctx, uint8 *key, int nbits );
void aes_encrypt( aes_context *ctx, uint8 input[16], uint8 output[16] );
void aes_decrypt( aes_context *ctx, uint8 input[16], uint8 output[16] );

#endif /* crypto.h */
