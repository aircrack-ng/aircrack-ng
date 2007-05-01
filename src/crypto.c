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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>
#include <arpa/inet.h>

#include "crypto.h"

#define GET_UINT32_LE(n,b,i)                    \
{                                               \
    (n) = ( (uint32) (b)[(i)    ]       )       \
        | ( (uint32) (b)[(i) + 1] <<  8 )       \
        | ( (uint32) (b)[(i) + 2] << 16 )       \
        | ( (uint32) (b)[(i) + 3] << 24 );      \
}

#define PUT_UINT32_LE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8) ( (n)       );       \
    (b)[(i) + 1] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uint8) ( (n) >> 24 );       \
}

#define GET_UINT32_BE(n,b,i)                    \
{                                               \
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \
        | ( (uint32) (b)[(i) + 1] << 16 )       \
        | ( (uint32) (b)[(i) + 2] <<  8 )       \
        | ( (uint32) (b)[(i) + 3]       );      \
}

#define PUT_UINT32_BE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8) ( (n)       );       \
}

/* RFC 1321 compliant MD5 implementation */

void md5_starts( md5_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}

void md5_process( md5_context *ctx, uint8 data[64] )
{
    uint32 X[16], A, B, C, D;

    GET_UINT32_LE( X[0],  data,  0 );
    GET_UINT32_LE( X[1],  data,  4 );
    GET_UINT32_LE( X[2],  data,  8 );
    GET_UINT32_LE( X[3],  data, 12 );
    GET_UINT32_LE( X[4],  data, 16 );
    GET_UINT32_LE( X[5],  data, 20 );
    GET_UINT32_LE( X[6],  data, 24 );
    GET_UINT32_LE( X[7],  data, 28 );
    GET_UINT32_LE( X[8],  data, 32 );
    GET_UINT32_LE( X[9],  data, 36 );
    GET_UINT32_LE( X[10], data, 40 );
    GET_UINT32_LE( X[11], data, 44 );
    GET_UINT32_LE( X[12], data, 48 );
    GET_UINT32_LE( X[13], data, 52 );
    GET_UINT32_LE( X[14], data, 56 );
    GET_UINT32_LE( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
{                                                       \
    a += F(b,c,d) + X[k] + t; a = S(a,s) + b;           \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

    P( A, B, C, D,  0,  7, 0xD76AA478 );
    P( D, A, B, C,  1, 12, 0xE8C7B756 );
    P( C, D, A, B,  2, 17, 0x242070DB );
    P( B, C, D, A,  3, 22, 0xC1BDCEEE );
    P( A, B, C, D,  4,  7, 0xF57C0FAF );
    P( D, A, B, C,  5, 12, 0x4787C62A );
    P( C, D, A, B,  6, 17, 0xA8304613 );
    P( B, C, D, A,  7, 22, 0xFD469501 );
    P( A, B, C, D,  8,  7, 0x698098D8 );
    P( D, A, B, C,  9, 12, 0x8B44F7AF );
    P( C, D, A, B, 10, 17, 0xFFFF5BB1 );
    P( B, C, D, A, 11, 22, 0x895CD7BE );
    P( A, B, C, D, 12,  7, 0x6B901122 );
    P( D, A, B, C, 13, 12, 0xFD987193 );
    P( C, D, A, B, 14, 17, 0xA679438E );
    P( B, C, D, A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    P( A, B, C, D,  1,  5, 0xF61E2562 );
    P( D, A, B, C,  6,  9, 0xC040B340 );
    P( C, D, A, B, 11, 14, 0x265E5A51 );
    P( B, C, D, A,  0, 20, 0xE9B6C7AA );
    P( A, B, C, D,  5,  5, 0xD62F105D );
    P( D, A, B, C, 10,  9, 0x02441453 );
    P( C, D, A, B, 15, 14, 0xD8A1E681 );
    P( B, C, D, A,  4, 20, 0xE7D3FBC8 );
    P( A, B, C, D,  9,  5, 0x21E1CDE6 );
    P( D, A, B, C, 14,  9, 0xC33707D6 );
    P( C, D, A, B,  3, 14, 0xF4D50D87 );
    P( B, C, D, A,  8, 20, 0x455A14ED );
    P( A, B, C, D, 13,  5, 0xA9E3E905 );
    P( D, A, B, C,  2,  9, 0xFCEFA3F8 );
    P( C, D, A, B,  7, 14, 0x676F02D9 );
    P( B, C, D, A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) (x ^ y ^ z)

    P( A, B, C, D,  5,  4, 0xFFFA3942 );
    P( D, A, B, C,  8, 11, 0x8771F681 );
    P( C, D, A, B, 11, 16, 0x6D9D6122 );
    P( B, C, D, A, 14, 23, 0xFDE5380C );
    P( A, B, C, D,  1,  4, 0xA4BEEA44 );
    P( D, A, B, C,  4, 11, 0x4BDECFA9 );
    P( C, D, A, B,  7, 16, 0xF6BB4B60 );
    P( B, C, D, A, 10, 23, 0xBEBFBC70 );
    P( A, B, C, D, 13,  4, 0x289B7EC6 );
    P( D, A, B, C,  0, 11, 0xEAA127FA );
    P( C, D, A, B,  3, 16, 0xD4EF3085 );
    P( B, C, D, A,  6, 23, 0x04881D05 );
    P( A, B, C, D,  9,  4, 0xD9D4D039 );
    P( D, A, B, C, 12, 11, 0xE6DB99E5 );
    P( C, D, A, B, 15, 16, 0x1FA27CF8 );
    P( B, C, D, A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    P( A, B, C, D,  0,  6, 0xF4292244 );
    P( D, A, B, C,  7, 10, 0x432AFF97 );
    P( C, D, A, B, 14, 15, 0xAB9423A7 );
    P( B, C, D, A,  5, 21, 0xFC93A039 );
    P( A, B, C, D, 12,  6, 0x655B59C3 );
    P( D, A, B, C,  3, 10, 0x8F0CCC92 );
    P( C, D, A, B, 10, 15, 0xFFEFF47D );
    P( B, C, D, A,  1, 21, 0x85845DD1 );
    P( A, B, C, D,  8,  6, 0x6FA87E4F );
    P( D, A, B, C, 15, 10, 0xFE2CE6E0 );
    P( C, D, A, B,  6, 15, 0xA3014314 );
    P( B, C, D, A, 13, 21, 0x4E0811A1 );
    P( A, B, C, D,  4,  6, 0xF7537E82 );
    P( D, A, B, C, 11, 10, 0xBD3AF235 );
    P( C, D, A, B,  2, 15, 0x2AD7D2BB );
    P( B, C, D, A,  9, 21, 0xEB86D391 );

#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

#undef P
#undef S

void md5_update( md5_context *ctx, uint8 *input, uint32 length )
{
    uint32 left, fill;

    if( ! length ) return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        md5_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 )
    {
        md5_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, length );
    }
}

static uint8 md5_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5_finish( md5_context *ctx, uint8 digest[16] )
{
    uint32 last, padn;
    uint32 high, low;
    uint8 msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  msglen, 0 );
    PUT_UINT32_LE( high, msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    md5_update( ctx, md5_padding, padn );
    md5_update( ctx, msglen, 8 );

    PUT_UINT32_LE( ctx->state[0], digest,  0 );
    PUT_UINT32_LE( ctx->state[1], digest,  4 );
    PUT_UINT32_LE( ctx->state[2], digest,  8 );
    PUT_UINT32_LE( ctx->state[3], digest, 12 );
}

void hmac_md5( uint8 *key, int keylen, uint8 *buffer, int length,
               uint8 digest[16] )
{
    int i;
    md5_context ctx;
    uint8 k_ipad[64];
    uint8 k_opad[64];
    uint8 tmpbuf[16];

    memset( k_ipad, 0, sizeof( k_ipad ) );
    memset( k_opad, 0, sizeof( k_opad ) );

    memcpy( k_ipad, key, keylen );
    memcpy( k_opad, key, keylen );

    for( i = 0; i < 64; i++ )
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    md5_starts( &ctx );
    md5_update( &ctx, k_ipad, 64 );
    md5_update( &ctx, buffer, length );
    md5_finish( &ctx, tmpbuf );

    md5_starts( &ctx );
    md5_update( &ctx, k_opad, 64 );
    md5_update( &ctx, tmpbuf, 16 );
    md5_finish( &ctx, digest );
}

/* FIPS-180-1 compliant SHA-1 implementation */

void sha1_starts( sha1_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void sha1_process( sha1_context *ctx, uint8 data[64] )
{
    uint32 temp, W[16], A, B, C, D, E;

    GET_UINT32_BE( W[0],  data,  0 );
    GET_UINT32_BE( W[1],  data,  4 );
    GET_UINT32_BE( W[2],  data,  8 );
    GET_UINT32_BE( W[3],  data, 12 );
    GET_UINT32_BE( W[4],  data, 16 );
    GET_UINT32_BE( W[5],  data, 20 );
    GET_UINT32_BE( W[6],  data, 24 );
    GET_UINT32_BE( W[7],  data, 28 );
    GET_UINT32_BE( W[8],  data, 32 );
    GET_UINT32_BE( W[9],  data, 36 );
    GET_UINT32_BE( W[10], data, 40 );
    GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 );
    GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 );
    GET_UINT32_BE( W[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

#undef P
#undef R
#undef S

void sha1_update( sha1_context *ctx, uint8 *input, uint32 length )
{
    uint32 left, fill;

    if( ! length ) return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sha1_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 )
    {
        sha1_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, length );
    }
}

static uint8 sha1_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha1_finish( sha1_context *ctx, uint8 digest[20] )
{
    uint32 last, padn;
    uint32 high, low;
    uint8 msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( high, msglen, 0 );
    PUT_UINT32_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha1_update( ctx, sha1_padding, padn );
    sha1_update( ctx, msglen, 8 );

    PUT_UINT32_BE( ctx->state[0], digest,  0 );
    PUT_UINT32_BE( ctx->state[1], digest,  4 );
    PUT_UINT32_BE( ctx->state[2], digest,  8 );
    PUT_UINT32_BE( ctx->state[3], digest, 12 );
    PUT_UINT32_BE( ctx->state[4], digest, 16 );
}

void hmac_sha1( uint8 *key, int keylen, uint8 *buffer, int length,
                uint8 digest[20] )
{
    int i;
    sha1_context ctx;
    uint8 k_ipad[64];
    uint8 k_opad[64];
    uint8 tmpbuf[20];

    memset( k_ipad, 0, sizeof( k_ipad ) );
    memset( k_opad, 0, sizeof( k_opad ) );

    memcpy( k_ipad, key, keylen );
    memcpy( k_opad, key, keylen );

    for( i = 0; i < 64; i++ )
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    sha1_starts( &ctx );
    sha1_update( &ctx, k_ipad, 64 );
    sha1_update( &ctx, buffer, length );
    sha1_finish( &ctx, tmpbuf );

    sha1_starts( &ctx );
    sha1_update( &ctx, k_opad, 64 );
    sha1_update( &ctx, tmpbuf, 20 );
    sha1_finish( &ctx, digest );
}

/* An implementation of the ARC4 algorithm */

void rc4_setup( struct rc4_state *s, unsigned char *key,  int length )
{
    int i, j, k, *m, a;

    s->x = 0;
    s->y = 0;
	m = s->m;

    for( i = 0; i < 256; i++ )
    {
        m[i] = i;
    }

    j = k = 0;

    for(i=0 ; i < 256; i++ )
    {
        a = m[i];
        j = (unsigned char) ( j + a + key[k] );
        m[i] = m[j]; m[j] = a;
        if( ++k >= length ) k = 0;
    }
}

void rc4_crypt( struct rc4_state *s, unsigned char *data, int length )
{
    int i, x, y, *m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for( i = 0; i < length; i++ )
    {
        x = (unsigned char) ( x + 1 ); a = m[x];
        y = (unsigned char) ( y + a );
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char) ( a + b )];
    }

    s->x = x;
    s->y = y;
}

/* FIPS-197 compliant AES implementation */

/* forward S-box & tables */

uint32 FSb[256];
uint32 FT0[256];
uint32 FT1[256];
uint32 FT2[256];
uint32 FT3[256];

/* reverse S-box & tables */

uint32 RSb[256];
uint32 RT0[256];
uint32 RT1[256];
uint32 RT2[256];
uint32 RT3[256];

/* round constants */

uint32 RCON[10];

/* tables generation flag */

int do_init = 1;

/* tables generation routine */

#define ROTR8(x) ( ( ( x << 24 ) & 0xFFFFFFFF ) | \
                   ( ( x & 0xFFFFFFFF ) >>  8 ) )

#define XTIME(x) ( ( x <<  1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x &&  y ) ? pow[(log[x] + log[y]) % 255] : 0 )

void aes_gen_tables( void )
{
    int i;
    uint8 x, y;
    uint8 pow[256];
    uint8 log[256];

    /* compute pow and log tables over GF(2^8) */

    for( i = 0, x = 1; i < 256; i++, x ^= XTIME( x ) )
    {
        pow[i] = x;
        log[x] = i;
    }

    /* calculate the round constants */

    for( i = 0, x = 1; i < 10; i++, x = XTIME( x ) )
    {
        RCON[i] = (uint32) x << 24;
    }

    /* generate the forward and reverse S-boxes */

    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y = x;  y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y; y = ( y << 1 ) | ( y >> 7 );
        x ^= y ^ 0x63;

        FSb[i] = x;
        RSb[x] = i;
    }

    /* generate the forward and reverse tables */

    for( i = 0; i < 256; i++ )
    {
        x = (unsigned char) FSb[i]; y = XTIME( x );

        FT0[i] =   (uint32) ( x ^ y ) ^
                 ( (uint32) x <<  8 ) ^
                 ( (uint32) x << 16 ) ^
                 ( (uint32) y << 24 );

        FT0[i] &= 0xFFFFFFFF;

        FT1[i] = ROTR8( FT0[i] );
        FT2[i] = ROTR8( FT1[i] );
        FT3[i] = ROTR8( FT2[i] );

        y = (unsigned char) RSb[i];

        RT0[i] = ( (uint32) MUL( 0x0B, y )       ) ^
                 ( (uint32) MUL( 0x0D, y ) <<  8 ) ^
                 ( (uint32) MUL( 0x09, y ) << 16 ) ^
                 ( (uint32) MUL( 0x0E, y ) << 24 );

        RT0[i] &= 0xFFFFFFFF;

        RT1[i] = ROTR8( RT0[i] );
        RT2[i] = ROTR8( RT1[i] );
        RT3[i] = ROTR8( RT2[i] );
    }
}

/* decryption key schedule tables */

int KT_init = 1;

uint32 KT0[256];
uint32 KT1[256];
uint32 KT2[256];
uint32 KT3[256];

/* AES key scheduling routine */

int aes_set_key( aes_context *ctx, uint8 *key, int nbits )
{
    int i;
    uint32 *RK, *SK;

    if( do_init )
    {
        aes_gen_tables();

        do_init = 0;
    }

    switch( nbits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( 1 );
    }

    RK = ctx->erk;

    for( i = 0; i < (nbits >> 5); i++ )
    {
        GET_UINT32_BE( RK[i], key, i * 4 );
    }

    /* setup encryption round keys */

    switch( nbits )
    {
    case 128:

        for( i = 0; i < 10; i++, RK += 4 )
        {
            RK[4]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (uint8) ( RK[3] >> 16 ) ] << 24 ) ^
                        ( FSb[ (uint8) ( RK[3] >>  8 ) ] << 16 ) ^
                        ( FSb[ (uint8) ( RK[3]       ) ] <<  8 ) ^
                        ( FSb[ (uint8) ( RK[3] >> 24 ) ]       );

            RK[5]  = RK[1] ^ RK[4];
            RK[6]  = RK[2] ^ RK[5];
            RK[7]  = RK[3] ^ RK[6];
        }
        break;

    case 192:

        for( i = 0; i < 8; i++, RK += 6 )
        {
            RK[6]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (uint8) ( RK[5] >> 16 ) ] << 24 ) ^
                        ( FSb[ (uint8) ( RK[5] >>  8 ) ] << 16 ) ^
                        ( FSb[ (uint8) ( RK[5]       ) ] <<  8 ) ^
                        ( FSb[ (uint8) ( RK[5] >> 24 ) ]       );

            RK[7]  = RK[1] ^ RK[6];
            RK[8]  = RK[2] ^ RK[7];
            RK[9]  = RK[3] ^ RK[8];
            RK[10] = RK[4] ^ RK[9];
            RK[11] = RK[5] ^ RK[10];
        }
        break;

    case 256:

        for( i = 0; i < 7; i++, RK += 8 )
        {
            RK[8]  = RK[0] ^ RCON[i] ^
                        ( FSb[ (uint8) ( RK[7] >> 16 ) ] << 24 ) ^
                        ( FSb[ (uint8) ( RK[7] >>  8 ) ] << 16 ) ^
                        ( FSb[ (uint8) ( RK[7]       ) ] <<  8 ) ^
                        ( FSb[ (uint8) ( RK[7] >> 24 ) ]       );

            RK[9]  = RK[1] ^ RK[8];
            RK[10] = RK[2] ^ RK[9];
            RK[11] = RK[3] ^ RK[10];

            RK[12] = RK[4] ^
                        ( FSb[ (uint8) ( RK[11] >> 24 ) ] << 24 ) ^
                        ( FSb[ (uint8) ( RK[11] >> 16 ) ] << 16 ) ^
                        ( FSb[ (uint8) ( RK[11] >>  8 ) ] <<  8 ) ^
                        ( FSb[ (uint8) ( RK[11]       ) ]       );

            RK[13] = RK[5] ^ RK[12];
            RK[14] = RK[6] ^ RK[13];
            RK[15] = RK[7] ^ RK[14];
        }
        break;
    }

    /* setup decryption round keys */

    if( KT_init )
    {
        for( i = 0; i < 256; i++ )
        {
            KT0[i] = RT0[ FSb[i] ];
            KT1[i] = RT1[ FSb[i] ];
            KT2[i] = RT2[ FSb[i] ];
            KT3[i] = RT3[ FSb[i] ];
        }

        KT_init = 0;
    }

    SK = ctx->drk;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    for( i = 1; i < ctx->nr; i++ )
    {
        RK -= 8;

        *SK++ = KT0[ (uint8) ( *RK >> 24 ) ] ^
                KT1[ (uint8) ( *RK >> 16 ) ] ^
                KT2[ (uint8) ( *RK >>  8 ) ] ^
                KT3[ (uint8) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (uint8) ( *RK >> 24 ) ] ^
                KT1[ (uint8) ( *RK >> 16 ) ] ^
                KT2[ (uint8) ( *RK >>  8 ) ] ^
                KT3[ (uint8) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (uint8) ( *RK >> 24 ) ] ^
                KT1[ (uint8) ( *RK >> 16 ) ] ^
                KT2[ (uint8) ( *RK >>  8 ) ] ^
                KT3[ (uint8) ( *RK       ) ]; RK++;

        *SK++ = KT0[ (uint8) ( *RK >> 24 ) ] ^
                KT1[ (uint8) ( *RK >> 16 ) ] ^
                KT2[ (uint8) ( *RK >>  8 ) ] ^
                KT3[ (uint8) ( *RK       ) ]; RK++;
    }

    RK -= 8;

    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;
    *SK++ = *RK++;

    return( 0 );
}

/* AES 128-bit block encryption routine */

void aes_encrypt( aes_context *ctx, uint8 input[16], uint8 output[16] )
{
    uint32 *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->erk;

    GET_UINT32_BE( X0, input,  0 ); X0 ^= RK[0];
    GET_UINT32_BE( X1, input,  4 ); X1 ^= RK[1];
    GET_UINT32_BE( X2, input,  8 ); X2 ^= RK[2];
    GET_UINT32_BE( X3, input, 12 ); X3 ^= RK[3];

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ FT0[ (uint8) ( Y0 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y1 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y2 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y3       ) ];   \
                                                \
    X1 = RK[1] ^ FT0[ (uint8) ( Y1 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y2 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y3 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y0       ) ];   \
                                                \
    X2 = RK[2] ^ FT0[ (uint8) ( Y2 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y3 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y0 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y1       ) ];   \
                                                \
    X3 = RK[3] ^ FT0[ (uint8) ( Y3 >> 24 ) ] ^  \
                 FT1[ (uint8) ( Y0 >> 16 ) ] ^  \
                 FT2[ (uint8) ( Y1 >>  8 ) ] ^  \
                 FT3[ (uint8) ( Y2       ) ];   \
}

    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 1 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 2 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 3 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 4 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 5 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 6 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 7 */
    AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 8 */
    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 9 */

    if( ctx->nr > 10 )
    {
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 10 */
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 11 */
    }

    if( ctx->nr > 12 )
    {
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 12 */
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 13 */
    }

    /* last round */

    RK += 4;

    X0 = RK[0] ^ ( FSb[ (uint8) ( Y0 >> 24 ) ] << 24 ) ^
                 ( FSb[ (uint8) ( Y1 >> 16 ) ] << 16 ) ^
                 ( FSb[ (uint8) ( Y2 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (uint8) ( Y3       ) ]       );

    X1 = RK[1] ^ ( FSb[ (uint8) ( Y1 >> 24 ) ] << 24 ) ^
                 ( FSb[ (uint8) ( Y2 >> 16 ) ] << 16 ) ^
                 ( FSb[ (uint8) ( Y3 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (uint8) ( Y0       ) ]       );

    X2 = RK[2] ^ ( FSb[ (uint8) ( Y2 >> 24 ) ] << 24 ) ^
                 ( FSb[ (uint8) ( Y3 >> 16 ) ] << 16 ) ^
                 ( FSb[ (uint8) ( Y0 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (uint8) ( Y1       ) ]       );

    X3 = RK[3] ^ ( FSb[ (uint8) ( Y3 >> 24 ) ] << 24 ) ^
                 ( FSb[ (uint8) ( Y0 >> 16 ) ] << 16 ) ^
                 ( FSb[ (uint8) ( Y1 >>  8 ) ] <<  8 ) ^
                 ( FSb[ (uint8) ( Y2       ) ]       );

    PUT_UINT32_BE( X0, output,  0 );
    PUT_UINT32_BE( X1, output,  4 );
    PUT_UINT32_BE( X2, output,  8 );
    PUT_UINT32_BE( X3, output, 12 );
}

/* AES 128-bit block decryption routine */

void aes_decrypt( aes_context *ctx, uint8 input[16], uint8 output[16] )
{
    uint32 *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->drk;

    GET_UINT32_BE( X0, input,  0 ); X0 ^= RK[0];
    GET_UINT32_BE( X1, input,  4 ); X1 ^= RK[1];
    GET_UINT32_BE( X2, input,  8 ); X2 ^= RK[2];
    GET_UINT32_BE( X3, input, 12 ); X3 ^= RK[3];

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    RK += 4;                                    \
                                                \
    X0 = RK[0] ^ RT0[ (uint8) ( Y0 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y3 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y2 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y1       ) ];   \
                                                \
    X1 = RK[1] ^ RT0[ (uint8) ( Y1 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y0 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y3 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y2       ) ];   \
                                                \
    X2 = RK[2] ^ RT0[ (uint8) ( Y2 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y1 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y0 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y3       ) ];   \
                                                \
    X3 = RK[3] ^ RT0[ (uint8) ( Y3 >> 24 ) ] ^  \
                 RT1[ (uint8) ( Y2 >> 16 ) ] ^  \
                 RT2[ (uint8) ( Y1 >>  8 ) ] ^  \
                 RT3[ (uint8) ( Y0       ) ];   \
}

    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 1 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 2 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 3 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 4 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 5 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 6 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 7 */
    AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );       /* round 8 */
    AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );       /* round 9 */

    if( ctx->nr > 10 )
    {
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 10 */
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 11 */
    }

    if( ctx->nr > 12 )
    {
        AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );   /* round 12 */
        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );   /* round 13 */
    }

    /* last round */

    RK += 4;

    X0 = RK[0] ^ ( RSb[ (uint8) ( Y0 >> 24 ) ] << 24 ) ^
                 ( RSb[ (uint8) ( Y3 >> 16 ) ] << 16 ) ^
                 ( RSb[ (uint8) ( Y2 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (uint8) ( Y1       ) ]       );

    X1 = RK[1] ^ ( RSb[ (uint8) ( Y1 >> 24 ) ] << 24 ) ^
                 ( RSb[ (uint8) ( Y0 >> 16 ) ] << 16 ) ^
                 ( RSb[ (uint8) ( Y3 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (uint8) ( Y2       ) ]       );

    X2 = RK[2] ^ ( RSb[ (uint8) ( Y2 >> 24 ) ] << 24 ) ^
                 ( RSb[ (uint8) ( Y1 >> 16 ) ] << 16 ) ^
                 ( RSb[ (uint8) ( Y0 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (uint8) ( Y3       ) ]       );

    X3 = RK[3] ^ ( RSb[ (uint8) ( Y3 >> 24 ) ] << 24 ) ^
                 ( RSb[ (uint8) ( Y2 >> 16 ) ] << 16 ) ^
                 ( RSb[ (uint8) ( Y1 >>  8 ) ] <<  8 ) ^
                 ( RSb[ (uint8) ( Y0       ) ]       );

    PUT_UINT32_BE( X0, output,  0 );
    PUT_UINT32_BE( X1, output,  4 );
    PUT_UINT32_BE( X2, output,  8 );
    PUT_UINT32_BE( X3, output, 12 );
}

void *get_da(unsigned char *wh)
{
        if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh + 4;
        else
                return wh + 4 + 6*2;
}

void *get_sa(unsigned char *wh)
{
        if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh + 4 + 6*2;
        else
                return wh + 4 + 6;
}

int is_arp(void *wh, int len)
{
        int arpsize = 8 + 8 + 10*2;

	/* XXX check if broadcast to increase probability of correctness in some
	 * cases?
	 */
	if (wh) {}

        if (len == arpsize || len == 54)
                return 1;

        return 0;
}

int known_clear(void *clear, unsigned char *wh, int len)
{
        unsigned char *ptr = clear;

        /* IP */
        if (!is_arp(wh, len)) {
                unsigned short iplen = htons(len - 8);

//                printf("Assuming IP %d\n", len);

                len = sizeof(S_LLC_SNAP_IP) - 1;
                memcpy(ptr, S_LLC_SNAP_IP, len);
                ptr += len;
#if 1
                //version=4; header_length=20; services=0
                len = 2;
                memcpy(ptr, "\x45\x00", len);
                ptr += len;

                //ip total length
                memcpy(ptr, &iplen, len);
                ptr += len;

#if 0
		/* XXX IP ID is not always 0.  Can't use IP packets for PTW,
		 * unless they are our own.  Can we use them for 40-bit keys
		 * though [only 3+5 bytes of keystream needed]?  Or for
		 * calculating only the first 9 bytes of the key?  -sorbo.
		 */
                //ID=0
                len=2;
                memcpy(ptr, "\x00\x00", len);
                ptr += len;

                //ip flags=don't fragment
                len=2;
                memcpy(ptr, "\x40\x00", len);
                ptr += len;
#endif
#endif
                len = ptr - ((unsigned char*)clear);
                return len;
        }
//        printf("Assuming ARP %d\n", len);

        /* arp */
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

        len = ptr - ((unsigned char*)clear);
        return len;
}
