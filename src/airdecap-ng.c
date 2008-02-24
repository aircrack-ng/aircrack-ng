/*
 *  802.11 to Ethernet pcap translator
 *
 *  Copyright (C) 2006,2007,2008 Thomas d'Otreppe
 *  Copyright (C) 2004,2005  Christophe Devine
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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>

#include "version.h"
#include "crypto.h"
#ifdef WIN32
#include <Windows.h>
#include <airpcap.h>
#endif
#include "pcap.h"

#define CRYPT_NONE 0
#define CRYPT_WEP  1
#define CRYPT_WPA  2


#define	IEEE80211_FC0_SUBTYPE_MASK              0xf0
#define	IEEE80211_FC0_SUBTYPE_SHIFT             4

/* for TYPE_DATA (bit combination) */
#define	IEEE80211_FC0_SUBTYPE_QOS               0x80
#define	IEEE80211_FC0_SUBTYPE_QOS_NULL          0xc0

#define GET_SUBTYPE(fc) \
    ( ( (fc) & IEEE80211_FC0_SUBTYPE_MASK ) >> IEEE80211_FC0_SUBTYPE_SHIFT ) \
        << IEEE80211_FC0_SUBTYPE_SHIFT

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);
extern int check_crc_buf( unsigned char *buf, int len );
extern int calc_crc_buf( unsigned char *buf, int len );

const short Sbox[2][256]=
{
    {
        0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
        0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
        0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
        0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
        0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
        0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
        0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
        0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
        0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
        0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
        0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
        0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
        0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
        0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
        0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
        0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
        0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
        0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
        0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
        0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
        0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
        0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
        0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
        0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
        0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
        0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
        0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
        0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
        0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
        0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
        0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
        0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A
    },
    {
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C
    }
};

char usage[] =

"\n"
"  %s - (C) 2006,2007,2008 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: airdecap-ng [options] <pcap file>\n"
"\n"
"  Common options:\n"
"      -l         : don't remove the 802.11 header\n"
"      -b <bssid> : access point MAC address filter\n"
"      -e <essid> : target network SSID\n"
"\n"
"  WEP specific option:\n"
"      -w <key>   : target network WEP key in hex\n"
"\n"
"  WPA specific options:\n"
"      -p <pass>  : target network WPA passphrase\n"
"      -k <pmk>   : WPA Pairwise Master Key in hex\n"
"\n"
"      --help     : Displays this usage screen\n"
"\n";


/* derive the PMK from the passphrase and the essid */

void calc_pmk( char *key, char *essid_pre, uchar pmk[40] )
{
    int i, j, slen;
    uchar buffer[65];
    uchar essid[33+4];
    sha1_context ctx_ipad;
    sha1_context ctx_opad;
    sha1_context sha1_ctx;

    memset(essid,0,sizeof(essid));
    memcpy(essid,essid_pre,strlen(essid_pre));
    slen = (int)strlen((char*)essid)+4;

    /* setup the inner and outer contexts */

    memset( buffer, 0, sizeof( buffer ) );
    strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

    for( i = 0; i < 64; i++ )
        buffer[i] ^= 0x36;

    sha1_starts( &ctx_ipad );
    sha1_update( &ctx_ipad, buffer, 64 );

    for( i = 0; i < 64; i++ )
        buffer[i] ^= 0x6A;

    sha1_starts( &ctx_opad );
    sha1_update( &ctx_opad, buffer, 64 );

    /* iterate HMAC-SHA1 over itself 8192 times */

    essid[slen - 1] = '\1';
    hmac_sha1( (uchar *) key, strlen( key ),
               (uchar *) essid, slen, pmk );
    memcpy( buffer, pmk, 20 );

    for( i = 1; i < 4096; i++ )
    {
        memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
        sha1_update( &sha1_ctx, buffer, 20 );
        sha1_finish( &sha1_ctx, buffer );

        memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
        sha1_update( &sha1_ctx, buffer, 20 );
        sha1_finish( &sha1_ctx, buffer );

        for( j = 0; j < 20; j++ )
            pmk[j] ^= buffer[j];
    }

    essid[slen - 1] = '\2';
    hmac_sha1( (uchar *) key, strlen( key ),
               (uchar *) essid, slen, pmk + 20 );
    memcpy( buffer, pmk + 20, 20 );

    for( i = 1; i < 4096; i++ )
    {
        memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
        sha1_update( &sha1_ctx, buffer, 20 );
        sha1_finish( &sha1_ctx, buffer );

        memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
        sha1_update( &sha1_ctx, buffer, 20 );
        sha1_finish( &sha1_ctx, buffer );

        for( j = 0; j < 20; j++ )
            pmk[j + 20] ^= buffer[j];
    }
}

struct ST_info
{
    struct ST_info *next;       /* next supplicant              */
    uchar stmac[6];             /* supplicant MAC               */
    uchar bssid[6];             /* authenticator MAC            */
    uchar snonce[32];           /* supplicant nonce             */
    uchar anonce[32];           /* authenticator nonce          */
    uchar keymic[20];           /* eapol frame MIC              */
    uchar eapol[256];           /* eapol frame contents         */
    uchar ptk[80];              /* pairwise transcient key      */
    int eapol_size;             /* eapol frame size             */
    unsigned long t_crc;        /* last ToDS   frame CRC        */
    unsigned long f_crc;        /* last FromDS frame CRC        */
    int keyver, valid_ptk;
};

/* derive the pairwise transcient keys from a bunch of stuff */

int calc_ptk( struct ST_info *wpa, uchar pmk[32] )
{
    int i;
    uchar pke[100];
    uchar mic[20];

    memcpy( pke, "Pairwise key expansion", 23 );

    if( memcmp( wpa->stmac, wpa->bssid, 6 ) < 0 )
    {
        memcpy( pke + 23, wpa->stmac, 6 );
        memcpy( pke + 29, wpa->bssid, 6 );
    }
    else
    {
        memcpy( pke + 23, wpa->bssid, 6 );
        memcpy( pke + 29, wpa->stmac, 6 );
    }

    if( memcmp( wpa->snonce, wpa->anonce, 32 ) < 0 )
    {
        memcpy( pke + 35, wpa->snonce, 32 );
        memcpy( pke + 67, wpa->anonce, 32 );
    }
    else
    {
        memcpy( pke + 35, wpa->anonce, 32 );
        memcpy( pke + 67, wpa->snonce, 32 );
    }

    for( i = 0; i < 4; i++ )
    {
        pke[99] = i;
        hmac_sha1( pmk, 32, pke, 100, wpa->ptk + i * 20 );
    }

    /* check the EAPOL frame MIC */

    if( ( wpa->keyver & 0x07 ) == 1 )
        hmac_md5(  wpa->ptk, 16, wpa->eapol, wpa->eapol_size, mic );
    else
        hmac_sha1( wpa->ptk, 16, wpa->eapol, wpa->eapol_size, mic );

    return( memcmp( mic, wpa->keymic, 16 ) == 0 );
}


/* WEP (barebone RC4) decryption routine */

int decrypt_wep( uchar *data, int len, uchar *key, int keylen )
{
    struct rc4_state S;

    rc4_setup( &S, key, keylen );
    rc4_crypt( &S, data, len );

    return( check_crc_buf( data, len - 4 ) );
}

/* TKIP (RC4 + key mixing) decryption routine */

#define ROTR1(x)      ((((x) >> 1) & 0x7FFF) ^ (((x) & 1) << 15))
#define LO8(x)        ( (x) & 0x00FF )
#define LO16(x)       ( (x) & 0xFFFF )
#define HI8(x)        ( ((x) >>  8) & 0x00FF )
#define HI16(x)       ( ((x) >> 16) & 0xFFFF )
#define MK16(hi,lo)   ( (lo) ^ ( LO8(hi) << 8 ) )
#define TK16(N)       MK16(TK1[2*(N)+1],TK1[2*(N)])
#define _S_(x)        (Sbox[0][LO8(x)] ^ Sbox[1][HI8(x)])

int decrypt_tkip( uchar *h80211, int caplen, uchar TK1[16] )
{
    int i, z;
    uint IV32;
    ushort IV16;
    ushort PPK[6];
    uchar K[16];

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS ) {
        z += 2;
    }

    IV16 = MK16( h80211[z], h80211[z + 2] );

    IV32 = ( h80211[z + 4]       ) | ( h80211[z + 5] <<  8 ) |
           ( h80211[z + 6] << 16 ) | ( h80211[z + 7] << 24 );

    PPK[0] = LO16( IV32 );
    PPK[1] = HI16( IV32 );
    PPK[2] = MK16( h80211[11], h80211[10] );
    PPK[3] = MK16( h80211[13], h80211[12] );
    PPK[4] = MK16( h80211[15], h80211[14] );

    for( i = 0; i < 8; i++ )
    {
        PPK[0] += _S_( PPK[4] ^ TK16( (i & 1) + 0 ) );
        PPK[1] += _S_( PPK[0] ^ TK16( (i & 1) + 2 ) );
        PPK[2] += _S_( PPK[1] ^ TK16( (i & 1) + 4 ) );
        PPK[3] += _S_( PPK[2] ^ TK16( (i & 1) + 6 ) );
        PPK[4] += _S_( PPK[3] ^ TK16( (i & 1) + 0 ) ) + i;
    }

    PPK[5] = PPK[4] + IV16;

    PPK[0] += _S_( PPK[5] ^ TK16(0) );
    PPK[1] += _S_( PPK[0] ^ TK16(1) );
    PPK[2] += _S_( PPK[1] ^ TK16(2) );
    PPK[3] += _S_( PPK[2] ^ TK16(3) );
    PPK[4] += _S_( PPK[3] ^ TK16(4) );
    PPK[5] += _S_( PPK[4] ^ TK16(5) );

    PPK[0] += ROTR1( PPK[5] ^ TK16(6) );
    PPK[1] += ROTR1( PPK[0] ^ TK16(7) );
    PPK[2] += ROTR1( PPK[1] );
    PPK[3] += ROTR1( PPK[2] );
    PPK[4] += ROTR1( PPK[3] );
    PPK[5] += ROTR1( PPK[4] );

    K[0] =   HI8( IV16 );
    K[1] = ( HI8( IV16 ) | 0x20 ) & 0x7F;
    K[2] =   LO8( IV16 );
    K[3] =   LO8( (PPK[5] ^ TK16(0) ) >> 1);

    for( i = 0; i < 6; i++ )
    {
        K[4 + ( 2 * i)] = LO8( PPK[i] );
        K[5 + ( 2 * i)] = HI8( PPK[i] );
    }

    return( decrypt_wep( h80211 + z + 8, caplen - z - 8, K, 16 ) );
}

/* CCMP (AES-CTR-MAC) decryption routine */

static inline void XOR( uchar *dst, uchar *src, int len )
{
    int i;
    for( i = 0; i < len; i++ )
        dst[i] ^= src[i];
}

int decrypt_ccmp( uchar *h80211, int caplen, uchar TK1[16] )
{
    int is_a4, i, n, z, blocks;
    int data_len, last, offset;
    uchar B0[16], B[16], MIC[16];
    uchar PN[6], AAD[32];
    aes_context aes_ctx;

    is_a4 = ( h80211[1] & 3 ) == 3;

    z = 24 + 6 * is_a4;

    PN[0] = h80211[z + 7];
    PN[1] = h80211[z + 6];
    PN[2] = h80211[z + 5];
    PN[3] = h80211[z + 4];
    PN[4] = h80211[z + 1];
    PN[5] = h80211[z + 0];

    data_len = caplen - z - 8 - 8;

    B0[0] = 0x59;
    B0[1] = 0;
    memcpy( B0 + 2, h80211 + 10, 6 );
    memcpy( B0 + 8, PN, 6 );
    B0[14] = ( data_len >> 8 ) & 0xFF;
    B0[15] = ( data_len & 0xFF );

    memset( AAD, 0, sizeof( AAD ) );

    AAD[1] = 22 + 6 * is_a4;
    AAD[2] = h80211[0] & 0x8F;
    AAD[3] = h80211[1] & 0xC7;
    memcpy( AAD + 4, h80211 + 4, 3 * 6 );
    AAD[22] = h80211[22] & 0x0F;
    if( is_a4 )
        memcpy( AAD + 24, h80211 + 24, 6 );

    aes_set_key( &aes_ctx, TK1, 128 );
    aes_encrypt( &aes_ctx, B0, MIC );
    XOR( MIC, AAD, 16 );
    aes_encrypt( &aes_ctx, MIC, MIC );
    XOR( MIC, AAD + 16, 16 );
    aes_encrypt( &aes_ctx, MIC, MIC );

    B0[0] &= 0x07;
    B0[14] = B0[15] = 0;
    aes_encrypt( &aes_ctx, B0, B );
    XOR( h80211 + caplen - 8, B, 8 );

    blocks = ( data_len + 16 - 1 ) / 16;
    last = data_len % 16;
    offset = z + 8;

    for( i = 1; i <= blocks; i++ )
    {
        n = ( last > 0 && i == blocks ) ? last : 16;

        B0[14] = ( i >> 8 ) & 0xFF;
        B0[15] =   i & 0xFF;

        aes_encrypt( &aes_ctx, B0, B );
        XOR( h80211 + offset, B, n );
        XOR( MIC, h80211 + offset, n );
        aes_encrypt( &aes_ctx, MIC, MIC );

        offset += n;
    }

    return( memcmp( h80211 + offset, MIC, 8 ) == 0 );
}

struct decap_stats
{
    unsigned long nb_read;      /* # of packets read       */
    unsigned long nb_wep;       /* # of WEP data packets   */
    unsigned long nb_wpa;       /* # of WPA data packets   */
    unsigned long nb_plain;     /* # of plaintext packets  */
    unsigned long nb_unwep;     /* # of decrypted WEP pkt  */
    unsigned long nb_unwpa;     /* # of decrypted WPA pkt  */
}
stats;

struct options
{
    int no_convert;
    char essid[36];
    char passphrase[65];
    uchar bssid[6];
    uchar pmk[40];
    uchar wepkey[64];
    int weplen, crypt;
}
opt;

uchar buffer[65536];

/* this routine handles to 802.11 to Ethernet translation */

int write_packet( FILE *f_out, struct pcap_pkthdr *pkh, uchar *h80211 )
{
    int n;
    uchar arphdr[12];
    int qosh_offset = 0;

    if( opt.no_convert )
    {
        if( buffer != h80211 )
            memcpy( buffer, h80211, pkh->caplen );
    }
    else
    {
        /* create the Ethernet link layer (MAC dst+src) */

        switch( h80211[1] & 3 )
        {
            case  0:    /* To DS = 0, From DS = 0: DA, SA, BSSID */

                memcpy( arphdr + 0, h80211 +  4, 6 );
                memcpy( arphdr + 6, h80211 + 10, 6 );
                break;

            case  1:    /* To DS = 1, From DS = 0: BSSID, SA, DA */

                memcpy( arphdr + 0, h80211 + 16, 6 );
                memcpy( arphdr + 6, h80211 + 10, 6 );
                break;

            case  2:    /* To DS = 0, From DS = 1: DA, BSSID, SA */

                memcpy( arphdr + 0, h80211 +  4, 6 );
                memcpy( arphdr + 6, h80211 + 16, 6 );
                break;

            default:    /* To DS = 1, From DS = 1: RA, TA, DA, SA */

                memcpy( arphdr + 0, h80211 + 16, 6 );
                memcpy( arphdr + 6, h80211 + 24, 6 );
                break;
        }

        /* check QoS header */
        if ( GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS ) {
            qosh_offset += 2;
        }

        /* remove the 802.11 + LLC header */

        if( ( h80211[1] & 3 ) != 3 )
        {
            pkh->len    -= 24 + qosh_offset + 6;
            pkh->caplen -= 24 + qosh_offset + 6;

            memcpy( buffer + 12, h80211 + 30 + qosh_offset, pkh->caplen );
        }
        else
        {
            pkh->len    -= 30 + qosh_offset + 6;
            pkh->caplen -= 30 + qosh_offset + 6;

            memcpy( buffer + 12, h80211 + 36 + qosh_offset, pkh->caplen );
        }

        memcpy( buffer, arphdr, 12 );

        pkh->len    += 12;
        pkh->caplen += 12;
    }

    n = sizeof( struct pcap_pkthdr );

    if( fwrite( pkh, 1, n, f_out ) != (size_t) n )
    {
        perror( "fwrite(packet header) failed" );
        return( 1 );
    }

    n = pkh->caplen;

    if( fwrite( buffer, 1, n, f_out ) != (size_t) n )
    {
        perror( "fwrite(packet data) failed" );
        return( 1 );
    }

    return( 0 );
}

int main( int argc, char *argv[] )
{
    time_t tt;
    uint magic;
    char *s, buf[128];
    FILE *f_in, *f_out;
    unsigned long crc;
    int i = 0, n, z, linktype;
    uchar ZERO[32], *h80211;
    uchar bssid[6], stmac[6];

    struct ST_info *st_1st;
    struct ST_info *st_cur;
    struct ST_info *st_prv;
    struct pcap_file_header pfh;
    struct pcap_pkthdr pkh;

    /* parse the arguments */

    memset( ZERO, 0, sizeof( ZERO ) );
    memset( &opt, 0, sizeof( opt  ) );

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"bssid",   1, 0, 'b'},
            {"debug",   1, 0, 'd'},
            {"help",    0, 0, 'H'},
            {0,         0, 0,  0 }
        };

        int option = getopt_long( argc, argv, "lb:k:e:p:w:H",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
        	case ':' :

	    		printf("\"%s --help\" for help.\n", argv[0]);
        		return( 1 );

        	case '?' :

	    		printf("\"%s --help\" for help.\n", argv[0]);
        		return( 1 );

            case 'l' :

                opt.no_convert = 1;
                break;

            case 'b' :

                i = 0;
                s = optarg;

                while( sscanf( s, "%x", &n ) == 1 )
                {
                    if( n < 0 || n > 255 )
                    {
                        printf( "Invalid BSSID (not a MAC).\n" );
			    		printf("\"%s --help\" for help.\n", argv[0]);
                        return( 1 );
                    }

                    opt.bssid[i] = n;

                    if( ++i > 6 ) break;

                    if( ! ( s = strchr( s, ':' ) ) )
                        break;

                    s++;
                }

                if( i != 6 )
                {
                    printf( "Invalid BSSID (not a MAC).\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'k' :

                if( opt.crypt != CRYPT_NONE )
                {
                    printf( "Encryption key already specified.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.crypt = CRYPT_WPA;

                i = 0;
                s = optarg;

                buf[0] = s[0];
                buf[1] = s[1];
                buf[2] = '\0';

                while( sscanf( buf, "%x", &n ) == 1 )
                {
                    if( n < 0 || n > 255 )
                    {
                        printf( "Invalid WPA PMK.\n" );
			    		printf("\"%s --help\" for help.\n", argv[0]);
                        return( 1 );
                    }

                    opt.pmk[i++] = n;

                    if( i >= 32 ) break;

                    s += 2;

                    if( s[0] == ':' || s[0] == '-' )
                        s++;

                    if( s[0] == '\0' || s[1] == '\0' )
                        break;

                    buf[0] = s[0];
                    buf[1] = s[1];
                }

                if( i != 32 )
                {
                    printf( "Invalid WPA PMK.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'e' :

				if ( opt.essid[0])
				{
					printf( "ESSID already specified.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
				}

                memset(  opt.essid, 0, sizeof( opt.essid ) );
                strncpy( opt.essid, optarg, sizeof( opt.essid ) - 1 );
                break;

            case 'p' :

                if( opt.crypt != CRYPT_NONE )
                {
                    printf( "Encryption key already specified.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.crypt = CRYPT_WPA;

                memset(  opt.passphrase, 0, sizeof( opt.passphrase ) );
                strncpy( opt.passphrase, optarg, sizeof( opt.passphrase ) - 1 );
                break;

            case 'w' :

                if( opt.crypt != CRYPT_NONE )
                {
                    printf( "Encryption key already specified.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.crypt = CRYPT_WEP;

                i = 0;
                s = optarg;

                buf[0] = s[0];
                buf[1] = s[1];
                buf[2] = '\0';

                while( sscanf( buf, "%x", &n ) == 1 )
                {
                    if( n < 0 || n > 255 )
                    {
                        printf( "Invalid WEP key.\n" );
			    		printf("\"%s --help\" for help.\n", argv[0]);
                        return( 1 );
                    }

                    opt.wepkey[i++] = n;

                    if( i >= 64 ) break;

                    s += 2;

                    if( s[0] == ':' || s[0] == '-' )
                        s++;

                    if( s[0] == '\0' || s[1] == '\0' )
                        break;

                    buf[0] = s[0];
                    buf[1] = s[1];
                }

                if( i != 5 && i != 13 && i != 16 && i != 29 && i != 61 )
                {
                    printf( "Invalid WEP key length. [5,13,16,29,61]\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.weplen = i;

                break;

            case 'H' :

            	printf( usage, getVersion("Airdecap-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
            	return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
    	if(argc == 1)
    	{
usage:
	        printf( usage, getVersion("Airdecap-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
	    }
		if( argc - optind == 0)
	    {
	    	printf("No file to decrypt specified.\n");
	    }
	    if(argc > 1)
	    {
    		printf("\"%s --help\" for help.\n", argv[0]);
	    }
        return( 1 );
    }

    if( opt.crypt == CRYPT_WPA )
    {
        if( opt.passphrase[0] != '\0' )
        {
            /* compute the Pairwise Master Key */

            if( opt.essid[0] == '\0' )
            {
                printf( "You must also specify the ESSID (-e).\n" );
	    		printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );
            }

            calc_pmk( opt.passphrase, opt.essid, opt.pmk );
        }
    }

    /* open the input and output pcap files */

    if( ( f_in = fopen( argv[optind], "rb" ) ) == NULL )
    {
        perror( "fopen failed\n" );
        printf( "Could not open \"%s\".\n", argv[optind] );
        return( 1 );
    }

    n = sizeof( pfh );

    if( fread( &pfh, 1, n, f_in ) != (size_t) n )
    {
        perror( "fread(pcap file header) failed" );
        return( 1 );
    }

    if( pfh.magic != TCPDUMP_MAGIC &&
        pfh.magic != TCPDUMP_CIGAM )
    {
        printf( "\"%s\" isn't a pcap file (expected "
                "TCPDUMP_MAGIC).\n", argv[optind] );
        return( 1 );
    }

    if( ( magic = pfh.magic ) == TCPDUMP_CIGAM )
        SWAP32( pfh.linktype );

    if( pfh.linktype != LINKTYPE_IEEE802_11 &&
        pfh.linktype != LINKTYPE_PRISM_HEADER &&
        pfh.linktype != LINKTYPE_RADIOTAP_HDR )
    {
        printf( "\"%s\" isn't a regular 802.11 "
                "(wireless) capture.\n", argv[optind] );
        return( 1 );
    }

    linktype = pfh.linktype;

    n = strlen( argv[optind] );

    if( n > 4 && ( n + 5 < (int) sizeof( buffer ) ) &&
        argv[optind][n - 4] == '.' )
    {
        memcpy( buffer, argv[optind], n - 4 );
        memcpy( buffer + n - 4, "-dec", 4 );
        memcpy( buffer + n, argv[optind] + n - 4, 5 );
    }
    else
    {
        if( n > 5 && ( n + 6 < (int) sizeof( buffer ) ) &&
            argv[optind][n - 5] == '.' )
        {
            memcpy( buffer, argv[optind], n - 5 );
            memcpy( buffer + n - 5, "-dec", 4 );
            memcpy( buffer + n - 1, argv[optind] + n - 5, 6 );
        }
        else
        {
            memset( buffer, 0, sizeof( buffer ) );
            snprintf( (char *) buffer, sizeof( buffer ) - 1,
                      "%s-dec", argv[optind] );
        }
    }

    if( ( f_out = fopen( (char *) buffer, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        printf( "Could not create \"%s\".\n", buffer );
        return( 1 );
    }

    pfh.magic           = TCPDUMP_MAGIC;
    pfh.version_major   = PCAP_VERSION_MAJOR;
    pfh.version_minor   = PCAP_VERSION_MINOR;
    pfh.thiszone        = 0;
    pfh.sigfigs         = 0;
    pfh.snaplen         = 65535;
    pfh.linktype        = ( opt.no_convert ) ?
                            LINKTYPE_IEEE802_11 :
                            LINKTYPE_ETHERNET;

    n = sizeof( pfh );

    if( fwrite( &pfh, 1, n, f_out ) != (size_t) n )
    {
        perror( "fwrite(pcap file header) failed" );
        return( 1 );
    }

    /* loop reading and deciphering the packets */

    memset( &stats, 0, sizeof( stats ) );
    tt = time( NULL );
    st_1st = NULL;

    while( 1 )
    {
        if( time( NULL ) - tt > 0 )
        {
            /* update the status line every second */

            printf( "\33[KRead %ld packets...\r", stats.nb_read );
            fflush( stdout );
            tt = time( NULL );
        }

        /* read one packet */

        n = sizeof( pkh );

        if( fread( &pkh, 1, n, f_in ) != (size_t) n )
            break;

        if( magic == TCPDUMP_CIGAM )
            SWAP32( pkh.caplen );

        n = pkh.caplen;

        if( n <= 0 || n > 65535 )
        {
            printf( "Corrupted file? Invalid packet length %d.\n", n );
            break;
        }

        if( fread( buffer, 1, n, f_in ) != (size_t) n )
            break;

        stats.nb_read++;

        h80211 = buffer;

        if( linktype == LINKTYPE_PRISM_HEADER )
        {
            /* remove the prism header */

            if( h80211[7] == 0x40 )
                n = 64; /* prism54 */
            else
            {
                n = *(int *)( h80211 + 4 );

                if( magic == TCPDUMP_CIGAM )
                    SWAP32( n );
            }

            if( n < 8 || n >= (int) pkh.caplen )
                continue;

            h80211 += n; pkh.caplen -= n;
        }

        if( linktype == LINKTYPE_RADIOTAP_HDR )
        {
            /* remove the radiotap header */

            n = *(unsigned short *)( h80211 + 2 );

            if( n <= 0 || n >= (int) pkh.caplen )
                continue;

            h80211 += n; pkh.caplen -= n;
        }

        /* remove the FCS if present (madwifi) */

        if( check_crc_buf( h80211, pkh.caplen - 4 ) == 1 )
        {
            pkh.len    -= 4;
            pkh.caplen -= 4;
        }

        /* check if data */

        if( ( h80211[0] & 0x0C ) != 0x08 )
            continue;

        /* check minimum size */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        if( z + 16 > (int) pkh.caplen )
            continue;

        /* check QoS header */
        if ( GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS ) {
            z += 2;
        }
        /* check the BSSID */

        switch( h80211[1] & 3 )
        {
            case  0: memcpy( bssid, h80211 + 16, 6 ); break;
            case  1: memcpy( bssid, h80211 +  4, 6 ); break;
            case  2: memcpy( bssid, h80211 + 10, 6 ); break;
            default: memcpy( bssid, h80211 +  4, 6 ); break;
        }

        if( memcmp( opt.bssid, ZERO, 6 ) != 0 )
            if( memcmp( opt.bssid, bssid, 6 ) != 0 )
                continue;

        /* locate the station's MAC address */

        switch( h80211[1] & 3 )
        {
            case  1: memcpy( stmac, h80211 + 10, 6 ); break;
            case  2: memcpy( stmac, h80211 +  4, 6 ); break;
            case  3: memcpy( stmac, h80211 + 10, 6 ); break;
            default: continue;
        }

        st_prv = NULL;
        st_cur = st_1st;

        while( st_cur != NULL )
        {
            if( ! memcmp( st_cur->stmac, stmac, 6 ) )
                break;

            st_prv = st_cur;
            st_cur = st_cur->next;
        }

        /* if it's a new station, add it */

        if( st_cur == NULL )
        {
            if( ! ( st_cur = (struct ST_info *) malloc(
                             sizeof( struct ST_info ) ) ) )
            {
                perror( "malloc failed" );
                break;
            }

            memset( st_cur, 0, sizeof( struct ST_info ) );

            if( st_1st == NULL )
                st_1st = st_cur;
            else
                st_prv->next = st_cur;

            memcpy( st_cur->stmac, stmac, 6 );
            memcpy( st_cur->bssid, bssid, 6 );
        }

        /* check if we haven't already processed this packet */

        crc = calc_crc_buf( h80211 + z, pkh.caplen - z );

        if( ( h80211[1] & 3 ) == 2 )
        {
            if( st_cur->t_crc == crc )
                continue;

            st_cur->t_crc = crc;
        }
        else
        {
            if( st_cur->f_crc == crc )
                continue;

            st_cur->f_crc = crc;
        }

        /* check the SNAP header to see if data is encrypted *
         * as unencrypted data begins with AA AA 03 00 00 00 */

        if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 )
        {
            /* check the extended IV flag */

            if( ( h80211[z + 3] & 0x20 ) == 0 )
            {
                uchar K[64];

                stats.nb_wep++;

                if( opt.crypt != CRYPT_WEP )
                    continue;

                memcpy( K, h80211 + z, 3 );
                memcpy( K + 3, opt.wepkey, opt.weplen );

                if( decrypt_wep( h80211 + z + 4, pkh.caplen - z - 4,
                                 K, 3 + opt.weplen ) == 0 )
                    continue;

                /* WEP data packet was successfully decrypted, *
                 * remove the WEP IV & ICV and write the data  */

                pkh.len    -= 8;
                pkh.caplen -= 8;

                memcpy( h80211 + z, h80211 + z + 4, pkh.caplen - z );

                stats.nb_unwep++;

                h80211[1] &= 0xBF;

                if( write_packet( f_out, &pkh, h80211 ) != 0 )
                    break;
            }
            else
            {
                stats.nb_wpa++;

                if( opt.crypt != CRYPT_WPA )
                    continue;

                /* if the PTK is valid, try to decrypt */

                if( st_cur == NULL || ! st_cur->valid_ptk )
                    continue;

                if( st_cur->keyver == 1 )
                {
                    if( decrypt_tkip( h80211, pkh.caplen,
                                      st_cur->ptk + 32 ) == 0 )
                        continue;

                    pkh.len    -= 20;
                    pkh.caplen -= 20;
                }
                else
                {
                    if( decrypt_ccmp( h80211, pkh.caplen,
                                      st_cur->ptk + 32 ) == 0 )
                        continue;

                    pkh.len    -= 16;
                    pkh.caplen -= 16;
                }

                /* WPA data packet was successfully decrypted, *
                 * remove the WPA Ext.IV & MIC, write the data */

                memcpy( h80211 + z, h80211 + z + 8, pkh.caplen - z );

                stats.nb_unwpa++;

                h80211[1] &= 0xBF;

                if( write_packet( f_out, &pkh, h80211 ) != 0 )
                    break;
            }
        }
        else
        {
            /* check ethertype == EAPOL */

            z += 6;

            if( h80211[z] != 0x88 || h80211[z + 1] != 0x8E )
            {
                stats.nb_plain++;

                if( opt.crypt != CRYPT_NONE )
                    continue;

                if( write_packet( f_out, &pkh, h80211 ) != 0 )
                    break;
            }

            z += 2;

            /* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

            if( h80211[z + 1] != 0x03 ||
                ( h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02 ) )
                continue;

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) != 0 &&
                ( h80211[z + 5] & 0x01 ) == 0 )
            {
                /* set authenticator nonce */

                memcpy( st_cur->anonce, &h80211[z + 17], 32 );
            }

            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) == 0 &&
                ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    /* set supplicant nonce */

                    memcpy( st_cur->snonce, &h80211[z + 17], 32 );
                }
            }

            /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) != 0 &&
                ( h80211[z + 6] & 0x80 ) != 0 &&
                ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    /* set authenticator nonce */

                    memcpy( st_cur->anonce, &h80211[z + 17], 32 );
                }

                /* copy the MIC & eapol frame */

                st_cur->eapol_size = ( h80211[z + 2] << 8 )
                                   +   h80211[z + 3] + 4;

                memcpy( st_cur->keymic, &h80211[z + 81], 16 );
                memcpy( st_cur->eapol, &h80211[z], st_cur->eapol_size );
                memset( st_cur->eapol + 81, 0, 16 );

                /* copy the key descriptor version */

                st_cur->keyver = h80211[z + 6] & 7;
            }

            st_cur->valid_ptk = calc_ptk( st_cur, opt.pmk );
        }
    }

    fclose( f_in  );
    fclose( f_out );

    /* write some statistics */

    printf( "\33[KTotal number of packets read      % 8ld\n"
                 "Total number of WEP data packets  % 8ld\n"
                 "Total number of WPA data packets  % 8ld\n"
                 "Number of plaintext data packets  % 8ld\n"
                 "Number of decrypted WEP  packets  % 8ld\n"
                 "Number of decrypted WPA  packets  % 8ld\n",
            stats.nb_read, stats.nb_wep, stats.nb_wpa,
            stats.nb_plain, stats.nb_unwep, stats.nb_unwpa );

    return( 0 );
}
