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

#ifdef USE_GCRYPT
#include "gcrypt-openssl-wrapper.h"
#include "sha1-git.h"
#else
#include <openssl/hmac.h>
#include <openssl/sha.h>
// We don't use EVP. Bite me
#include <openssl/rc4.h>
#include <openssl/aes.h>
#endif

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_WLCCP      "\xAA\xAA\x03\x00\x40\x96\x00\x00"
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define S_LLC_SNAP_SPANTREE   "\x42\x42\x03\x00\x00\x00\x00\x00"
#define S_LLC_SNAP_CDP  "\xAA\xAA\x03\x00\x00\x0C\x20"
#define IEEE80211_FC1_DIR_FROMDS                0x02    /* AP ->STA */

#define TYPE_ARP    0
#define TYPE_IP     1

#define NULL_MAC  (unsigned char*)"\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char*)"\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE  (unsigned char*)"\x01\x80\xC2\x00\x00\x00"
#define CDP_VTP   (unsigned char*)"\x01\x00\x0C\xCC\xCC\xCC"

#define	IEEE80211_FC0_SUBTYPE_MASK              0xf0
#define	IEEE80211_FC0_SUBTYPE_SHIFT             4

/* for TYPE_DATA (bit combination) */
#define	IEEE80211_FC0_SUBTYPE_QOS               0x80
#define	IEEE80211_FC0_SUBTYPE_QOS_NULL          0xc0

#define GET_SUBTYPE(fc) \
    ( ( (fc) & IEEE80211_FC0_SUBTYPE_MASK ) >> IEEE80211_FC0_SUBTYPE_SHIFT ) \
        << IEEE80211_FC0_SUBTYPE_SHIFT

#define ROL32( A, n ) \
	( ((A) << (n)) | ( ((A)>>(32-(n))) & ( (1UL << (n)) - 1 ) ) )
#define ROR32( A, n ) ROL32( (A), 32-(n) )

struct WPA_ST_info
{
    struct WPA_ST_info *next;       /* next supplicant              */
    unsigned char stmac[6];             /* supplicant MAC               */
    unsigned char bssid[6];             /* authenticator MAC            */
    unsigned char snonce[32];           /* supplicant nonce             */
    unsigned char anonce[32];           /* authenticator nonce          */
    unsigned char keymic[20];           /* eapol frame MIC              */
    unsigned char eapol[256];           /* eapol frame contents         */
    unsigned char ptk[80];              /* pairwise transcient key      */
    unsigned eapol_size;            /* eapol frame size             */
    unsigned long t_crc;        /* last ToDS   frame CRC        */
    unsigned long f_crc;        /* last FromDS frame CRC        */
    int keyver, valid_ptk;
    unsigned char pn[6];                /* Packet Number (WPA-CCMP) */
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


// typedef unsigned char byte;    /* 8-bit byte (octet) */
// typedef unsigned short u16b;   /* 16-bit unsigned word */
// typedef unsigned long u32b;    /* 32-bit unsigned word */
// /* macros for extraction/creation of byte/u16b values */
// #define RotR1(v16)   ((((v16) >> 1) & 0x7FFF) ^ (((v16) & 1) << 15))
// #define   Lo8(v16)   ((byte)( (v16)       & 0x00FF))
// #define   Hi8(v16)   ((byte)(((v16) >> 8) & 0x00FF))
// #define Lo16(v32)    ((u16b)( (v32)       & 0xFFFF))
// #define Hi16(v32)    ((u16b)(((v32) >>16) & 0xFFFF))
// #define Mk16(hi,lo) ((lo) ^ (((u16b)(hi)) << 8))
// /* select the Nth 16-bit word of the Temporal Key byte array TK[]               */
// #define TK16(N)      Mk16(TK[2*(N)+1],TK[2*(N)])
// /* S-box lookup: 16 bits --> 16 bits */
// #define _S_(v16)     (Sbox[0][Lo8(v16)] ^ Sbox[1][Hi8(v16)])
// /* fixed algorithm "parameters" */
// #define PHASE1_LOOP_CNT   8    /* this needs to be "big enough"                 */
// #define TA_SIZE           6    /* 48-bit transmitter address                    */
// #define TK_SIZE          16    /* 128-bit Temporal Key                          */
// #define P1K_SIZE         10    /* 80-bit Phase1 key                             */
// #define RC4_KEY_SIZE     16    /* 128-bit RC4KEY (104 bits unknown)             */


/* 2-byte by 2-byte subset of the full AES S-box table */
// const u16b TkipSbox[2][256]=            /* Sbox for hash (can be in ROM)       */
// {{
//         0xC6A5,0xF884,0xEE99,0xF68D,0xFF0D,0xD6BD,0xDEB1,0x9154,
//         0x6050,0x0203,0xCEA9,0x567D,0xE719,0xB562,0x4DE6,0xEC9A,
//         0x8F45,0x1F9D,0x8940,0xFA87,0xEF15,0xB2EB,0x8EC9,0xFB0B,
//         0x41EC,0xB367,0x5FFD,0x45EA,0x23BF,0x53F7,0xE496,0x9B5B,
//         0x75C2,0xE11C,0x3DAE,0x4C6A,0x6C5A,0x7E41,0xF502,0x834F,
//         0x685C,0x51F4,0xD134,0xF908,0xE293,0xAB73,0x6253,0x2A3F,
//         0x080C,0x9552,0x4665,0x9D5E,0x3028,0x37A1,0x0A0F,0x2FB5,
//         0x0E09,0x2436,0x1B9B,0xDF3D,0xCD26,0x4E69,0x7FCD,0xEA9F,
//         0x121B,0x1D9E,0x5874,0x342E,0x362D,0xDCB2,0xB4EE,0x5BFB,
//         0xA4F6,0x764D,0xB761,0x7DCE,0x527B,0xDD3E,0x5E71,0x1397,
//         0xA6F5,0xB968,0x0000,0xC12C,0x4060,0xE31F,0x79C8,0xB6ED,
//         0xD4BE,0x8D46,0x67D9,0x724B,0x94DE,0x98D4,0xB0E8,0x854A,
//         0xBB6B,0xC52A,0x4FE5,0xED16,0x86C5,0x9AD7,0x6655,0x1194,
//         0x8ACF,0xE910,0x0406,0xFE81,0xA0F0,0x7844,0x25BA,0x4BE3,
//         0xA2F3,0x5DFE,0x80C0,0x058A,0x3FAD,0x21BC,0x7048,0xF104,
//         0x63DF,0x77C1,0xAF75,0x4263,0x2030,0xE51A,0xFD0E,0xBF6D,
//         0x814C,0x1814,0x2635,0xC32F,0xBEE1,0x35A2,0x88CC,0x2E39,
//         0x9357,0x55F2,0xFC82,0x7A47,0xC8AC,0xBAE7,0x322B,0xE695,
//         0xC0A0,0x1998,0x9ED1,0xA37F,0x4466,0x547E,0x3BAB,0x0B83,
//         0x8CCA,0xC729,0x6BD3,0x283C,0xA779,0xBCE2,0x161D,0xAD76,
//         0xDB3B,0x6456,0x744E,0x141E,0x92DB,0x0C0A,0x486C,0xB8E4,
//         0x9F5D,0xBD6E,0x43EF,0xC4A6,0x39A8,0x31A4,0xD337,0xF28B,
//         0xD532,0x8B43,0x6E59,0xDAB7,0x018C,0xB164,0x9CD2,0x49E0,
//         0xD8B4,0xACFA,0xF307,0xCF25,0xCAAF,0xF48E,0x47E9,0x1018,
//         0x6FD5,0xF088,0x4A6F,0x5C72,0x3824,0x57F1,0x73C7,0x9751,
//         0xCB23,0xA17C,0xE89C,0x3E21,0x96DD,0x61DC,0x0D86,0x0F85,
//         0xE090,0x7C42,0x71C4,0xCCAA,0x90D8,0x0605,0xF701,0x1C12,
//         0xC2A3,0x6A5F,0xAEF9,0x69D0,0x1791,0x9958,0x3A27,0x27B9,
//         0xD938,0xEB13,0x2BB3,0x2233,0xD2BB,0xA970,0x0789,0x33A7,
//         0x2DB6,0x3C22,0x1592,0xC920,0x8749,0xAAFF,0x5078,0xA57A,
//         0x038F,0x59F8,0x0980,0x1A17,0x65DA,0xD731,0x84C6,0xD0B8,
//         0x82C3,0x29B0,0x5A77,0x1E11,0x7BCB,0xA8FC,0x6DD6,0x2C3A,
//     },
//     { /* second half of table is byte-reversed version of first! */
//         0xA5C6,0x84F8,0x99EE,0x8DF6,0x0DFF,0xBDD6,0xB1DE,0x5491,
//         0x5060,0x0302,0xA9CE,0x7D56,0x19E7,0x62B5,0xE64D,0x9AEC,
//         0x458F,0x9D1F,0x4089,0x87FA,0x15EF,0xEBB2,0xC98E,0x0BFB,
//         0xEC41,0x67B3,0xFD5F,0xEA45,0xBF23,0xF753,0x96E4,0x5B9B,
//         0xC275,0x1CE1,0xAE3D,0x6A4C,0x5A6C,0x417E,0x02F5,0x4F83,
//         0x5C68,0xF451,0x34D1,0x08F9,0x93E2,0x73AB,0x5362,0x3F2A,
//         0x0C08,0x5295,0x6546,0x5E9D,0x2830,0xA137,0x0F0A,0xB52F,
//         0x090E,0x3624,0x9B1B,0x3DDF,0x26CD,0x694E,0xCD7F,0x9FEA,
//         0x1B12,0x9E1D,0x7458,0x2E34,0x2D36,0xB2DC,0xEEB4,0xFB5B,
//         0xF6A4,0x4D76,0x61B7,0xCE7D,0x7B52,0x3EDD,0x715E,0x9713,
//         0xF5A6,0x68B9,0x0000,0x2CC1,0x6040,0x1FE3,0xC879,0xEDB6,
//         0xBED4,0x468D,0xD967,0x4B72,0xDE94,0xD498,0xE8B0,0x4A85,
//         0x6BBB,0x2AC5,0xE54F,0x16ED,0xC586,0xD79A,0x5566,0x9411,
//         0xCF8A,0x10E9,0x0604,0x81FE,0xF0A0,0x4478,0xBA25,0xE34B,
//         0xF3A2,0xFE5D,0xC080,0x8A05,0xAD3F,0xBC21,0x4870,0x04F1,
//         0xDF63,0xC177,0x75AF,0x6342,0x3020,0x1AE5,0x0EFD,0x6DBF,
//         0x4C81,0x1418,0x3526,0x2FC3,0xE1BE,0xA235,0xCC88,0x392E,
//         0x5793,0xF255,0x82FC,0x477A,0xACC8,0xE7BA,0x2B32,0x95E6,
//         0xA0C0,0x9819,0xD19E,0x7FA3,0x6644,0x7E54,0xAB3B,0x830B,
//         0xCA8C,0x29C7,0xD36B,0x3C28,0x79A7,0xE2BC,0x1D16,0x76AD,
//         0x3BDB,0x5664,0x4E74,0x1E14,0xDB92,0x0A0C,0x6C48,0xE4B8,
//         0x5D9F,0x6EBD,0xEF43,0xA6C4,0xA839,0xA431,0x37D3,0x8BF2,
//         0x32D5,0x438B,0x596E,0xB7DA,0x8C01,0x64B1,0xD29C,0xE049,
//         0xB4D8,0xFAAC,0x07F3,0x25CF,0xAFCA,0x8EF4,0xE947,0x1810,
//         0xD56F,0x88F0,0x6F4A,0x725C,0x2438,0xF157,0xC773,0x5197,
//         0x23CB,0x7CA1,0x9CE8,0x213E,0xDD96,0xDC61,0x860D,0x850F,
//         0x90E0,0x427C,0xC471,0xAACC,0xD890,0x0506,0x01F7,0x121C,
//         0xA3C2,0x5F6A,0xF9AE,0xD069,0x9117,0x5899,0x273A,0xB927,
//         0x38D9,0x13EB,0xB32B,0x3322,0xBBD2,0x70A9,0x8907,0xA733,
//         0xB62D,0x223C,0x9215,0x20C9,0x4987,0xFFAA,0x7850,0x7AA5,
//         0x8F03,0xF859,0x8009,0x171A,0xDA65,0x31D7,0xC684,0xB8D0,
//         0xC382,0xB029,0x775A,0x111E,0xCB7B,0xFCA8,0xD66D,0x3A2C,
//     }
// };
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
int is_ipv6(void *wh);
int is_dhcp_discover(void *wh, int len);
int is_qos_arp_tkip(void *wh, int len);
int calc_tkip_ppk( unsigned char *h80211, int caplen, unsigned char TK1[16], unsigned char key[16] );
int decrypt_tkip( unsigned char *h80211, int caplen, unsigned char TK1[16] );
int encrypt_ccmp( unsigned char *h80211, int caplen, unsigned char TK1[16], unsigned char PN[6] );
int decrypt_ccmp( unsigned char *h80211, int caplen, unsigned char TK1[16] );
int calc_ptk( struct WPA_ST_info *wpa, unsigned char pmk[32] );
int calc_tkip_mic(unsigned char* packet, int length, unsigned char ptk[80], unsigned char value[8]);
int michael_test(unsigned char key[8], unsigned char *message, int length, unsigned char out[8]);
int calc_tkip_mic_key(unsigned char* packet, int length, unsigned char key[8]);
#endif /* crypto.h */
