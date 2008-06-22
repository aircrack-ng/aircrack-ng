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
#include <assert.h>
#include "crypto.h"
#include "crctable.h"
#include "aircrack-ng.h"

#define uchar  unsigned char

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

/* RC4 encryption/ WEP decryption check */

/*  SSL decryption */

int encrypt_wep( uchar *data, int len, uchar *key, int keylen )
{
    RC4_KEY S;

    RC4_set_key( &S, keylen, key );
    RC4( &S, len, data, data );

    return ( 0 );

}

int decrypt_wep( uchar *data, int len, uchar *key, int keylen )
{
    encrypt_wep (data,len,key,keylen);
    return( check_crc_buf( data, len - 4 ) );

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

/* WEP (barebone RC4) en-/decryption routines */
/*
int encrypt_wep( uchar *data, int len, uchar *key, int keylen )
{
    struct rc4_state S;

    rc4_setup( &S, key, keylen );
    rc4_crypt( &S, data, len );

    return( 0 );
}

int decrypt_wep( uchar *data, int len, uchar *key, int keylen )
{
    struct rc4_state S;

    rc4_setup( &S, key, keylen );
    rc4_crypt( &S, data, len );

    return( check_crc_buf( data, len - 4 ) );
}
*/

/* derive the PMK from the passphrase and the essid */

void calc_pmk( char *key, char *essid_pre, uchar pmk[40] )
{
	int i, j, slen;
	uchar buffer[65];
	char essid[33+4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, strlen(essid_pre));
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x36;

	SHA1_Init( &ctx_ipad );
	SHA1_Update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x6A;

	SHA1_Init( &ctx_opad );
	SHA1_Update( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmk, NULL);
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	HMAC(EVP_sha1(), (uchar *)key, strlen(key), (uchar*)essid, slen, pmk+20, NULL);
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		SHA1_Update( &sha1_ctx, buffer, 20 );
		SHA1_Final( buffer, &sha1_ctx );

		for( j = 0; j < 20; j++ )
			pmk[j + 20] ^= buffer[j];
	}
}

// void calc_ptk (struct WPA_hdsk *wpa, unsigned char bssid[6], unsigned char pmk[32], unsigned char ptk[80]) {
// 	int i;
// 	uchar pke[100];
// 	HMAC_CTX ctx;
//
// 	memcpy( pke, "Pairwise key expansion", 23 );
//
// 	if( memcmp( wpa->stmac, bssid, 6 ) < 0 )
// 	{
// 		memcpy( pke + 23, wpa->stmac, 6 );
// 		memcpy( pke + 29, bssid, 6 );
// 	}
// 	else
// 	{
// 		memcpy( pke + 23, bssid, 6 );
// 		memcpy( pke + 29, wpa->stmac, 6 );
// 	}
//
// 	if( memcmp( wpa->snonce, wpa->anonce, 32 ) < 0 )
// 	{
// 		memcpy( pke + 35, wpa->snonce, 32 );
// 		memcpy( pke + 67, wpa->anonce, 32 );
// 	}
// 	else
// 	{
// 		memcpy( pke + 35, wpa->anonce, 32 );
// 		memcpy( pke + 67, wpa->snonce, 32 );
// 	}
//
// 	HMAC_CTX_init(&ctx);
// 	HMAC_Init_ex(&ctx, pmk, 32, EVP_sha1(), NULL);
// 	for(i = 0; i < 4; i++ )
// 	{
// 		pke[99] = i;
// 		//HMAC(EVP_sha1(), values[0], 32, pke, 100, ptk + i * 20, NULL);
// 		HMAC_Init_ex(&ctx, 0, 0, 0, 0);
// 		HMAC_Update(&ctx, pke, 100);
// 		HMAC_Final(&ctx, ptk + i*20, NULL);
// 	}
// 	HMAC_CTX_cleanup(&ctx);
// }

void calc_mic (struct AP_info *ap, unsigned char pmk[32], unsigned char ptk[80], unsigned char mic[20]) {
	int i;
	uchar pke[100];
	HMAC_CTX ctx;

	memcpy( pke, "Pairwise key expansion", 23 );

	if( memcmp( ap->wpa.stmac, ap->bssid, 6 ) < 0 )
	{
		memcpy( pke + 23, ap->wpa.stmac, 6 );
		memcpy( pke + 29, ap->bssid, 6 );
	}
	else
	{
		memcpy( pke + 23, ap->bssid, 6 );
		memcpy( pke + 29, ap->wpa.stmac, 6 );
	}

	if( memcmp( ap->wpa.snonce, ap->wpa.anonce, 32 ) < 0 )
	{
		memcpy( pke + 35, ap->wpa.snonce, 32 );
		memcpy( pke + 67, ap->wpa.anonce, 32 );
	}
	else
	{
		memcpy( pke + 35, ap->wpa.anonce, 32 );
		memcpy( pke + 67, ap->wpa.snonce, 32 );
	}

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, pmk, 32, EVP_sha1(), NULL);
	for(i = 0; i < 4; i++ )
	{
		pke[99] = i;
		//HMAC(EVP_sha1(), values[0], 32, pke, 100, ptk + i * 20, NULL);
		HMAC_Init_ex(&ctx, 0, 0, 0, 0);
		HMAC_Update(&ctx, pke, 100);
		HMAC_Final(&ctx, ptk + i*20, NULL);
	}
	HMAC_CTX_cleanup(&ctx);

	if( ap->wpa.keyver == 1 )
	{
		HMAC(EVP_md5(), ptk, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic, NULL);
	}
	else
	{
		HMAC(EVP_sha1(), ptk, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic, NULL);
	}

}

unsigned long calc_crc( unsigned char * buf, int len)
{
    unsigned long crc = 0xFFFFFFFF;

    for( ; len > 0; len--, buf++ )
        crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ ( crc >> 8 );

    return( ~crc );
}

//without inversion, must be used for bit flipping attacks
unsigned long calc_crc_plain( unsigned char * buf, int len)
{
    unsigned long crc = 0x00000000;

    for( ; len > 0; len--, buf++ )
        crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ ( crc >> 8 );

    return( crc );
}

/* CRC checksum verification routine */

int check_crc_buf( unsigned char *buf, int len )
{
    unsigned long crc;

    crc = calc_crc(buf, len);
    buf+=len;
    return( ( ( crc       ) & 0xFF ) == buf[0] &&
            ( ( crc >>  8 ) & 0xFF ) == buf[1] &&
            ( ( crc >> 16 ) & 0xFF ) == buf[2] &&
            ( ( crc >> 24 ) & 0xFF ) == buf[3] );
}

/* Add CRC32 */

int add_crc32(unsigned char* data, int length)
{
    unsigned long crc;

    crc = calc_crc(data, length);

    data[length]   = (crc      ) & 0xFF;
    data[length+1] = (crc >>  8) & 0xFF;
    data[length+2] = (crc >> 16) & 0xFF;
    data[length+3] = (crc >> 24) & 0xFF;

    return 0;
}

int add_crc32_plain(unsigned char* data, int length)
{
    unsigned long crc;

    crc = calc_crc_plain(data, length);

    data[length]   = (crc      ) & 0xFF;
    data[length+1] = (crc >>  8) & 0xFF;
    data[length+2] = (crc >> 16) & 0xFF;
    data[length+3] = (crc >> 24) & 0xFF;

    return 0;
}

int calc_crc_buf( unsigned char *buf, int len )
{
    return (calc_crc(buf, len));
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

int is_ipv6(void *wh)
{
    if(memcmp(wh+4, "\x33\x33", 2) == 0 || memcmp(wh+16, "\x33\x33", 2) == 0)
        return 1;

    return 0;
}

int is_dhcp_discover(void *wh, int len)
{
    if( (memcmp(wh+4, BROADCAST, 6) == 0 || memcmp(wh+16, BROADCAST, 6) == 0) && (len >= 360 - 24 - 4 - 4 && len <= 380 - 24 - 4 - 4 )  )
        return 1;

    return 0;
}

int is_arp(void *wh, int len)
{
        int arpsize = 8 + 8 + 10*2;

        if(wh) {}
        /* remove non BROADCAST frames? could be anything, but
         * chances are good that we got an arp response tho.   */

        if (len == arpsize || len == 54)
            return 1;

        return 0;
}

int is_spantree(void *wh)
{
        if ( memcmp( wh +  4, SPANTREE, 6 ) == 0 ||
             memcmp( wh + 16, SPANTREE, 6 ) == 0 )
            return 1;

        return 0;
}

int is_cdp_vtp(void *wh)
{
        if ( memcmp( wh +  4, CDP_VTP, 6 ) == 0 ||
             memcmp( wh + 16, CDP_VTP, 6 ) == 0 )
            return 1;

        return 0;
}

/* weight is used for guesswork in PTW.  Can be null if known_clear is not for
 * PTW, but just for getting known clear-text.
 */
int known_clear(void *clear, int *clen, int *weight, unsigned char *wh, int len)
{
        unsigned char *ptr = clear;
        int num;

        if(is_arp(wh, len)) /*arp*/
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

            len = ptr - ((unsigned char*)clear);
            *clen = len;
	    if (weight)
                weight[0] = 256;
            return 1;

        }
        else if(is_spantree(wh)) /*spantree*/
        {
            len = sizeof(S_LLC_SNAP_SPANTREE) - 1;
            memcpy(ptr, S_LLC_SNAP_SPANTREE, len);
            ptr += len;

            len = ptr - ((unsigned char*)clear);
            *clen = len;
	    if (weight)
                weight[0] = 256;
            return 1;
        }
        else if(is_cdp_vtp(wh)) /*spantree*/
        {
            len = sizeof(S_LLC_SNAP_CDP) - 1;
            memcpy(ptr, S_LLC_SNAP_CDP, len);
            ptr += len;

            len = ptr - ((unsigned char*)clear);
            *clen = len;
	    if (weight)
                weight[0] = 256;
            return 1;
        }
        else /* IP */
        {
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

		/* no guesswork */
		if (!weight) {
			*clen = ptr - ((unsigned char*)clear);
			return 1;
		}
#if 1
		/* setting IP ID 0 is ok, as we
                 * bruteforce it later
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
                *clen = len;

                memcpy(clear+32, clear, len);
                memcpy(clear+32+14, "\x00\x00", 2); //ip flags=none

                num=2;
		assert(weight);
                weight[0] = 220;
                weight[1] = 36;

                return num;
        }
        *clen=0;
        return 1;
}

/*
**********************************************************************
* Routine: Phase 1 -- generate P1K, given TA, TK, IV32
*
* Inputs:
*        TK[]             = Temporal Key                   [128 bits]
*        TA[]             = transmitter's MAC address      [ 48 bits]
*        IV32             = upper 32 bits of IV            [ 32 bits]
* Output:
*        P1K[]            = Phase 1 key                    [ 80 bits]
*
* Note:
*        This function only needs to be called every 2**16 frames,
*        although in theory it could be called every frame.
*
**********************************************************************
*/
// void Phase1(u16b *P1K,const byte *TK,const byte *TA,u32b IV32)
//         {
//         int  i;
//         /* Initialize the 80 bits of P1K[] from IV32 and TA[0..5]                 */
//         P1K[0]      = Lo16(IV32);
//         P1K[1]      = Hi16(IV32);
//         P1K[2]      = Mk16(TA[1],TA[0]); /* use TA[] as little-endian */
//         P1K[3]      = Mk16(TA[3],TA[2]);
//         P1K[4]      = Mk16(TA[5],TA[4]);
//         /* Now compute an unbalanced Feistel cipher with 80-bit block             */
//         /* size on the 80-bit block P1K[], using the 128-bit key TK[]             */
//         for (i=0; i < PHASE1_LOOP_CNT ;i++)
//             {                 /* Each add operation here is mod 2**16             */
//             P1K[0] += _S_(P1K[4] ^ TK16((i&1)+0));
//             P1K[1] += _S_(P1K[0] ^ TK16((i&1)+2));
//             P1K[2] += _S_(P1K[1] ^ TK16((i&1)+4));
//             P1K[3] += _S_(P1K[2] ^ TK16((i&1)+6));
//             P1K[4] += _S_(P1K[3] ^ TK16((i&1)+0));
//             P1K[4] += i;                     /* avoid "slide attacks"             */
//             }
//         }
    /*
    **********************************************************************
    * Routine: Phase 2 -- generate RC4KEY, given TK, P1K, IV16
    *
    * Inputs:
    *       TK[]      = Temporal Key                              [128 bits]
    *       P1K[]     = Phase 1 output key                        [ 80 bits]
    *       IV16      = low 16 bits of IV counter                 [ 16 bits]
    * Output:
    *       RC4KEY[] = the key used to encrypt the frame          [128 bits]
    *
    * Note:
    *       The value {TA,IV32,IV16} for Phase1/Phase2 must be unique
    *       across all frames using the same key TK value. Then, for a
    *       given value of TK[], this TKIP48 construction guarantees that
    *       the final RC4KEY value is unique across all frames.
    *
    * Suggested implementation optimization: if PPK[] is "overlaid"
    *       appropriately on RC4KEY[], there is no need for the final
    *       for loop below that copies the PPK[] result into RC4KEY[].
    *
    **********************************************************************
    */
//     void Phase2(byte *RC4KEY,const byte *TK,const u16b *P1K,u16b IV16)
//         {
//         int i;
//         u16b PPK[6];                        /* temporary key for mixing                  */
//         /* all adds in the PPK[] equations below are mod 2**16                     */
//         for (i=0;i<5;i++) PPK[i]=P1K[i];    /* first, copy P1K to PPK                    */
//         PPK[5] = P1K[4] + IV16;             /* next, add in IV16                         */
//         /* Bijective non-linear mixing of the 96 bits of PPK[0..5]                       */
//         PPK[0] +=    _S_(PPK[5] ^ TK16(0)); /* Mix key in each "round"                   */
//         PPK[1] +=    _S_(PPK[0] ^ TK16(1));
//         PPK[2] +=    _S_(PPK[1] ^ TK16(2));
//         PPK[3] +=            _S_(PPK[2] ^ TK16(3));
//         PPK[4] +=            _S_(PPK[3] ^ TK16(4));
//         PPK[5] +=            _S_(PPK[4] ^ TK16(5)); /* Total # S-box lookups == 6        */
//         /* Final sweep: bijective, linear. Rotates kill LSB correlations                 */
//         PPK[0] += RotR1(PPK[5] ^ TK16(6));
//         PPK[1] += RotR1(PPK[0] ^ TK16(7)); /* Use all of TK[] in Phase2                  */
//         PPK[2] += RotR1(PPK[1]);
//         PPK[3] += RotR1(PPK[2]);
//         PPK[4] += RotR1(PPK[3]);
//         PPK[5] += RotR1(PPK[4]);
//         /* At this point, for a given key TK[0..15], the 96-bit output */
//         /*        value PPK[0..5] is guaranteed to be unique, as a function              */
//         /*        of the 96-bit "input" value         {TA,IV32,IV16}. That is, P1K       */
//         /*        is now a keyed permutation of {TA,IV32,IV16}.                          */
//         /* Set RC4KEY[0..3], which includes cleartext portion of RC4 key                 */
//         RC4KEY[0] = Hi8(IV16);                      /* RC4KEY[0..2] is the WEP IV        */
//         RC4KEY[1] =(Hi8(IV16) | 0x20) & 0x7F; /* Help avoid FMS weak keys                */
//         RC4KEY[2] = Lo8(IV16);
//         RC4KEY[3] = Lo8((PPK[5] ^ TK16(0)) >> 1);
//         /* Copy 96 bits of PPK[0..5] to RC4KEY[4..15]          (little-endian)            */
//         for (i=0;i<6;i++)
//             {
//             RC4KEY[4+2*i] = Lo8(PPK[i]);
//             RC4KEY[5+2*i] = Hi8(PPK[i]);
//             }
//         }
