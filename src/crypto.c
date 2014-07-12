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

#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include "crypto.h"
#include "crctable.h"
#include "aircrack-ng.h"

#define GET_UINT32_LE(n,b,i)                    \
{                                               \
    (n) = ( (uint32_t) (b)[(i)    ]       )       \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )       \
        | ( (uint32_t) (b)[(i) + 2] << 16 )       \
        | ( (uint32_t) (b)[(i) + 3] << 24 );      \
}

#define PUT_UINT32_LE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8_t) ( (n)       );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uint8_t) ( (n) >> 24 );       \
}

#define GET_UINT32_BE(n,b,i)                    \
{                                               \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )       \
        | ( (uint32_t) (b)[(i) + 1] << 16 )       \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )       \
        | ( (uint32_t) (b)[(i) + 3]       );      \
}

#define PUT_UINT32_BE(n,b,i)                    \
{                                               \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}

static unsigned char ZERO[32] =
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00";

/* RC4 encryption/ WEP decryption check */

/*  SSL decryption */

int encrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen )
{
    RC4_KEY S;

    RC4_set_key( &S, keylen, key );
    RC4( &S, len, data, data );

    return ( 0 );

}

int decrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen )
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
int encrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen )
{
    struct rc4_state S;

    rc4_setup( &S, key, keylen );
    rc4_crypt( &S, data, len );

    return( 0 );
}

int decrypt_wep( unsigned char *data, int len, unsigned char *key, int keylen )
{
    struct rc4_state S;

    rc4_setup( &S, key, keylen );
    rc4_crypt( &S, data, len );

    return( check_crc_buf( data, len - 4 ) );
}
*/

/* derive the PMK from the passphrase and the essid */

void calc_pmk( char *key, char *essid_pre, unsigned char pmk[40] )
{
	int i, j, slen;
	unsigned char buffer[65];
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
	HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, pmk, NULL);
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
	HMAC(EVP_sha1(), (unsigned char *)key, strlen(key), (unsigned char*)essid, slen, pmk+20, NULL);
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
// 	unsigned char pke[100];
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
	unsigned char pke[100];
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

int is_wlccp(void *wh, int len)
{
	int wlccpsize = 58;

	if(wh) {}

	if (len == wlccpsize)
		return 1;

	return 0;
}

int is_qos_arp_tkip(void *wh, int len)
{
        unsigned char *packet = (unsigned char*) wh;
        int qosarpsize = (24 + 2) + 8 + (8 + (8 + 10*2)) + 8 + 4; //82 in total

        if((packet[1] & 3) == 1) //to ds
        {
            if (len == qosarpsize) //always wireless
                return 1;
        }

        if((packet[1] & 3) == 2) //from ds
        {
            if (len == qosarpsize || len == qosarpsize + 18) //wireless or padded wired
                return 1;
        }

        return 0;
}

int is_spantree(void *wh)
{
        if ( wh != NULL &&
	     (memcmp( wh +  4, SPANTREE, 6 ) == 0 ||
              memcmp( wh + 16, SPANTREE, 6 ) == 0 ))
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
        else if(is_wlccp(wh, len)) /*wlccp*/
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

/* derive the pairwise transcient keys from a bunch of stuff */

int calc_ptk( struct WPA_ST_info *wpa, unsigned char pmk[32] )
{
    int i;
    unsigned char pke[100];
    unsigned char mic[20];

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
        HMAC(EVP_sha1(), pmk, 32, pke, 100, wpa->ptk + i * 20, NULL );
    }

    /* check the EAPOL frame MIC */

    if( ( wpa->keyver & 0x07 ) == 1 )
        HMAC(EVP_md5(), wpa->ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL );
    else
        HMAC(EVP_sha1(), wpa->ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL );

    return( memcmp( mic, wpa->keymic, 16 ) == 0 );
}

int init_michael(struct Michael *mic, unsigned char key[8])
{
    mic->key0 = key[0]<<0 | key[1]<<8 | key[2]<<16 | key[3]<<24;
    mic->key1 = key[4]<<0 | key[5]<<8 | key[6]<<16 | key[7]<<24;
    // and reset the message
    mic->left  = mic->key0;
    mic->right = mic->key1;
    mic->nBytesInM = 0;
    mic->message = 0;
    return 0;
}

int michael_append_byte(struct Michael *mic, unsigned char byte)
{
    mic->message |= (byte << (8*mic->nBytesInM));
    mic->nBytesInM++;
    // Process the word if it is full.
    if( mic->nBytesInM >= 4 )
    {
        mic->left ^= mic->message;
        mic->right ^= ROL32( mic->left, 17 );
        mic->left += mic->right;
        mic->right ^= ((mic->left & 0xff00ff00) >> 8) | ((mic->left & 0x00ff00ff) << 8);
        mic->left += mic->right;
        mic->right ^= ROL32( mic->left, 3 );
        mic->left += mic->right;
        mic->right ^= ROR32( mic->left, 2 );
        mic->left += mic->right;
        // Clear the buffer
        mic->message = 0;
        mic->nBytesInM = 0;
    }
    return 0;
}

int michael_remove_byte(struct Michael *mic, unsigned char bytes[4])
{
    if( mic->nBytesInM == 0 )
    {
        // Clear the buffer
        mic->message = bytes[0] << 0 | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;
        mic->nBytesInM = 4;
        mic->left -= mic->right;
        mic->right ^= ROR32( mic->left, 2 );
        mic->left -= mic->right;
        mic->right ^= ROL32( mic->left, 3 );
        mic->left -= mic->right;
        mic->right ^= ((mic->left & 0xff00ff00) >> 8) | ((mic->left & 0x00ff00ff) << 8);
        mic->left -= mic->right;
        mic->right ^= ROL32( mic->left, 17 );
        mic->left ^= mic->message;
    }
    mic->nBytesInM--;
    mic->message &= ~(0xFF << (8*mic->nBytesInM));

    return 0;
}

int michael_append(struct Michael *mic, unsigned char *bytes, int length)
{
    while(length > 0)
    {
        michael_append_byte(mic, *bytes++);
        length--;
    }
    return 0;
}

int michael_remove(struct Michael *mic, unsigned char *bytes, int length)
{
    while(length >= 4)
    {
        michael_remove_byte(mic, (bytes+length-4));
        length--;
    }
    return 0;
}

int michael_finalize(struct Michael *mic)
{
    // Append the minimum padding
    michael_append_byte(mic, 0x5a );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    // and then zeroes until the length is a multiple of 4
    while( mic->nBytesInM != 0 )
    {
            michael_append_byte(mic, 0 );
    }
    // The appendByte function has already computed the result.
    mic->mic[0] = (mic->left  >> 0 ) & 0xff;
    mic->mic[1] = (mic->left  >> 8 ) & 0xff;
    mic->mic[2] = (mic->left  >> 16) & 0xff;
    mic->mic[3] = (mic->left  >> 24) & 0xff;
    mic->mic[4] = (mic->right >> 0 ) & 0xff;
    mic->mic[5] = (mic->right >> 8 ) & 0xff;
    mic->mic[6] = (mic->right >> 16) & 0xff;
    mic->mic[7] = (mic->right >> 24) & 0xff;

    return 0;
}

int michael_finalize_zero(struct Michael *mic)
{
    // Append the minimum padding
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    michael_append_byte(mic, 0 );
    // and then zeroes until the length is a multiple of 4
    while( mic->nBytesInM != 0 )
    {
            michael_append_byte(mic, 0 );
    }
    // The appendByte function has already computed the result.
    mic->mic[0] = (mic->left  >> 0 ) & 0xff;
    mic->mic[1] = (mic->left  >> 8 ) & 0xff;
    mic->mic[2] = (mic->left  >> 16) & 0xff;
    mic->mic[3] = (mic->left  >> 24) & 0xff;
    mic->mic[4] = (mic->right >> 0 ) & 0xff;
    mic->mic[5] = (mic->right >> 8 ) & 0xff;
    mic->mic[6] = (mic->right >> 16) & 0xff;
    mic->mic[7] = (mic->right >> 24) & 0xff;

    return 0;
}

int michael_test(unsigned char key[8], unsigned char *message, int length, unsigned char out[8])
{
    int i=0;
    struct Michael mic0;
    struct Michael mic1;
    struct Michael mic2;
    struct Michael mic;

    init_michael(&mic0, (unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00");
    init_michael(&mic1, (unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00");
    init_michael(&mic2, (unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00");

    michael_append_byte(&mic0, 0x02);
    michael_append_byte(&mic1, 0x01);
    michael_append_byte(&mic2, 0x03);

    michael_finalize(&mic0);
    michael_finalize_zero(&mic1);
    michael_finalize(&mic2);

    printf("Blub 2:");
    for(i=0; i<8; i++)
    {
        printf("%02X ", mic0.mic[i]);
    }
    printf("\n");

    printf("Blub 1:");
    for(i=0; i<8; i++)
    {
        printf("%02X ", mic1.mic[i]);
    }
    printf("\n");

    printf("Blub 3:");
    for(i=0; i<8; i++)
    {
        printf("%02X ", mic2.mic[i]);
    }
    printf("\n");

    init_michael(&mic, key);
    michael_append(&mic, message, length);
    michael_finalize(&mic);

    return (memcmp(mic.mic, out, 8) == 0);
}

int calc_tkip_mic_key(unsigned char* packet, int length, unsigned char key[8])
{
    int z, is_qos=0;
    unsigned char smac[6], dmac[6], bssid[6];
    unsigned char prio[4];
    unsigned char message[4096];
    unsigned char *ptr;
    struct Michael mic;

    memset(message, 0, 4096);

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z) return 0;

    /* Check if 802.11e (QoS) */
    if( (packet[0] & 0x80) == 0x80)
    {
        z+=2;
        is_qos = 1;
    }

    memset(prio, 0, 4);
    if(is_qos)
    {
        prio[0] = packet[z-2] & 0x0f;
    }

    switch( packet[1] & 3 )
    {
        case  0:
            memcpy( bssid, packet + 16, 6 );
            memcpy( dmac, packet + 4, 6 );
            memcpy( smac, packet + 10, 6 );
            break;
        case  1:
            memcpy( bssid, packet + 4, 6 );
            memcpy( dmac, packet + 16, 6 );
            memcpy( smac, packet + 10, 6 );
            break;
        case  2:
            memcpy( bssid, packet + 10, 6 );
            memcpy( dmac, packet + 4, 6 );
            memcpy( smac, packet + 16, 6 );
            break;
        default:
            memcpy( bssid, packet + 10, 6 );
            memcpy( dmac, packet + 16, 6 );
            memcpy( smac, packet + 24, 6 );
            break;
    }

    ptr = message;
    memcpy(ptr, dmac, 6);               ptr+=6;
    memcpy(ptr, smac, 6);               ptr+=6;
    memcpy(ptr, prio, 4);               ptr+=4;
    memcpy(ptr, packet+z, length-z-8);  ptr+=length-z-8;
    memcpy(ptr, "\x5a", 1);             ptr+=1;
    memcpy(ptr, ZERO, 4);               ptr+=4;
    if((ptr-message) % 4 > 0)
        memcpy(ptr, ZERO, 4-((ptr-message)%4)); ptr+=4-((ptr-message)%4);

    init_michael(&mic, packet+length-8);
    michael_remove(&mic, message, (ptr-message));

    mic.mic[0] = (mic.left >> 0 ) & 0xFF;
    mic.mic[1] = (mic.left >> 8 ) & 0xFF;
    mic.mic[2] = (mic.left >> 16) & 0xFF;
    mic.mic[3] = (mic.left >> 24) & 0xFF;
    mic.mic[4] = (mic.right >> 0 ) & 0xFF;
    mic.mic[5] = (mic.right >> 8 ) & 0xFF;
    mic.mic[6] = (mic.right >> 16) & 0xFF;
    mic.mic[7] = (mic.right >> 24) & 0xFF;

    memcpy(key, mic.mic, 8);
    return 0;
}

int calc_tkip_mic(unsigned char* packet, int length, unsigned char ptk[80], unsigned char value[8])
{
    int z, koffset=0, is_qos=0;
    unsigned char smac[6], dmac[6], bssid[6];
    unsigned char prio[4];
    struct Michael mic;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z) return 0;

    /* Check if 802.11e (QoS) */
    if( (packet[0] & 0x80) == 0x80)
    {
        z+=2;
        is_qos = 1;
    }

    switch( packet[1] & 3 )
    {
        case  0:
            memcpy( bssid, packet + 16, 6 );
            memcpy( dmac, packet + 4, 6 );
            memcpy( smac, packet + 10, 6 );
            break;
        case  1:
            memcpy( bssid, packet + 4, 6 );
            memcpy( dmac, packet + 16, 6 );
            memcpy( smac, packet + 10, 6 );
            koffset = 48+8;
            break;
        case  2:
            memcpy( bssid, packet + 10, 6 );
            memcpy( dmac, packet + 4, 6 );
            memcpy( smac, packet + 16, 6 );
            koffset = 48;
            break;
        default:
            memcpy( bssid, packet + 10, 6 );
            memcpy( dmac, packet + 16, 6 );
            memcpy( smac, packet + 24, 6 );
            break;
    }

    if(koffset != 48 && koffset != 48+8)
        return 1;

    init_michael(&mic, ptk+koffset);

    michael_append(&mic, dmac, 6);
    michael_append(&mic, smac, 6);

    memset(prio, 0, 4);
    if(is_qos)
    {
        prio[0] = packet[z-2] & 0x0f;
    }
    michael_append(&mic, prio, 4);

    michael_append(&mic, packet+z, length - z);

    michael_finalize(&mic);

    memcpy(value, mic.mic, 8);

    return 0;
}

const short TkipSbox[2][256]=
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

/* TKIP (RC4 + key mixing) decryption routine */

#define ROTR1(x)      ((((x) >> 1) & 0x7FFF) ^ (((x) & 1) << 15))
#define LO8(x)        ( (x) & 0x00FF )
#define LO16(x)       ( (x) & 0xFFFF )
#define HI8(x)        ( ((x) >>  8) & 0x00FF )
#define HI16(x)       ( ((x) >> 16) & 0xFFFF )
#define MK16(hi,lo)   ( (lo) ^ ( LO8(hi) << 8 ) )
#define TK16(N)       MK16(TK1[2*(N)+1],TK1[2*(N)])
#define _S_(x)        (TkipSbox[0][LO8(x)] ^ TkipSbox[1][HI8(x)])

int calc_tkip_ppk( unsigned char *h80211, int caplen, unsigned char TK1[16], unsigned char key[16] )
{
    int i, z;
    uint32_t IV32;
    uint16_t IV16;
    uint16_t PPK[6];

    if(caplen) {}

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

    key[0] =   HI8( IV16 );
    key[1] = ( HI8( IV16 ) | 0x20 ) & 0x7F;
    key[2] =   LO8( IV16 );
    key[3] =   LO8( (PPK[5] ^ TK16(0) ) >> 1);

    for( i = 0; i < 6; i++ )
    {
        key[4 + ( 2 * i)] = LO8( PPK[i] );
        key[5 + ( 2 * i)] = HI8( PPK[i] );
    }

    return 0;
}

int decrypt_tkip( unsigned char *h80211, int caplen, unsigned char TK1[16] )
{
    unsigned char K[16];
    int z;

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS ) {
        z += 2;
    }

    calc_tkip_ppk( h80211, caplen, TK1, K );

    return( decrypt_wep( h80211 + z + 8, caplen - z - 8, K, 16 ) );
}

/* CCMP (AES-CTR-MAC) decryption routine */

static inline void XOR( unsigned char *dst, unsigned char *src, int len )
{
    int i;
    for( i = 0; i < len; i++ )
        dst[i] ^= src[i];
}

int decrypt_ccmp( unsigned char *h80211, int caplen, unsigned char TK1[16] )
{
    int is_a4, i, n, z, blocks, is_qos;
    int data_len, last, offset;
    unsigned char B0[16], B[16], MIC[16];
    unsigned char PN[6], AAD[32];
    AES_KEY aes_ctx;

    is_a4 = ( h80211[1] & 3 ) == 3;
    is_qos = ( h80211[0] & 0x8C ) == 0x88;
    z = 24 + 6 * is_a4;
    z += 2 * is_qos;

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
    
    AAD[2] = h80211[0] & 0x8F;
    AAD[3] = h80211[1] & 0xC7;
    memcpy( AAD + 4, h80211 + 4, 3 * 6 );
    AAD[22] = h80211[22] & 0x0F;
    
    if( is_a4 ) 
    {
        memcpy( AAD + 24, h80211 + 24, 6 );
        
        if( is_qos ) 
        {
            AAD[30] = h80211[z - 2] & 0x0F;
            AAD[31] = 0;
            B0[1] = AAD[30];
            AAD[1] = 22 + 2 + 6;
        } 
        else 
        {
            memset(&AAD[30], 0, 2);
            B0[1] = 0;
            AAD[1] = 22 + 6;
        }
    } 
    else 
    {
        if( is_qos ) 
        {
            AAD[24] = h80211[z - 2] & 0x0F;
            AAD[25] = 0;
            B0[1] = AAD[24];
            AAD[1] = 22 + 2;
        }
        else
        {
            memset(&AAD[24], 0, 2);
            B0[1] = 0;
            AAD[1] = 22;
        }
    }

    AES_set_encrypt_key( TK1, 128, &aes_ctx );
    AES_encrypt( B0, MIC, &aes_ctx );
    XOR( MIC, AAD, 16 );
    AES_encrypt( MIC, MIC, &aes_ctx );
    XOR( MIC, AAD + 16, 16 );
    AES_encrypt( MIC, MIC, &aes_ctx );

    B0[0] &= 0x07;
    B0[14] = B0[15] = 0;
    AES_encrypt( B0, B, &aes_ctx );
    XOR( h80211 + caplen - 8, B, 8 );

    blocks = ( data_len + 16 - 1 ) / 16;
    last = data_len % 16;
    offset = z + 8;

    for( i = 1; i <= blocks; i++ )
    {
        n = ( last > 0 && i == blocks ) ? last : 16;

        B0[14] = ( i >> 8 ) & 0xFF;
        B0[15] =   i & 0xFF;

        AES_encrypt( B0, B, &aes_ctx );
        XOR( h80211 + offset, B, n );
        XOR( MIC, h80211 + offset, n );
        AES_encrypt( MIC, MIC, &aes_ctx );

        offset += n;
    }

    // We need to free the ctx when using gcrypt to avoid memory leaks
    #ifdef USE_GCRYPT
        gcry_cipher_close(aes_ctx);
    #endif

    return( memcmp( h80211 + offset, MIC, 8 ) == 0 );
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
