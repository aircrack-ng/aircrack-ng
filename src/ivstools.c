 /*
  *  IVS Tools - Convert or merge IVs
  *
  *  Copyright (C) 2006-2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
  *  Copyright (C) 2004, 2005  Christophe Devine (pcap2ivs and mergeivs)
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "version.h"
#include "crypto.h"
#include "pcap.h"
#include "uniqueiv.h"
#include "osdep/byteorder.h"
#include "common.h"
#include "eapol.h"

#define FAILURE -1
#define IVS     1
#define WPA     2
#define ESSID   3

/* linked list of detected access points */

struct AP_info
{
    struct AP_info *prev;     /* prev. AP in list         */
    struct AP_info *next;     /* next  AP in list         */

    int ssid_length;          /* length of ssid           */

    unsigned char bssid[6];   /* the access point's MAC   */
    unsigned char essid[256]; /* ascii network identifier */

    unsigned char **uiv_root; /* unique iv root structure */
    /* if wep-encrypted network */

    int wpa_stored;           /* wpa stored in ivs file?   */
    int essid_stored;         /* essid stored in ivs file? */
};

/* linked list of detected clients */

struct ST_info
{
    struct ST_info *prev;    /* the prev client in list   */
    struct ST_info *next;    /* the next client in list   */
    struct AP_info *base;    /* AP this client belongs to */
    unsigned char stmac[6];  /* the client's MAC address  */
    struct WPA_hdsk wpa;     /* WPA handshake data        */
};

/* bunch of global stuff */

struct globals
{
    struct AP_info *ap_1st, *ap_end;
    struct ST_info *st_1st, *st_end;

    unsigned char prev_bssid[6];
    FILE *f_ivs;            /* output ivs file      */
}
G;

static unsigned char ZERO[32] =
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00";

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);

void usage(int what)
{
    char *version_info = getVersion("ivsTools", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
    printf("\n  %s - (C) 2006-2018 Thomas d\'Otreppe\n"
            "  https://www.aircrack-ng.org\n"
            "\n   usage: ", version_info);
    free(version_info);
    if (what == 0 || what == 1)
        printf( "ivstools --convert <pcap file> <ivs output file>\n"
                "        Extract ivs from a pcap file\n");
    if (what == 0)
        printf("       ");
    if (what == 0 || what == 2)
        printf("ivstools --merge <ivs file 1> <ivs file 2> .. <output file>\n"
                "        Merge ivs files\n");
}

int merge( int argc, char *argv[] )
{
    int i, n, unused;
    unsigned long nbw;
    unsigned char buffer[1024];
    FILE *f_in, *f_out;
    struct ivs2_filehdr fivs2;

    if( argc < 5 )
    {
        usage(2);
        return( 1 );
    }

    printf( "Creating %s\n", argv[argc - 1] );

    if( ( f_out = fopen( argv[argc - 1], "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    nbw = 0;

    for( i = 2; i < argc - 1; ++i )
    {
        printf( "Opening %s\n", argv[i] );

        if( ( f_in = fopen( argv[i], "rb" ) ) == NULL )
        {
        	fclose(f_out);
            perror( "fopen failed" );
            return( 1 );
        }

        if( fread( buffer, 1, 4, f_in ) != 4 )
        {
        	fclose(f_out);
        	fclose(f_in);
            perror( "fread file header failed" );
            return( 1 );
        }

        if( memcmp( buffer, IVSONLY_MAGIC, 4 ) == 0 )
        {
        	fclose(f_out);
        	fclose(f_in);
            printf( "%s is an old .ivs file\n", argv[i] );
            return( 1 );
        }

        if( memcmp( buffer, IVS2_MAGIC, 4 ) != 0 )
        {
        	fclose(f_out);
        	fclose(f_in);
            printf( "%s is not an .%s file\n", argv[i], IVS2_EXTENSION );
            return( 1 );
        }

        if( fread( &fivs2, 1, sizeof(struct ivs2_filehdr), f_in ) != (size_t) sizeof(struct ivs2_filehdr) )
        {
        	fclose(f_out);
        	fclose(f_in);
            perror( "fread file header failed" );
            return( 1 );
        }

        if( fivs2.version > IVS2_VERSION )
        {
        	fclose(f_out);
        	fclose(f_in);
            printf( "Error, wrong %s version: %d. Supported up to version %d.\n", IVS2_EXTENSION, fivs2.version, IVS2_VERSION );
            return( 1 );
        }

        if( i == 2 )
        {
            unused = fwrite( buffer, 1, 4, f_out );
            unused = fwrite( &fivs2, 1, sizeof(struct ivs2_filehdr), f_out );
        }

        while( ( n = fread( buffer, 1, 1024, f_in ) ) > 0 )
        {
            nbw += n;
            unused = fwrite( buffer, 1, n, f_out );
            printf( "%lu bytes written\r", nbw );
        }

        fclose( f_in );

        printf( "\n" );
    }

    fclose( f_out );

    return( 0 );
}

int dump_add_packet( unsigned char *h80211, unsigned caplen)
{
    int i, n, seq, dlen, clen;
    unsigned z;
    struct ivs2_pkthdr ivs2;
    unsigned char *p;
    unsigned char bssid[6];
    unsigned char stmac[6];
    unsigned char clear[2048];
    int weight[16];
    int num_xor, o;

    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct AP_info *ap_prv = NULL;
    struct ST_info *st_prv = NULL;

    /* skip packets smaller than a 802.11 header */

    if( caplen < 24 )
        return FAILURE;

    /* skip (uninteresting) control frames */

    if( ( h80211[0] & 0x0C ) == 0x04 )
        return FAILURE;

    /* grab the sequence number */
    seq = ((h80211[22]>>4)+(h80211[23]<<4));

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;
        default: memcpy( bssid, h80211 + 10, 6 ); break;
    }

    /* update our chained list of access points */

    ap_cur = G.ap_1st;
    ap_prv = NULL;

    while( ap_cur != NULL )
    {
        if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
            break;

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    /* if it's a new access point, add it */

    if( ap_cur == NULL )
    {
        if( ! ( ap_cur = (struct AP_info *) malloc(
                sizeof( struct AP_info ) ) ) )
        {
            perror( "malloc failed" );
            return FAILURE;
        }

        memset( ap_cur, 0, sizeof( struct AP_info ) );

        if( G.ap_1st == NULL )
            G.ap_1st = ap_cur;
        else
            ap_prv->next  = ap_cur;

        memcpy( ap_cur->bssid, bssid, 6 );

        ap_cur->prev = ap_prv;

        ap_cur->uiv_root = uniqueiv_init();

        G.ap_end = ap_cur;

        ap_cur->ssid_length = 0;
        ap_cur->wpa_stored   = 0;
        ap_cur->essid_stored = 0;
    }

    /* find wpa handshake */
    if( h80211[0] == 0x10 )
    {
        /* reset the WPA handshake state */

        if( st_cur != NULL && st_cur->wpa.state != 0xFF )
            st_cur->wpa.state = 0;
//        printf("initial auth %d\n", ap_cur->wpa_state);
    }

    /* locate the station MAC in the 802.11 header */

    switch( h80211[1] & 3 )
    {
        case  0:

            /* if management, check that SA != BSSID */

            if( memcmp( h80211 + 10, bssid, 6 ) == 0 )
                goto skip_station;

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  1:

            /* ToDS packet, must come from a client */

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  2:

            /* FromDS packet, reject broadcast MACs */

            if( h80211[4] != 0 ) goto skip_station;
            memcpy( stmac, h80211 +  4, 6 ); break;

            default: goto skip_station;
    }

    /* update our chained list of wireless stations */

    st_cur = G.st_1st;
    st_prv = NULL;

    while( st_cur != NULL )
    {
        if( ! memcmp( st_cur->stmac, stmac, 6 ) )
            break;

        st_prv = st_cur;
        st_cur = st_cur->next;
    }

    /* if it's a new client, add it */

    if( st_cur == NULL )
    {
        if( ! ( st_cur = (struct ST_info *) malloc(
                sizeof( struct ST_info ) ) ) )
        {
            perror( "malloc failed" );
            return FAILURE;
        }

        memset( st_cur, 0, sizeof( struct ST_info ) );

        if( G.st_1st == NULL )
            G.st_1st = st_cur;
        else
            st_prv->next  = st_cur;

        memcpy( st_cur->stmac, stmac, 6 );

        st_cur->prev = st_prv;

        G.st_end = st_cur;
    }

    if( st_cur->base == NULL ||
        memcmp( ap_cur->bssid, BROADCAST, 6 ) != 0 )
        st_cur->base = ap_cur;

skip_station:

        /* packet parsing: Beacon or Probe Response */

        if( h80211[0] == 0x80 || h80211[0] == 0x50 )
        {
            p = h80211 + 36;

            while( p < h80211 + caplen )
            {
                if( p + 2 + p[1] > h80211 + caplen )
                    break;

                if( p[0] == 0x00 ) ap_cur->ssid_length = p[1];

                if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                    ( p[1] > 1 || p[2] != ' ' ) )
                {
                    /* found a non-cloaked ESSID */

//                n = ( p[1] > 32 ) ? 32 : p[1];
                    n = p[1];

                    memset( ap_cur->essid, 0, 256 );
                    memcpy( ap_cur->essid, p + 2, n );

                    if( G.f_ivs != NULL && !ap_cur->essid_stored )
                    {
                        memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                        ivs2.flags |= IVS2_ESSID;
                        ivs2.len += ap_cur->ssid_length;

                        if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                        {
                            ivs2.flags |= IVS2_BSSID;
                            ivs2.len += 6;
                            memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                        }

                        /* write header */
                        if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                            != (size_t) sizeof(struct ivs2_pkthdr) )
                        {
                            perror( "fwrite(IV header) failed" );
                            return( 1 );
                        }

                        /* write BSSID */
                        if(ivs2.flags & IVS2_BSSID)
                        {
                            if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs )
                                != (size_t) 6 )
                            {
                                perror( "fwrite(IV bssid) failed" );
                                return( 1 );
                            }
                        }

                        /* write essid */
                        if( fwrite( ap_cur->essid, 1, ap_cur->ssid_length, G.f_ivs )
                            != (size_t) ap_cur->ssid_length )
                        {
                            perror( "fwrite(IV essid) failed" );
                            return( 1 );
                        }

                        ap_cur->essid_stored = 1;
                        return ESSID;
                    }

                    for( i = 0; i < n; i++ )
                        if( ( ap_cur->essid[i] >   0 && ap_cur->essid[i] <  32 ) ||
                              ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                            ap_cur->essid[i] = '.';
                }

                p += 2 + p[1];
            }
        }

        /* packet parsing: Association Request */

        if( h80211[0] == 0x00 && caplen > 28 )
        {
            p = h80211 + 28;

            while( p < h80211 + caplen )
            {
                if( p + 2 + p[1] > h80211 + caplen )
                    break;

                if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                    ( p[1] > 1 || p[2] != ' ' ) )
                {
                    /* found a non-cloaked ESSID */

                    n = ( p[1] > 32 ) ? 32 : p[1];

                    memset( ap_cur->essid, 0, 33 );
                    memcpy( ap_cur->essid, p + 2, n );

                    if( G.f_ivs != NULL && !ap_cur->essid_stored )
                    {
                        memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                        ivs2.flags |= IVS2_ESSID;
                        ivs2.len += ap_cur->ssid_length;

                        if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                        {
                            ivs2.flags |= IVS2_BSSID;
                            ivs2.len += 6;
                            memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                        }

                        /* write header */
                        if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                            != (size_t) sizeof(struct ivs2_pkthdr) )
                        {
                            perror( "fwrite(IV header) failed" );
                            return( 1 );
                        }

                        /* write BSSID */
                        if(ivs2.flags & IVS2_BSSID)
                        {
                            if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs )
                                != (size_t) 6 )
                            {
                                perror( "fwrite(IV bssid) failed" );
                                return( 1 );
                            }
                        }

                        /* write essid */
                        if( fwrite( ap_cur->essid, 1, ap_cur->ssid_length, G.f_ivs )
                            != (size_t) ap_cur->ssid_length )
                        {
                            perror( "fwrite(IV essid) failed" );
                            return( 1 );
                        }

                        ap_cur->essid_stored = 1;
                        return ESSID;
                    }

                    for( i = 0; i < n; i++ )
                        if( ap_cur->essid[i] < 32 ||
                            ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                            ap_cur->essid[i] = '.';
                }

                p += 2 + p[1];
            }
        }

        /* packet parsing: some data */

        if( ( h80211[0] & 0x0C ) == 0x08 )
        {
            /* check the SNAP header to see if data is encrypted */

            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

            if( z + 26 > caplen )
                return FAILURE;

            if( z + 10 > caplen )
                return FAILURE;

             //check if WEP bit set and extended iv
            if( (h80211[1] & 0x40) != 0 && (h80211[z+3] & 0x20) == 0  )
            {
                /* WEP: check if we've already seen this IV */

                if( ! uniqueiv_check( ap_cur->uiv_root, &h80211[z] ) )
                {
                    /* first time seen IVs */

                    if( G.f_ivs != NULL )
                    {
                        memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                        ivs2.flags = 0;
                        ivs2.len = 0;

                        dlen = caplen -24 -4 -4; //original data len
                        if(dlen > 2048) dlen = 2048;
                        //get cleartext + len + 4(iv+idx)
                        num_xor = known_clear(clear, &clen, weight, h80211, dlen);
                        if(num_xor == 1)
                        {
                            ivs2.flags |= IVS2_XOR;
                            ivs2.len += clen + 4;
                            /* reveal keystream (plain^encrypted) */
                            for(n=0; n<(ivs2.len-4); n++)
                            {
                                clear[n] = (clear[n] ^ h80211[z+4+n]) & 0xFF;
                            }
                            //clear is now the keystream
                        }
                        else
                        {
                            //do it again to get it 2 bytes higher
                            num_xor = known_clear(clear+2, &clen, weight, h80211, dlen);
                            ivs2.flags |= IVS2_PTW;
                            //len = 4(iv+idx) + 1(num of keystreams) + 1(len per keystream) + 32*num_xor + 16*sizeof(int)(weight[16])
                            ivs2.len += 4 + 1 + 1 + 32*num_xor + 16*sizeof(int);
                            clear[0] = num_xor;
                            clear[1] = clen;
                            /* reveal keystream (plain^encrypted) */
                            for(o=0; o<num_xor; o++)
                            {
                                for(n=0; n<(ivs2.len-4); n++)
                                {
                                    clear[2+n+o*32] = (clear[2+n+o*32] ^ h80211[z+4+n]) & 0xFF;
                                }
                            }
                            memcpy(clear+4 + 1 + 1 + 32*num_xor, weight, 16*sizeof(int));
                            //clear is now the keystream
                        }

                        if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                        {
                            ivs2.flags |= IVS2_BSSID;
                            ivs2.len += 6;
                            memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                        }

                        if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                            != (size_t) sizeof(struct ivs2_pkthdr) )
                        {
                            perror( "fwrite(IV header) failed" );
                            return( 1 );
                        }

                        if( ivs2.flags & IVS2_BSSID )
                        {
                            if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs ) != (size_t) 6 )
                            {
                                perror( "fwrite(IV bssid) failed" );
                                return( 1 );
                            }
                            ivs2.len -= 6;
                        }

                        if( fwrite( h80211+z, 1, 4, G.f_ivs ) != (size_t) 4 )
                        {
                            perror( "fwrite(IV iv+idx) failed" );
                            return( 1 );
                        }
                        ivs2.len -= 4;

                        if( fwrite( clear, 1, ivs2.len, G.f_ivs ) != (size_t) ivs2.len )
                        {
                            perror( "fwrite(IV keystream) failed" );
                            return( 1 );
                        }
                    }

                    uniqueiv_mark( ap_cur->uiv_root, &h80211[z] );
                    return IVS;
                }
            }

            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

            if( z + 26 > caplen )
                return FAILURE;

            z += 6;     //skip LLC header

            /* check ethertype == EAPOL */
            if( h80211[z] == 0x88 && h80211[z + 1] == 0x8E && (h80211[1] & 0x40) != 0x40 )
            {
                z += 2;     //skip ethertype

                if( st_cur == NULL )
                    return FAILURE;

                /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

                if( ( h80211[z + 6] & 0x08 ) != 0 &&
                      ( h80211[z + 6] & 0x40 ) == 0 &&
                      ( h80211[z + 6] & 0x80 ) != 0 &&
                      ( h80211[z + 5] & 0x01 ) == 0 )
                {
                    memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state = 1;
                }


                /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

                if( z+17+32 > caplen )
                    return FAILURE;

                if( ( h80211[z + 6] & 0x08 ) != 0 &&
                      ( h80211[z + 6] & 0x40 ) == 0 &&
                      ( h80211[z + 6] & 0x80 ) == 0 &&
                      ( h80211[z + 5] & 0x01 ) != 0 )
                {
                    if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                    {
                        memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );
                        st_cur->wpa.state |= 2;

                    }
                }

                /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

                if( ( h80211[z + 6] & 0x08 ) != 0 &&
                      ( h80211[z + 6] & 0x40 ) != 0 &&
                      ( h80211[z + 6] & 0x80 ) != 0 &&
                      ( h80211[z + 5] & 0x01 ) != 0 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                            +   h80211[z + 3] + 4;

                    if (st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol_size) ||
                        caplen - z < st_cur->wpa.eapol_size) {
                        // ignore packet trying to crash us
                        st_cur->wpa.eapol_size = 0;
                        return 0;
                    }

                    if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                    {
                        memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                        st_cur->wpa.state |= 4;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 8;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;

                    if( st_cur->wpa.state == 15)
                    {
                        memcpy( st_cur->wpa.stmac, st_cur->stmac, 6 );

                        if( G.f_ivs != NULL )
                        {
                            memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                            ivs2.flags = 0;
                            ivs2.len = 0;

                            ivs2.len= sizeof(struct WPA_hdsk);
                            ivs2.flags |= IVS2_WPA;

                            if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                            {
                                ivs2.flags |= IVS2_BSSID;
                                ivs2.len += 6;
                                memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                            }

                            if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                                != (size_t) sizeof(struct ivs2_pkthdr) )
                            {
                                perror( "fwrite(IV header) failed" );
                                return( 1 );
                            }

                            if( ivs2.flags & IVS2_BSSID )
                            {
                                if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs ) != (size_t) 6 )
                                {
                                    perror( "fwrite(IV bssid) failed" );
                                    return( 1 );
                                }
                                ivs2.len -= 6;
                            }

                            if( fwrite( &(st_cur->wpa), 1, sizeof(struct WPA_hdsk), G.f_ivs ) != (size_t) sizeof(struct WPA_hdsk) )
                            {
                                perror( "fwrite(IV wpa_hdsk) failed" );
                                return( 1 );
                            }
                            return WPA;
                        }
                    }
                }
            }
        }

        return( 0 );
}

int main( int argc, char *argv[] )
{
    time_t tt;
    int n, unused, ret;
    FILE *f_in;
    unsigned long nbr;
    unsigned long nbivs;
    unsigned char *h80211;
    unsigned char bssid_cur[6];
    unsigned char bssid_prv[6];
    unsigned char buffer[65536];
    struct pcap_file_header pfh;
    struct pcap_pkthdr pkh;
    struct ivs2_filehdr fivs2;

    if( argc < 4 )
    {
        usage(0);
        return( 1 );
    }

    if (strcmp(argv[1],"--merge")==0) {
        return merge(argc,argv);
    }
    if (strcmp(argv[1],"--convert")) {
        usage(1);
        return( 1 );
    }

    memset( bssid_cur, 0, 6 );
    memset( bssid_prv, 0, 6 );

    /* check the input pcap file */

    printf( "Opening %s\n", argv[2] );

    if( ( f_in = fopen( argv[2], "rb" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    n = sizeof( pfh );

    if( fread( &pfh, 1, n, f_in ) != (size_t) n )
    {
        perror( "fread(pcap file header) failed" );
        fclose( f_in );
        return( 1 );
    }

    if( pfh.magic != TCPDUMP_MAGIC &&
        pfh.magic != TCPDUMP_CIGAM )
    {
        printf( "\"%s\" isn't a pcap file (expected "
                "TCPDUMP_MAGIC).\n", argv[2] );
        fclose( f_in );
        return( 1 );
    }

    if( pfh.magic == TCPDUMP_CIGAM )
        SWAP32( pfh.linktype );

    if( pfh.linktype != LINKTYPE_IEEE802_11 &&
        pfh.linktype != LINKTYPE_PRISM_HEADER &&
        pfh.linktype != LINKTYPE_RADIOTAP_HDR &&
		pfh.linktype != LINKTYPE_PPI_HDR )
    {
        printf( "\"%s\" isn't a regular 802.11 "
                "(wireless) capture.\n", argv[2] );
        fclose( f_in );
        return( 1 );
    }

    /* create the output ivs file */

    printf( "Creating %s\n", argv[3] );

    if( ( G.f_ivs = fopen( argv[3], "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        fclose( f_in );
        return( 1 );
    }

    fivs2.version = IVS2_VERSION;

    unused = fwrite( IVS2_MAGIC, 4, 1, G.f_ivs );
    unused = fwrite( &fivs2, sizeof(struct ivs2_filehdr), 1, G.f_ivs );

    nbr = 0;
    tt = time( NULL ) - 1;

    nbivs = 0;

    while( 1 )
    {
        if( time( NULL ) - tt > 0 )
        {
            printf( "\33[KRead %lu packets...\r", nbr );
            fflush( stdout );
            tt = time( NULL );
        }

        /* read one packet */

        n = sizeof( pkh );

        if( fread( &pkh, 1, n, f_in ) != (size_t) n )
            break;

        if( pfh.magic == TCPDUMP_CIGAM ) {
            SWAP32( pkh.caplen );
            SWAP32( pkh.len );
        }

        n = pkh.caplen;

        if( n <= 0 || n > 65535 )
        {
            printf( "Corrupted file? Invalid packet length: %d.\n", n );
            return( 1 );
        }

        if( fread( buffer, 1, n, f_in ) != (size_t) n )
            break;

        ++nbr;

        h80211 = buffer;

        /* remove any prism/radiotap header */

        if( pfh.linktype == LINKTYPE_PRISM_HEADER )
        {
            if( h80211[7] == 0x40 )
                n = 64;
            else
            {
                n = *(int *)( h80211 + 4 );

                if( pfh.magic == TCPDUMP_CIGAM )
                    SWAP32( n );
            }

            if( n < 8 || n >= (int) pkh.caplen )
                continue;

            h80211 += n; pkh.caplen -= n;
        }

        if( pfh.linktype == LINKTYPE_RADIOTAP_HDR )
        {
            n = *(unsigned short *)( h80211 + 2 );

            if( n <= 0 || n >= (int) pkh.caplen )
                continue;

            h80211 += n; pkh.caplen -= n;
        }

		if( pfh.linktype == LINKTYPE_PPI_HDR )
		{
			/* Remove the PPI header */

			n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

			if( n <= 0 || n>= (int) pkh.caplen )
				continue;

			/* for a while Kismet logged broken PPI headers */
			if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
				n = 32;

			if( n <= 0 || n>= (int) pkh.caplen )
				continue;

			h80211 += n; pkh.caplen -= n;
		}

        ret = dump_add_packet(h80211, pkh.caplen);

        if(ret == IVS) ++nbivs;
    }
    fclose( f_in );
    fclose( G.f_ivs );

    printf( "\33[2KRead %lu packets.\n", nbr );

    if ( nbivs > 0 )
        printf( "Written %lu IVs.\n", nbivs);
    else
    {
        remove ( argv[3] );
        puts("No IVs written");
    }

    return( 0 );
}
