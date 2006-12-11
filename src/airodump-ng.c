/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006 Thomas d'Otreppe
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#ifdef linux
    int linux_acpi;
    int linux_apm;
    #include <dirent.h>
#endif

#include "version.h"
#include "pcap.h"
#include "uniqueiv.c"

/* some constants */

#define FORMAT_CAP 1
#define FORMAT_IVS 2

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#define REFRESH_RATE 100000  /* delay in us between updates */

#define BROADCAST_ADDR "\xFF\xFF\xFF\xFF\xFF\xFF"

#define NB_PWR  5       /* size of signal power ring buffer */
#define NB_PRB 10       /* size of probed ESSID ring buffer */

extern char * getVersion(char * progname, int maj, int min, int submin, int betavers);
extern int is_ndiswrapper(const char * iface, const char * path);
extern char * wiToolsPath(const char * tool);

const unsigned char llcnull[4] = {0, 0, 0, 0};
char *f_ext[4] = { "txt", "gps", "cap", "ivs" };

int abg_chans [] =
{
    1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12,
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
    112, 116, 120, 124, 128, 132, 136, 140, 149,
    153, 157, 161, 184, 188, 192, 196, 200, 204,
    208, 212, 216,0
};

int bg_chans  [] =
{
    1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0
};

int a_chans   [] =
{
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
    112, 116, 120, 124, 128, 132, 136, 140, 149,
    153, 157, 161, 184, 188, 192, 196, 200, 204,
    208, 212, 216,0
};

/* linked list of detected access points */

struct AP_info
{
    struct AP_info *prev;     /* prev. AP in list         */
    struct AP_info *next;     /* next  AP in list         */

    time_t tinit, tlast;      /* first and last time seen */

    int channel;              /* AP radio channel         */
    int max_speed;            /* AP maximum speed in Mb/s */
    int avg_power;            /* averaged signal power    */
    int power_index;          /* index in power ring buf. */
    int power_lvl[NB_PWR];    /* signal power ring buffer */
    int preamble;             /* 0 = long, 1 = short      */
    int encryption;           /* 0 = none, > 1 = WEP/WPA  */
	int beacon_logged;        /* We need 1 beacon per AP  */

    unsigned long nb_bcn;     /* total number of beacons  */
    unsigned long nb_pkt;     /* total number of packets  */
    unsigned long nb_data;    /* number of  data packets  */

    unsigned char bssid[6];   /* the access point's MAC   */
    unsigned char essid[36];  /* ascii network identifier */

    unsigned char lanip[4];   /* last detected ip address */
                              /* if non-encrypted network */

    unsigned char **uiv_root; /* unique iv root structure */
                              /* if wep-encrypted network */
};

/* linked list of detected clients */

struct ST_info
{
    struct ST_info *prev;    /* the prev client in list   */
    struct ST_info *next;    /* the next client in list   */
    struct AP_info *base;    /* AP this client belongs to */
    time_t tinit, tlast;     /* first and last time seen  */
    unsigned long nb_pkt;    /* total number of packets   */
    unsigned char stmac[6];  /* the client's MAC address  */
    int probe_index;         /* probed ESSIDs ring index  */
    char probes[NB_PRB][36]; /* probed ESSIDs ring buffer */
    int power;               /* last signal power         */
};

/* bunch of global stuff */

struct globals
{
    struct AP_info *ap_1st, *ap_end;
    struct ST_info *st_1st, *st_end;

    unsigned char prev_bssid[6];

    int f_index;            /* outfiles index       */
    FILE *f_txt;            /* output csv file      */
    FILE *f_gps;            /* output gps file      */
    FILE *f_cap;            /* output cap file      */
    FILE *f_ivs;            /* output ivs file      */

    char * batt;            /* Battery string       */
    int channel;            /* current channel #    */
    int ch_pipe[2];         /* current channel pipe */
    int gc_pipe[2];         /* gps coordinates pipe */
    float gps_loc[5];       /* gps coordinates      */
    int save_gps;           /* keep gps file flag   */
    int usegpsd;            /* do we use GPSd?      */
    int * channels;

    int is_wlanng;          /* set if wlan-ng       */
    int is_orinoco;         /* set if orinoco       */
    int is_madwifing;       /* set if madwifi-ng    */
    int do_exit;            /* interrupt flag       */
    struct winsize ws;      /* console window size  */

    char * elapsed_time;	/* capture time			*/

    int one_beacon;         /* Record only 1 beacon?*/

    int record_data;		/* do we record data?   */

    char * iwpriv;
    char * wlanctlng;
    char * wl;
}
G;


char usage[] =

"\n"
"  %s - (C) 2006 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: airodump-ng <options> <interface>\n"
"\n"
"  Options:\n"
"      --ivs               : Save only captured IVs\n"
"      --gpsd              : Use GPSd\n"
"      --write    <prefix> : Dump file prefix\n"
"      -w                  : same as --write \n"
"      --beacons           : Record all beacons in dump file\n"
"\n"
"  By default, airodump-ng hop on 2.4Ghz channels.\n"
"  You can make it capture on other/specific channel(s) by using:\n"
"      --channel <channel> : Capture on a specific channel\n"
"      --band <abg>        : Band on which airodump-ng should hop\n"
"\n";


/* setup the output files */

int dump_initialize( char *prefix, int ivs_only )
{
    int i;
    FILE *f;
    char ofn[1024];


	/* If you only want to see what happening, send all data to /dev/null */

	if ( prefix == NULL) {
		return( 0 );
	}

    /* check not to overflow the ofn buffer */

    if( strlen( prefix ) >= sizeof( ofn ) - 10 )
        prefix[sizeof( ofn ) - 10] = '\0';

    /* make sure not to overwrite any existing file */

    memset( ofn, 0, sizeof( ofn ) );

    G.f_index = 1;

    do
    {
        for( i = 0; i < 4; i++ )
        {
            snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.%s",
                      prefix, G.f_index, f_ext[i] );

            if( ( f = fopen( ofn, "rb+" ) ) != NULL )
            {
                fclose( f );
                G.f_index++;
                break;
            }
        }
    }
    while( i < 4 );

    /* create the output CSV & GPS files */

    snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.txt",
              prefix, G.f_index );

    if( ( G.f_txt = fopen( ofn, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        fprintf( stderr, "Could not create \"%s\".\n", ofn );
        return( 1 );
    }

    if (G.usegpsd)
    {
        snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.gps",
                  prefix, G.f_index );

        if( ( G.f_gps = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            return( 1 );
        }
    }
    /* create the output packet capture file */

    if( ivs_only == 0 )
    {
        struct pcap_file_header pfh;

        snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.cap",
                  prefix, G.f_index );

        if( ( G.f_cap = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            return( 1 );
        }

        pfh.magic           = TCPDUMP_MAGIC;
        pfh.version_major   = PCAP_VERSION_MAJOR;
        pfh.version_minor   = PCAP_VERSION_MINOR;
        pfh.thiszone        = 0;
        pfh.sigfigs         = 0;
        pfh.snaplen         = 65535;
        pfh.linktype        = LINKTYPE_IEEE802_11;

        if( fwrite( &pfh, 1, sizeof( pfh ), G.f_cap ) !=
                    (size_t) sizeof( pfh ) )
        {
            perror( "fwrite(pcap file header) failed" );
            return( 1 );
        }
    } else {

        snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.ivs",
                  prefix, G.f_index );

        if( ( G.f_ivs = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            return( 1 );
        }

        if( fwrite( IVSONLY_MAGIC, 1, 4, G.f_ivs ) != (size_t) 4 )
        {
            perror( "fwrite(IVs file header) failed" );
            return( 1 );
        }
    }

    return( 0 );
}

int dump_add_packet( unsigned char *h80211, int caplen, int power )
{
    int i, n, z;
    struct pcap_pkthdr pkh;
    struct timeval tv;
    unsigned char *p, c;
    unsigned char bssid[6];
    unsigned char stmac[6];

    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct AP_info *ap_prv = NULL;
    struct ST_info *st_prv = NULL;

    /* skip packets smaller than a 802.11 header */

    if( caplen < 24 )
        goto write_packet;

    /* skip (uninteresting) control frames */

    if( ( h80211[0] & 0x0C ) == 0x04 )
        goto write_packet;

	/* if it's a LLC null packet, just forget it (may change in the future) */

	if ( caplen > 28)
		if ( memcmp(h80211 + 24, llcnull, 4) == 0)
			return ( 0 );

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;
        default: memcpy( bssid, h80211 +  4, 6 ); break;
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
            return( 1 );
        }

        memset( ap_cur, 0, sizeof( struct AP_info ) );

        if( G.ap_1st == NULL )
            G.ap_1st = ap_cur;
        else
            ap_prv->next  = ap_cur;

        memcpy( ap_cur->bssid, bssid, 6 );

        ap_cur->prev = ap_prv;

        ap_cur->tinit = time( NULL );
        ap_cur->tlast = time( NULL );

        ap_cur->avg_power   = -1;
        ap_cur->power_index = -1;

        for( i = 0; i < NB_PWR; i++ )
            ap_cur->power_lvl[i] = -1;

        ap_cur->channel    = -1;
        ap_cur->max_speed  = -1;
        ap_cur->encryption = -1;

        ap_cur->uiv_root = uniqueiv_init();

        G.ap_end = ap_cur;
    }

    /* update the last time seen */

    ap_cur->tlast = time( NULL );

    /* only update power if packets comes from
     * the AP: either type == mgmt and SA != BSSID,
     * or FromDS == 1 and ToDS == 0 */

    if( ( ( h80211[1] & 3 ) == 0 &&
            memcmp( h80211 + 10, bssid, 6 ) == 0 ) ||
        ( ( h80211[1] & 3 ) == 2 ) )
    {
        ap_cur->power_index = ( ap_cur->power_index + 1 ) % NB_PWR;
        ap_cur->power_lvl[ap_cur->power_index] = power;

        ap_cur->avg_power = 0;

        for( i = 0, n = 0; i < NB_PWR; i++ )
        {
            if( ap_cur->power_lvl[i] != -1 )
            {
                ap_cur->avg_power += ap_cur->power_lvl[i];
                n++;
            }
        }

        if( n > 0 )
            ap_cur->avg_power /= n;
        else
            ap_cur->avg_power = -1;
    }

    if( h80211[0] == 0x80 )
        ap_cur->nb_bcn++;

    ap_cur->nb_pkt++;


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
            return( 1 );
        }

        memset( st_cur, 0, sizeof( struct ST_info ) );

        if( G.st_1st == NULL )
            G.st_1st = st_cur;
        else
            st_prv->next  = st_cur;

        memcpy( st_cur->stmac, stmac, 6 );

        st_cur->prev = st_prv;

        st_cur->tinit = time( NULL );
        st_cur->tlast = time( NULL );

        st_cur->power = -1;

        st_cur->probe_index = -1;

        for( i = 0; i < NB_PRB; i++ )
            memset( st_cur->probes[i], 0, sizeof(
                    st_cur->probes[i] ) );

        G.st_end = st_cur;
    }

    if( st_cur->base == NULL ||
        memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) != 0 )
        st_cur->base = ap_cur;

    /* update the last time seen */

    st_cur->tlast = time( NULL );

    /* only update power if packets comes from the
     * client: either type == Mgmt and SA != BSSID,
     * or FromDS == 0 and ToDS == 1 */

    if( ( ( h80211[1] & 3 ) == 0 &&
            memcmp( h80211 + 10, bssid, 6 ) != 0 ) ||
        ( ( h80211[1] & 3 ) == 1 ) )
    {
        st_cur->power = power;
    }

    st_cur->nb_pkt++;

skip_station:

    /* packet parsing: Probe Request */

    if( h80211[0] == 0x40 && st_cur != NULL )
    {
        p = h80211 + 24;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                n = ( p[1] > 32 ) ? 32 : p[1];

                for( i = 0; i < n; i++ )
                    if( p[2 + i] > 0 && p[2 + i] < ' ' )
                        goto skip_probe;

                /* got a valid ASCII probed ESSID, check if it's
                   already in the ring buffer */

                for( i = 0; i < NB_PRB; i++ )
                    if( memcmp( st_cur->probes[i], p + 2, n ) == 0 )
                        goto skip_probe;

                st_cur->probe_index = ( st_cur->probe_index + 1 ) % NB_PRB;
                memset( st_cur->probes[st_cur->probe_index], 0, 36 );
                memcpy( st_cur->probes[st_cur->probe_index], p + 2, n );

                for( i = 0; i < n; i++ )
                {
                    c = p[2 + i];
                    if( c == 0 || ( c > 126 && c < 160 ) ) c = '.';
                    st_cur->probes[st_cur->probe_index][i] = c;
                }
            }

            p += 2 + p[1];
        }
    }

skip_probe:

    /* packet parsing: Beacon or Probe Response */

    if( h80211[0] == 0x80 || h80211[0] == 0x50 )
    {
        if( ap_cur->encryption < 0 )
            ap_cur->encryption = ( h80211[34] & 0x10 ) >> 4;

        ap_cur->preamble = ( h80211[34] & 0x20 ) >> 5;

        p = h80211 + 36;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

                n = ( p[1] > 32 ) ? 32 : p[1];

                memset( ap_cur->essid, 0, 36 );
                memcpy( ap_cur->essid, p + 2, n );

                for( i = 0; i < n; i++ )
                    if( ( ap_cur->essid[i] >   0 && ap_cur->essid[i] <  32 ) ||
                        ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            /* get the maximum speed in Mb and the AP's channel */

            if( p[0] == 0x01 || p[0] == 0x32 )
                ap_cur->max_speed = ( p[1 + p[1]] & 0x7F ) / 2;

            if( p[0] == 0x03 )
                ap_cur->channel = p[2];

            p += 2 + p[1];
        }
    }

    /* packet parsing: Association Request */

    if( h80211[0] == 0x00 )
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
        /* update the channel if we didn't get any beacon */

        if( ap_cur->channel == -1 )
            ap_cur->channel = G.channel;

        /* check the SNAP header to see if data is encrypted */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        if( z + 26 > caplen )
            goto write_packet;

        if( h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03 )
        {
            if( ap_cur->encryption < 0 )
                ap_cur->encryption = 0;

            /* if ethertype == IPv4, find the LAN address */

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00 &&
                ( h80211[1] & 3 ) == 0x01 )
                    memcpy( ap_cur->lanip, &h80211[z + 20], 4 );

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06 )
                memcpy( ap_cur->lanip, &h80211[z + 22], 4 );
        }
        else
            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5 );

        if( z + 10 > caplen )
            goto write_packet;

        if( ap_cur->encryption == 2 )
        {
            /* WEP: check if we've already seen this IV */

            if( ! uniqueiv_check( ap_cur->uiv_root, &h80211[z] ) )
            {
                /* first time seen IVs */

                if( G.f_ivs != NULL )
                {
                    unsigned char iv_info[64];

                    if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) == 0 )
                    {
                        iv_info[0] = 0xFF;
                        memcpy( iv_info + 1, &h80211[z    ], 3 );
                        memcpy( iv_info + 4, &h80211[z + 4], 2 );
                        n =  6;
                    }
                    else
                    {
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                        memcpy( iv_info     , ap_cur->bssid,  6 );
                        memcpy( iv_info + 6 , &h80211[z    ], 3 );
                        memcpy( iv_info + 9 , &h80211[z + 4], 2 );
                        n = 11;
                    }

                    if( fwrite( iv_info, 1, n, G.f_ivs ) != (size_t) n )
                    {
                        perror( "fwrite(IV info) failed" );
                        return( 1 );
                    }
                }

                uniqueiv_mark( ap_cur->uiv_root, &h80211[z] );

                ap_cur->nb_data++;
            }
        }
        else
            ap_cur->nb_data++;
    }

write_packet:

    if( h80211[0] == 0x80 && G.one_beacon){
        if( !ap_cur->beacon_logged )
            ap_cur->beacon_logged = 1;
        else return ( 0 );
    }

    if( G.f_cap != NULL )
    {
        pkh.caplen = pkh.len = caplen;

        gettimeofday( &tv, NULL );

        pkh.tv_sec  =   tv.tv_sec;
        pkh.tv_usec = ( tv.tv_usec & ~0x1ff ) + power + 64;

        n = sizeof( pkh );

        if( fwrite( &pkh, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet header) failed" );
            return( 1 );
        }

        fflush( stdout );

        n = pkh.caplen;

        if( fwrite( h80211, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet data) failed" );
            return( 1 );
        }

        fflush( stdout );
    }

    return( 0 );
}

void dump_sort_power( void )
{
    time_t tt = time( NULL );

    /* thanks to Arnaud Cornet :-) */

    struct AP_info *new_ap_1st = NULL;
    struct AP_info *new_ap_end = NULL;

    struct ST_info *new_st_1st = NULL;
    struct ST_info *new_st_end = NULL;

    struct ST_info *st_cur, *st_min;
    struct AP_info *ap_cur, *ap_min;

    /* sort the aps by power first */

    while( G.ap_1st )
    {
        ap_min = NULL;
        ap_cur = G.ap_1st;

        while( ap_cur != NULL )
        {
            if( tt - ap_cur->tlast > 20 )
                ap_min = ap_cur;

            ap_cur = ap_cur->next;
        }

        if( ap_min == NULL )
        {
            ap_min = ap_cur = G.ap_1st;

            while( ap_cur != NULL )
            {
                if( ap_cur->avg_power < ap_min->avg_power)
                    ap_min = ap_cur;

                ap_cur = ap_cur->next;
            }
        }

        if( ap_min == G.ap_1st )
            G.ap_1st = ap_min->next;

        if( ap_min == G.ap_end )
            G.ap_end = ap_min->prev;

        if( ap_min->next )
            ap_min->next->prev = ap_min->prev;

        if( ap_min->prev )
            ap_min->prev->next = ap_min->next;

        if( new_ap_end )
        {
            new_ap_end->next = ap_min;
            ap_min->prev = new_ap_end;
            new_ap_end = ap_min;
            new_ap_end->next = NULL;
        }
        else
        {
            new_ap_1st = new_ap_end = ap_min;
            ap_min->next = ap_min->prev = NULL;
        }
    }

    G.ap_1st = new_ap_1st;
    G.ap_end = new_ap_end;

    /* now sort the stations */

    while( G.st_1st )
    {
        st_min = NULL;
        st_cur = G.st_1st;

        while( st_cur != NULL )
        {
            if( tt - st_cur->tlast > 60 )
                st_min = st_cur;

            st_cur = st_cur->next;
        }

        if( st_min == NULL )
        {
            st_min = st_cur = G.st_1st;

            while( st_cur != NULL )
            {
                if( st_cur->power < st_min->power)
                    st_min = st_cur;

                st_cur = st_cur->next;
            }
        }

        if( st_min == G.st_1st )
            G.st_1st = st_min->next;

        if( st_min == G.st_end )
            G.st_end = st_min->prev;

        if( st_min->next )
            st_min->next->prev = st_min->prev;

        if( st_min->prev )
            st_min->prev->next = st_min->next;

        if( new_st_end )
        {
            new_st_end->next = st_min;
            st_min->prev = new_st_end;
            new_st_end = st_min;
            new_st_end->next = NULL;
        }
        else
        {
            new_st_1st = new_st_end = st_min;
            st_min->next = st_min->prev = NULL;
        }
    }

    G.st_1st = new_st_1st;
    G.st_end = new_st_end;
}

int getBatteryState()
{
#ifdef linux
    char buf[128];
    int batteryTime = 0;
    FILE *apm;
    int flag;
    char units[32];

    if (linux_apm == 1)
    {
        if ((apm = fopen("/proc/apm", "r")) != NULL ) {
        	if ( fgets(buf, 128,apm) != NULL ) {
				int charging, ac;
				fclose(apm);

				sscanf(buf, "%*s %*d.%*d %*x %x %x %x %*d%% %d %s\n", &ac,
					&charging, &flag, &batteryTime, units);

				if ((flag & 0x80) == 0 && charging != 0xFF && ac != 1 && batteryTime != -1) {
					if (!strncmp(units, "min", 32))
						batteryTime *= 60;
				}
				else return 0;
				linux_acpi = 0;
				return batteryTime;
            }
        }
        linux_apm = 0;
    }
    if (linux_acpi && !linux_apm)
    {
        DIR *batteries, *ac_adapters;
        struct dirent *this_battery, *this_adapter;
        FILE *acpi, *info;
        char battery_state[128];
        char battery_info[128];
        int rate = 1, remain = 0, current = 0;
        static int total_remain = 0, total_cap = 0;
        int batno = 0;
        static int info_timer = 0;
        int batt_full_capacity[3];
        linux_apm=0;
        linux_acpi=1;
        ac_adapters = opendir("/proc/acpi/ac_adapter");
        if ( ac_adapters == NULL )
            return 0;

        while (ac_adapters != NULL && ((this_adapter = readdir(ac_adapters)) != NULL)) {
            if (this_adapter->d_name[0] == '.')
                continue;
            /* safe overloaded use of battery_state path var */
            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/ac_adapter/%s/state", this_adapter->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            if (acpi != NULL) {
                while(fgets(buf, 128, acpi)) {
                    if (strstr(buf, "on-line") != NULL) {
                        fclose(acpi);
                        if (ac_adapters != NULL)
                            closedir(ac_adapters);
                        return 0;
                    }
                }
                fclose(acpi);
            }
        }

        if (ac_adapters != NULL)
            closedir(ac_adapters);

        batteries = opendir("/proc/acpi/battery");

        if (batteries == NULL) {
            closedir(batteries);
            return 0;
        }

        while (batteries != NULL && ((this_battery = readdir(batteries)) != NULL)) {
            if (this_battery->d_name[0] == '.')
                continue;

            snprintf(battery_info, sizeof(battery_info), "/proc/acpi/battery/%s/info", this_battery->d_name);
            info = fopen(battery_info, "r");
            batt_full_capacity[batno] = 0;
            if ( info != NULL ) {
                while (fgets(buf, sizeof(buf), info) != NULL)
                    if (sscanf(buf, "last full capacity:      %d mWh", &batt_full_capacity[batno]) == 1)
                        continue;
                fclose(info);
            }


            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/battery/%s/state", this_battery->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            while (fgets(buf, 128, acpi)) {
                if (strncmp(buf, "present:", 8 ) == 0) {
				/* No information for this battery */
                    if (strstr(buf, "no" ))
                        continue;
                }
                else if (strncmp(buf, "charging state:", 15) == 0) {
				/* the space makes it different than discharging */
                    if (strstr(buf, " charging" )) {
                        fclose( acpi );
                        return 0;
                    }
                }
                else if (strncmp(buf, "present rate:", 13) == 0)
                    rate = atoi(buf + 25);
                else if (strncmp(buf, "remaining capacity:", 19) == 0) {
                    remain = atoi(buf + 25);
                    total_remain += remain;
                }
                else if (strncmp(buf, "present voltage:", 17) == 0)
                    current = atoi(buf + 25);
            }
            total_cap += batt_full_capacity[batno];
            fclose(acpi);
            batteryTime += (int) (( ((float)remain) /rate ) * 3600);
            batno++;
        }
        info_timer++;

        if (batteries != NULL)
            closedir(batteries);
    }
    return batteryTime;
#elif defined(_BSD_SOURCE)
    struct apm_power_info api;
    int apmfd;
    if ((apmfd = open("/dev/apm", O_RDONLY)) < 0)
        return 0;
    if (ioctl(apmfd, APM_IOC_GETPOWER, &api) < 0) {
        close(apmfd);
        return 0;
    }
    close(apmfd);
    if (api.battery_state == APM_BATT_UNKNOWN ||
        api.battery_state == APM_BATTERY_ABSENT ||
        api.battery_state == APM_BATT_CHARGING ||
    api.ac_state == APM_AC_ON) {
        return 0;
    }
    return ((int)(api.minutes_left))*60;
#else
    return 0;
#endif
}


char * getStringTimeFromSec(double seconds)
{
	int hour[3];
	char * ret;
    char * HourTime;
    char * MinTime;

	if (seconds <0)
		return NULL;

	ret = (char *) calloc(1,256);

    HourTime = (char *) calloc (1,128);
    MinTime  = (char *) calloc (1,128);

	hour[0]  = (int) (seconds);
	hour[1]  = hour[0] / 60;
    hour[2]  = hour[1] / 60;
	hour[0] %= 60 ;
	hour[1] %= 60 ;

	if (hour[2] != 0 )
		sprintf(HourTime,"%d %s", hour[2], ( hour[2] == 1 ) ? "hour" : "hours");
	if (hour[1] != 0 )
		sprintf(MinTime,"%d %s", hour[1], ( hour[1] == 1 ) ? "min" : "mins");

    if ( hour[2] != 0 && hour[1] != 0 )
        sprintf(ret, "%s %s", HourTime, MinTime);
    else
    {
    	if (hour[2] == 0 && hour[1] == 0)
    		sprintf(ret, "%d s", hour[0] );
        else
        	sprintf(ret, "%s", (hour[2] == 0) ? MinTime : HourTime );
	}

    free(MinTime);
    free(HourTime);

	return ret;

}


char * getBatteryString(void)
{
    int batt_time;
    char * ret;
	char * batt_string;

    batt_time = getBatteryState();

    if ( batt_time <= 60 ) {
        ret = (char *) calloc(1,2);
        ret[0] = ']';
        return ret;
    }

	batt_string = getStringTimeFromSec( (double) batt_time );

	ret = (char *) calloc( 1, 256 );

	sprintf( ret,"][ BAT: %s ]", batt_string );

	free( batt_string);

    return ret;
}


void dump_print( int ws_row, int ws_col )
{
    time_t tt;
    struct tm *lt;
    int nlines, i, n;
    char strbuf[512];
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    nlines = 2;

    if( nlines >= ws_row )
        return;

    tt = time( NULL );
    lt = localtime( &tt );

    /*
     *  display the channel, battery, position (if we are connected to GPSd)
     *  and current time
     */

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );


    if (G.gps_loc[0]) {
        snprintf( strbuf, sizeof( strbuf ) - 1,
              " CH %2d %s[ GPS %8.3f %8.3f %8.3f %6.2f "
              "][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ", G.channel, G.batt,
              G.gps_loc[0], G.gps_loc[1], G.gps_loc[2], G.gps_loc[3],
              G.elapsed_time , 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }
    else
    {
        snprintf( strbuf, sizeof( strbuf ) - 1,
              " CH %2d %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
              G.channel, G.batt, G.elapsed_time, 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    /* print some informations about each detected AP */

    nlines += 3;

    if( nlines >= ws_row )
        return;

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    memcpy( strbuf, " BSSID              PWR  Beacons"
                    "   # Data  CH  MB  ENC   ESSID", 62 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */

        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > 120 ||
            memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        nlines++;

        if( nlines >= ws_row )
            return;

        fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
                ap_cur->bssid[0], ap_cur->bssid[1],
                ap_cur->bssid[2], ap_cur->bssid[3],
                ap_cur->bssid[4], ap_cur->bssid[5] );

        fprintf( stderr, "  %3d %8ld %8ld",
                 ap_cur->avg_power,
                 ap_cur->nb_bcn,
                 ap_cur->nb_data );

        fprintf( stderr, " %3d %3d%c ",
                 ap_cur->channel, ap_cur->max_speed,
                 ( ap_cur->preamble ) ? '.' : ' ' );

        switch( ap_cur->encryption )
        {
            case  0: fprintf( stderr, "OPN " ); break;
            case  1: fprintf( stderr, "WEP?" ); break;
            case  2: fprintf( stderr, "WEP " ); break;
            case  3: fprintf( stderr, "WPA " ); break;
            default: fprintf( stderr, "    " ); break;
        }

        if( ws_col > 58 )
        {
            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "%-256s", ap_cur->essid );
            strbuf[ws_col - 58] = '\0';
            fprintf( stderr, "  %s", strbuf );
        }

        fprintf( stderr, "\n" );

        ap_cur = ap_cur->prev;
    }

    /* print some informations about each detected station */

    nlines += 3;

    if( nlines >= ws_row )
        return;

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    memcpy( strbuf, " BSSID              STATION "
            "           PWR  Packets  Probes", 59 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        if( ap_cur->nb_pkt < 2 ||
            time( NULL ) - ap_cur->tlast > 120 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if( nlines >= ws_row )
            return;

        st_cur = G.st_end;

        while( st_cur != NULL )
        {
            if( st_cur->base != ap_cur ||
                time( NULL ) - st_cur->tlast > 120 )
            {
                st_cur = st_cur->prev;
                continue;
            }

            nlines++;

            if( ws_row != 0 && nlines > ws_row )
                return;

            if( ! memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) )
                fprintf( stderr, " (not associated) " );
            else
                fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
                        ap_cur->bssid[0], ap_cur->bssid[1],
                        ap_cur->bssid[2], ap_cur->bssid[3],
                        ap_cur->bssid[4], ap_cur->bssid[5] );

            fprintf( stderr, "  %02X:%02X:%02X:%02X:%02X:%02X",
                    st_cur->stmac[0], st_cur->stmac[1],
                    st_cur->stmac[2], st_cur->stmac[3],
                    st_cur->stmac[4], st_cur->stmac[5] );

            fprintf( stderr, "  %3d", st_cur->power );
            fprintf( stderr, " %8ld", st_cur->nb_pkt );

            if( ws_col > 53 )
            {
                memset( ssid_list, 0, sizeof( ssid_list ) );

                for( i = 0, n = 0; i < NB_PRB; i++ )
                {
                    if( st_cur->probes[i][0] == '\0' )
                        continue;

                    snprintf( ssid_list + n, sizeof( ssid_list ) - n - 1,
                              "%c%s", ( i > 0 ) ? ',' : ' ',
                              st_cur->probes[i] );

                    n += ( 1 + strlen( st_cur->probes[i] ) );

                    if( n >= (int) sizeof( ssid_list ) )
                        break;
                }

                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "%-256s", ssid_list );
                strbuf[ws_col - 53] = '\0';
                fprintf( stderr, " %s", strbuf );
            }

            fprintf( stderr, "\n" );

            st_cur = st_cur->prev;
        }

        ap_cur = ap_cur->prev;
    }
}

int dump_write_csv( void )
{
    int i, n;
    struct tm *ltime;
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    if (! G.record_data)
    	return 0;

    fseek( G.f_txt, 0, SEEK_SET );

    fprintf( G.f_txt,
        "\r\nBSSID, First time seen, Last time seen, channel, Speed, "
        "Privacy, Power, # beacons, # IV, LAN IP, ESSID\r\n" );

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
        if( memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) == 0 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if( ap_cur->nb_pkt < 2 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X, ",
                 ap_cur->bssid[0], ap_cur->bssid[1],
                 ap_cur->bssid[2], ap_cur->bssid[3],
                 ap_cur->bssid[4], ap_cur->bssid[5] );

        ltime = localtime( &ap_cur->tinit );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        ltime = localtime( &ap_cur->tlast );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        fprintf( G.f_txt, "%2d, %3d, ",
                 ap_cur->channel,
                 ap_cur->max_speed );

        switch( ap_cur->encryption )
        {
            case  0: fprintf( G.f_txt, "OPN " ); break;
            case  1: fprintf( G.f_txt, "WEP?" ); break;
            case  2: fprintf( G.f_txt, "WEP " ); break;
            case  3: fprintf( G.f_txt, "WPA " ); break;
            default: fprintf( G.f_txt, "    " ); break;
        }

        fprintf( G.f_txt, ", %3d, %8ld, %8ld, ",
                 ap_cur->avg_power,
                 ap_cur->nb_bcn,
                 ap_cur->nb_data );

        fprintf( G.f_txt, "%3d.%3d.%3d.%3d, ",
                 ap_cur->lanip[0], ap_cur->lanip[1],
                 ap_cur->lanip[2], ap_cur->lanip[2] );

        fprintf( G.f_txt, "%-32s\r\n", ap_cur->essid );

        ap_cur = ap_cur->next;
    }

    fprintf( G.f_txt,
        "\r\nStation MAC, First time seen, Last time seen, "
        "Power, # packets, BSSID, Probed ESSIDs\r\n" );

    st_cur = G.st_1st;

    while( st_cur != NULL )
    {
        ap_cur = st_cur->base;

        if( ap_cur->nb_pkt < 2 )
        {
            st_cur = st_cur->next;
            continue;
        }

        fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X, ",
                 st_cur->stmac[0], st_cur->stmac[1],
                 st_cur->stmac[2], st_cur->stmac[3],
                 st_cur->stmac[4], st_cur->stmac[5] );

        ltime = localtime( &st_cur->tinit );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        ltime = localtime( &st_cur->tlast );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        fprintf( G.f_txt, "%3d, %8ld, ",
                 st_cur->power,
                 st_cur->nb_pkt );

        if( ! memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) )
            fprintf( G.f_txt, "(not associated) ," );
        else
            fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X,",
                     ap_cur->bssid[0], ap_cur->bssid[1],
                     ap_cur->bssid[2], ap_cur->bssid[3],
                     ap_cur->bssid[4], ap_cur->bssid[5] );

        memset( ssid_list, 0, sizeof( ssid_list ) );

        for( i = 0, n = 0; i < NB_PRB; i++ )
        {
            if( st_cur->probes[i][0] == '\0' )
                continue;

            snprintf( ssid_list + n, sizeof( ssid_list ) - n - 1,
                      "%c%s", ( i > 0 ) ? ',' : ' ', st_cur->probes[i] );

            n += ( 1 + strlen( st_cur->probes[i] ) );
            if( n >= (int) sizeof( ssid_list ) )
                break;
        }

        fprintf( G.f_txt, "%s\r\n", ssid_list );

        st_cur = st_cur->next;
    }

    fprintf( G.f_txt, "\r\n" );
    fflush( G.f_txt );
    sync();
    return 0;
}


void gps_tracker( void )
{
    int gpsd_sock;
    char line[256], *p;
    struct sockaddr_in gpsd_addr;

    /* attempt to connect to localhost, port 2947 */

    gpsd_sock = socket( AF_INET, SOCK_STREAM, 0 );

    if( gpsd_sock < 0 ) {
        return;
    }

    gpsd_addr.sin_family      = AF_INET;
    gpsd_addr.sin_port        = htons( 2947 );
    gpsd_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );

    if( connect( gpsd_sock, (struct sockaddr *) &gpsd_addr,
                 sizeof( gpsd_addr ) ) < 0 ) {
        return;
    }

    /* loop reading the GPS coordinates */

    while( 1 )
    {
        sleep( 1 );

        memset( G.gps_loc, 0, sizeof( float ) * 5 );

        /* read position, speed, heading, altitude */

        memset( line, 0, sizeof( line ) );
        snprintf( line,  sizeof( line ) - 1, "PVTAD\r\n" );
        if( send( gpsd_sock, line, 7, 0 ) != 7 )
            return;

        memset( line, 0, sizeof( line ) );
        if( recv( gpsd_sock, line, sizeof( line ) - 1, 0 ) <= 0 )
            return;

        if( memcmp( line, "GPSD,P=", 7 ) != 0 )
            continue;

        /* make sure the coordinates are present */

        if( line[7] == '?' )
            continue;

        sscanf( line + 7, "%f %f", &G.gps_loc[0], &G.gps_loc[1] );

        if( ( p = strstr( line, "V=" ) ) == NULL ) continue;
        sscanf( p + 2, "%f", &G.gps_loc[2] ); /* speed */

        if( ( p = strstr( line, "T=" ) ) == NULL ) continue;
        sscanf( p + 2, "%f", &G.gps_loc[3] ); /* heading */

        if( ( p = strstr( line, "A=" ) ) == NULL ) continue;
        sscanf( p + 2, "%f", &G.gps_loc[4] ); /* altitude */

        if (G.record_data)
        	fputs( line, G.f_gps );

        G.save_gps = 1;

        write( G.gc_pipe[1], G.gps_loc, sizeof( float ) * 5 );
        kill( getppid(), SIGUSR2 );
    }
}

void sighandler( int signum )
{
    signal( signum, sighandler );

    if( signum == SIGUSR1 )
        read( G.ch_pipe[0], &G.channel, sizeof( int ) );

    if( signum == SIGUSR2 )
        read( G.gc_pipe[0], &G.gps_loc, sizeof( float ) * 5 );

    if( signum == SIGINT || signum == SIGTERM )
    {
        alarm( 1 );
        G.do_exit = 1;
        signal( SIGALRM, sighandler );
        printf( "\n" );
    }

    if( signum == SIGSEGV )
    {
        fprintf( stderr, "Caught signal 11 (SIGSEGV). Please"
                         " contact the author!\33[?25h\n\n" );
        fflush( stdout );
        exit( 1 );
    }

    if( signum == SIGALRM )
    {
        fprintf( stderr, "Caught signal 14 (SIGALRM). Please"
                         " contact the author!\33[?25h\n\n" );
        fflush( stdout );
        exit( 1 );
    }

    if( signum == SIGCHLD )
        wait( NULL );

    if( signum == SIGWINCH )
    {
        fprintf( stderr, "\33[2J" );
        fflush( stdout );
    }
}

int disable_wep_key( char *interface, int fd_raw )
{
    struct iwreq wrq;

    memset( &wrq, 0, sizeof( struct iwreq ) );
    strncpy( wrq.ifr_name, interface, IFNAMSIZ );
    wrq.u.data.flags = IW_ENCODE_DISABLED | IW_ENCODE_NOKEY;

    return( ioctl( fd_raw, SIOCSIWENCODE, &wrq ) != 0 );
}

int set_channel( char *interface, int fd_raw, int channel )
{
    char s[32];
    int pid, status;
    struct iwreq wrq;

    memset( s, 0, sizeof( s ) );

    if( G.is_wlanng )
    {
        snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( G.wlanctlng, "wlanctl-ng", interface,
                    "lnxreq_wlansniff", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );

        if( WIFEXITED(status) )
            return( WEXITSTATUS(status) );
        else
            return( 1 );
    }

    if( G.is_orinoco )
    {
        snprintf( s,  sizeof( s ) - 1, "%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execlp( G.iwpriv, "iwpriv", interface,
                    "monitor", "1", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );
    }

    memset( &wrq, 0, sizeof( struct iwreq ) );
    strncpy( wrq.ifr_name, interface, IFNAMSIZ );
    wrq.u.freq.m = (double) channel;
    wrq.u.freq.e = (double) 0;

    if( ioctl( fd_raw, SIOCSIWFREQ, &wrq ) < 0 )
    {
        usleep( 10000 ); /* madwifi needs a second chance */

        if( ioctl( fd_raw, SIOCSIWFREQ, &wrq ) < 0 )
        {
/*          perror( "ioctl(SIOCSIWFREQ) failed" ); */
            return( 1 );
        }
    }

    return( 0 );
}

int set_monitor( char *interface, int fd_raw )
{
	char s[32];
    int pid, status, channel;
    struct iwreq wrq;

	channel = (G.channel == 0 ) ? 10 : G.channel;

	if( strcmp(interface,"prism0") == 0 )
	{
		if( ( pid = fork() ) == 0 )
		{
			close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
			execl( G.wl, "wl", "monitor", "1", NULL);
			exit( 1 );
		}
		waitpid( pid, &status, 0 );
		if( WIFEXITED(status) )
			return( WEXITSTATUS(status) );
		return( 1 );
	}
	else if (strncmp(interface, "rtap", 4) == 0 )
	{
		return 0;
	}
	else
	{
		if( G.is_wlanng )
		{
			snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );
			if( ( pid = fork() ) == 0 )
			{
				close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
				execl( G.wlanctlng, "wlanctl-ng", interface,
						"lnxreq_wlansniff", "enable=true",
						"prismheader=true", "wlanheader=false",
						"stripfcs=true", "keepwepflags=true",
						s, NULL );
				exit( 1 );
			}

			waitpid( pid, &status, 0 );

			if( WIFEXITED(status) )
				return( WEXITSTATUS(status) );
			return( 1 );
		}

		memset( &wrq, 0, sizeof( struct iwreq ) );
		strncpy( wrq.ifr_name, interface, IFNAMSIZ );
		wrq.u.mode = IW_MODE_MONITOR;

		if( ioctl( fd_raw, SIOCSIWMODE, &wrq ) < 0 )
		{
			perror( "ioctl(SIOCSIWMODE) failed" );
			return( 1 );
		}

	}

	/* Check later if it's really usefull to set channel here */

	set_channel( interface, fd_raw, channel);

    return( 0 );
}

void channel_hopper( char *interface, int fd_raw )
{

    int ch, ch_idx = 0;

    while( getppid() != 1 )
    {
        ++ch_idx;

        if( G.channels[ch_idx] ==  0 )
            ch_idx = 0;

        if( G.channels[ch_idx] == -1 )
            continue;

        ch = G.channels[ch_idx];

        if( set_channel( interface, fd_raw, ch ) == 0 )
        {
            write( G.ch_pipe[1], &ch, sizeof( int ) );
            kill( getppid(), SIGUSR1 );
            usleep( 350000 );
        }
        else
            G.channels[ch_idx] = -1;      /* remove invalid channel */
    }

    exit( 0 );
}

int main( int argc, char *argv[] )
{
    long time_slept;
    int i, n, caplen, pid;
    int fd_raw, arptype;
    int ivs_only, power;
    int valid_channel, chanoption;
    int freq [2];
    time_t tt1, tt2, tt3, start_time;

    unsigned char      *buffer;
    unsigned char      *h80211;
    char               *dump_prefix;
    char               *iface;

    struct ifreq       ifr;
    struct packet_mreq mr;
    struct sockaddr_ll sll;
    struct timeval     tv0;
    struct timeval     tv1;
    struct timeval     tv2;
    struct winsize     ws;
    /*
    struct sockaddr_in provis_addr;
    */

    fd_set             rfds;
    FILE               *check_madwifing;

    /* initialize a bunch of variables */

    memset( &G, 0, sizeof( G ) );

    ivs_only       =  0;
    chanoption     =  0;
    power          = -1;
    fd_raw         = -1;
    arptype        =  0;
    time_slept     =  0;
    G.batt         =  NULL;
    valid_channel  =  0;
    G.usegpsd      =  0;
    G.channels     =  bg_chans;
    G.channel      =  0;
    G.one_beacon   =  1;
    dump_prefix    =  NULL;
    G.record_data  =  0;
	G.f_cap        =  NULL;
	G.f_ivs        =  NULL;
	G.f_txt        =  NULL;
    G.f_gps        =  NULL;

    #ifdef linux
        linux_acpi =  1;
        linux_apm  =  1;
    #endif

    /* check the arguments */

    if( argc < 2 )
    {
        usage:
        printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _BETA)  );
        return( 1 );
    }

    do
    {
        int option_index = 0;

        static struct option long_options[] = {
			{"band",    1, 0, 'b'},
			{"beacon",  0, 0, 'e'},
            {"beacons", 0, 0, 'e'},
            {"channel", 1, 0, 'c'},
            {"gpsd",    0, 0, 'g'},
            {"ivs",     0, 0, 'i'},
			{"write",   1, 0, 'w'},
            {0,         0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "b:c:egiw:",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

			case 'e':
				G.one_beacon = 0;
				break;

            case 'c' :

				if (G.channel > 0 || chanoption == 1) {
					if (chanoption == 1)
						printf( "Notice: Channel range already given\n" );
					else
						printf( "Notice: Channel already given (%d)\n", G.channel);
					break;
				}

                sscanf(optarg, "%d",&(G.channel));

                if ( G.channel < 0 )
                    goto usage;

                if (G.channel != 0)
                {
                    n=0;
                    do {
                        if (G.channel == abg_chans[n])
                            break;
                    } while (abg_chans[++n]);
                    if (G.channel != abg_chans[n])
                        goto usage;
                    else
                    	chanoption = 1;
                }
                /*
                 * else, hop on 2.4Ghz channels
				 */
				G.channels = bg_chans;
				break;

            case 'b' :

				if (chanoption == 1 && option != 'c') {
					printf( "Notice: Channel range already given\n" );
					break;
				}
				freq[0] = freq[1] = 0;

				for (i = 0; i < (int)strlen(optarg); i++) {
					if ( optarg[i] == 'a' )
						freq[1] = 1;
					else if ( optarg[i] == 'b' || optarg[i] == 'g')
						freq[0] = 1;
					else {
						printf( "Error: invalid band (%c)\n", optarg[i] );
						exit ( 1 );
					}
				}

				if (freq[1] + freq[0] == 2 )
					G.channels = abg_chans;
				else {
					if ( freq[1] == 1 )
						G.channels = a_chans;
					else
						G.channels = bg_chans;
				}

                break;

            case 'i':

                ivs_only = 1;
                break;

            case 'g':

                G.usegpsd  = 1;
                /*
                if (inet_aton(optarg, &provis_addr.sin_addr) == 0 )
                {
                    printf("Invalid IP address.\n");
                    return (1);
                }
                */
                break;

            case 'w':
            	if (dump_prefix != NULL) {
            		printf( "Notice: dump prefix already given\n" );
            		break;
            	}
                /* Write prefix */
                dump_prefix   = optarg;
                G.record_data = 1;
                break;

            default : goto usage;
        }
    }
    while ( 1 );

	if ( ivs_only && !G.record_data ) {
		printf( "Missing dump prefix (-w)\n" );
		return( 1 );
	}

    /* Check if we have root privileges */

    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }

    /* create the raw socket and drop privileges */

    fd_raw = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) );

    if( fd_raw < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    setuid( getuid() );

    /* Check iwpriv existence */

	G.iwpriv = wiToolsPath("iwpriv");

    if (! G.iwpriv )
    {
        fprintf(stderr, "Can't find wireless tools, exiting.\n");
        return (1);
    }

    /* reserve the buffer space */

    if( ( buffer = (unsigned char *) malloc( 65536 ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }

    /* find the interface index */

    iface = argv[argc-1];

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd_raw, SIOCGIFINDEX, &ifr ) < 0 )
    {
        fprintf( stderr, "%s is not a network interface.\n", argv[argc-1] );
        return( 1 );
    }

    /* Exit if ndiswrapper : check iwpriv ndis_reset */

    if ( is_ndiswrapper(iface, G.iwpriv) ) {
    	fprintf(stderr, "Ndiswrapper doesn't support monitor mode.\n");
    	return (1);
    }

	if( strcmp(iface,"prism0") == 0 )
		G.wl = wiToolsPath("wl");

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons( ETH_P_ALL );

    if( memcmp( iface, "wlan", 4 ) == 0 )
    {
		G.wlanctlng = wiToolsPath("wlanctl-ng");
        if( ( pid = fork() ) == 0 )     /* wlan-ng brain damage */
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( G.wlanctlng, "wlanctl-ng", iface,
                    "lnxreq_ifstate", "ifstate=enable", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            G.is_wlanng = 1;

        if( ! fork() )                  /* hostap card reset */
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( G.iwpriv, "iwpriv", iface, "reset", "1", NULL );
            exit( 1 );
        }
        wait( NULL );
    }

    /* test if orinoco */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( G.iwpriv, "iwpriv", iface, "get_port3", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            G.is_orinoco = 1;
    }

    /* Check if madwifi-ng */

    G.is_madwifing = 0;
    memset( buffer,0, 65536 );
    snprintf( (char*) buffer, strlen( iface ) + 23,
        "/proc/sys/net/%s/%%parent", iface );
    check_madwifing = fopen( (char*) buffer,"r");
    if (check_madwifing != NULL) {
        fclose(check_madwifing);
        G.is_madwifing = 1;
        memset(buffer,0, 65536);
        sprintf((char *) buffer, "/proc/sys/net/%s/dev_type", iface);
        FILE * f = fopen((char*)buffer,"w");
        if (f != NULL) {
            char * madwifiPrism2 = "802\n";
            fprintf(f, madwifiPrism2);
            fclose(f);
        }
        /* Force prism2 header on madwifi-ng */
    }
    memset(buffer,0, 65536);

    /* make sure the interface is up */

    ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;

    if( ioctl( fd_raw, SIOCSIFFLAGS, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCSIFFLAGS) failed" );
        return( 1 );
    }

    if ( set_monitor( iface, fd_raw ) )
    {
        printf("Error setting monitor mode on %s\n",iface);
        return( 1 );
    }

    /* bind the raw socket to the interface */

    if( bind( fd_raw, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* couple of iwprivs to enable the prism header */

    if( ! fork() )  /* hostap */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execlp( G.iwpriv, "iwpriv", iface, "monitor_type", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* r8180 */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execl( G.iwpriv, "iwpriv", iface, "prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* prism54 */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execl( G.iwpriv, "iwpriv", iface, "set_prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* rt2570-cvs */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execlp( "iwpriv", "iwpriv", argv[1], "forceprismheader", "1", NULL );
        exit( 1 );
    }
    wait( NULL );


    /* make sure the WEP key is off only if it's not rtap0 */
	if ( strncmp( iface, "rtap", 4) )
    	disable_wep_key( iface, fd_raw );

    /* start a child to hop between channels */

    if( G.channel == 0 )
    {
        pipe( G.ch_pipe );

        signal( SIGUSR1, sighandler );

        if( ! fork() )
        {
            channel_hopper( iface, fd_raw );
            exit( 1 );
        }
    }
    else
        set_channel( iface, fd_raw, G.channel );

    /* lookup the hardware type */

    if( ioctl( fd_raw, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    arptype = ifr.ifr_hwaddr.sa_family;

    if( arptype != ARPHRD_IEEE80211 &&
        arptype != ARPHRD_IEEE80211_PRISM &&
        arptype != ARPHRD_IEEE80211_FULL )
    {
        if( arptype == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     arptype );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\n\n", iface, iface );
        return( 1 );
    }

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd_raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    /* open or create the output files */

    if (G.record_data)
    	if( dump_initialize( dump_prefix, ivs_only ) )
    	    return( 1 );

    signal( SIGINT,   sighandler );
    signal( SIGSEGV,  sighandler );
    signal( SIGTERM,  sighandler );
    signal( SIGWINCH, sighandler );

    sighandler( SIGWINCH );

    /* start the GPS tracker */

    if (G.usegpsd)
    {
        pipe( G.gc_pipe );
        signal( SIGUSR2, sighandler );

        if( ! fork() )
        {
            gps_tracker();
            exit( 1 );
        }

        usleep( 50000 );
        waitpid( -1, NULL, WNOHANG );
    }

    fprintf( stderr, "\33[?25l\33[2J\n" );

	start_time = time( NULL );
    tt1        = time( NULL );
    tt2        = time( NULL );
    tt3        = time( NULL );

	G.batt     = getBatteryString();

	G.elapsed_time = (char *) calloc( 1, 4 );
	strcpy(G.elapsed_time,"0 s");

    while( 1 )
    {
        if( G.do_exit ) break;

        if( time( NULL ) - tt1 >= 20 )
        {
            /* update the csv stats file */

            tt1 = time( NULL );
            dump_write_csv();

            /* sort the APs by power */

            dump_sort_power();
        }

        if( time( NULL ) - tt2 > 3 )
        {
            /* update the battery state */
			free(G.batt);

            tt2 			= time( NULL );
            G.batt 			= getBatteryString();

            /* update elapsed time */

			free(G.elapsed_time);
    		G.elapsed_time = getStringTimeFromSec(
    			difftime(tt2, start_time) );


            /* flush the output files */

            if( G.f_cap != NULL ) fflush( G.f_cap );
            if( G.f_ivs != NULL ) fflush( G.f_ivs );
        }

        /* capture one packet */

        FD_ZERO( &rfds );
        FD_SET( fd_raw, &rfds );

        tv0.tv_sec  = 0;
        tv0.tv_usec = REFRESH_RATE;

        gettimeofday( &tv1, NULL );

        if( select( fd_raw + 1, &rfds, NULL, NULL, &tv0 ) < 0 )
        {
            if( errno == EINTR ) continue;
            perror( "select failed" );
            return( 1 );
        }

        gettimeofday( &tv2, NULL );

        time_slept += 1000000 * ( tv2.tv_sec  - tv1.tv_sec  )
                              + ( tv2.tv_usec - tv1.tv_usec );

        if( time_slept > REFRESH_RATE )
        {
            time_slept = 0;

            /* update the window size */

            if( ioctl( 0, TIOCGWINSZ, &ws ) < 0 )
            {
                ws.ws_row = 25;
                ws.ws_col = 80;
            }

            if( ws.ws_col <   1 ) ws.ws_col =   1;
            if( ws.ws_col > 300 ) ws.ws_col = 300;

            /* display the list of access points we have */

            fprintf( stderr, "\33[1;1H" );
            dump_print( ws.ws_row, ws.ws_col );
            fprintf( stderr, "\33[J" );
            fflush( stdout );
            continue;
        }

        if( ! FD_ISSET( fd_raw, &rfds ) )
            continue;

        /* one packet available for reading */

        memset( buffer, 0, 4096 );

        if( ( caplen = read( fd_raw, buffer, 65535 ) ) < 0 )
        {
            perror( "read failed" );
            return( 1 );
        }

        /* if device is an atheros, remove the FCS */

        if( ! memcmp( iface, "ath", 3 ) && (! G.is_madwifing) )
            caplen -= 4;

        /* prism (wlan-ng) header parsing */

        h80211 = buffer;

        if( arptype == ARPHRD_IEEE80211_PRISM )
        {
            if( buffer[7] == 0x40 )
            {
                /* prism54 uses a different format */

                power = buffer[0x33];

                n = 0x40;
            }
            else
            {
                power = *(int *)( buffer + 0x5C );

                if( ! memcmp( iface, "ath", 3 ) )
                    power -= *(int *)( buffer + 0x68 );

                n = *(int *)( buffer + 4 );
            }

            if( n <= 0 || n >= caplen )
                continue;

            h80211 += n;
            caplen -= n;
        }

        /* radiotap header parsing */

        if( arptype == ARPHRD_IEEE80211_FULL )
        {
            if( buffer[0] != 0 )
            {
                fprintf( stderr, "Wrong radiotap header version.\n" );
                return( 1 );
            }

            n = *(unsigned short *)( buffer + 2 );

            if( *(int *)( buffer + 4 ) == 0x0000082E )
                power = buffer[14];     /* ipw2200 1.0.7 */

            if( n <= 0 || n >= caplen )
                continue;

            h80211 += n;
            caplen -= n;
        }

        dump_add_packet( h80211, caplen, power );
    }

    if (G.record_data) {
    	dump_write_csv();

    	if( G.f_txt != NULL ) fclose( G.f_txt );
    	if( G.f_gps != NULL ) fclose( G.f_gps );
    	if( G.f_cap != NULL ) fclose( G.f_cap );
    	if( G.f_ivs != NULL ) fclose( G.f_ivs );
	}

    if( ! G.save_gps )
    {
        sprintf( (char *) buffer, "%s-%02d.gps", argv[2], G.f_index );
        unlink(  (char *) buffer );
    }

    fprintf( stderr, "\33[?25h" );
    fflush( stdout );

    return( 0 );
}
