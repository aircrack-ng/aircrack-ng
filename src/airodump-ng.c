/*
 *  pcap-compatible 802.11 packet sniffer
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

#if !(defined(linux) || defined(__FreeBSD__) || defined( __FreeBSD_kernel__))
    #warning Airodump-ng could fail on this OS
#endif

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#ifndef TIOCGWINSZ
	#include <sys/termios.h>
#endif

#if defined(linux)
    #include <netpacket/packet.h>
    #include <linux/if_ether.h>
    #include <linux/if.h>
    #include <linux/wireless.h>
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    #include <sys/sysctl.h>
    #include <net/bpf.h>
    #include <net/if.h>
    #include <net/if_media.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #include <net80211/ieee80211.h>
    #include <net80211/ieee80211_ioctl.h>
    #include <net80211/ieee80211_radiotap.h>
#endif /* __FreeBSD__ */

#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>


#if defined(linux)
    #include <wait.h>
#endif /* linux */

#if defined(linux)
    int linux_acpi;
    int linux_apm;
    #include <dirent.h>
#endif /* linux */

#include "version.h"
#include "pcap.h"
#include "uniqueiv.c"
#include "crctable.h"

/* some constants */

#define FORMAT_CAP 1
#define FORMAT_IVS 2

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#define REFRESH_RATE 100000  /* default delay in us between updates */

#define NULL_MAC       "\x00\x00\x00\x00\x00\x00"
#define BROADCAST_ADDR "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE_ADDR  "\x01\x80\xC2\x00\x00\x00"

#define NB_PWR  5       /* size of signal power ring buffer */
#define NB_PRB 10       /* size of probed ESSID ring buffer */

#define MAX_CARDS 8	/* maximum number of cards to capture from */

#define NULL_MAC "\x00\x00\x00\x00\x00\x00"

#define	STD_OPN		0x0001
#define	STD_WEP		0x0002
#define	STD_WPA		0x0004
#define	STD_WPA2	0x0008

#define	ENC_WEP		0x0010
#define	ENC_TKIP	0x0020
#define	ENC_WRAP	0x0040
#define	ENC_CCMP	0x0080
#define ENC_WEP40	0x1000
#define	ENC_WEP104	0x0100

#define	AUTH_OPN	0x0200
#define	AUTH_PSK	0x0400
#define	AUTH_MGT	0x0800

#define	QLT_TIME	5
#define	QLT_COUNT	25

#define	MAX(a,b)	((a)>(b)?(a):(b))

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
#if defined(linux)
extern int is_ndiswrapper(const char * iface, const char * path);
extern char * wiToolsPath(const char * tool);
#endif /* linux */

const unsigned char llcnull[4] = {0, 0, 0, 0};
char *f_ext[4] = { "txt", "gps", "cap", "ivs" };

static uchar ZERO[32] =
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

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
    int security;             /* ENC_*, AUTH_*, STD_*     */
    int beacon_logged;        /* We need 1 beacon per AP  */
    int dict_started;         /* 1 if dict attack started */
    int ssid_length;          /* length of ssid           */

    unsigned long nb_bcn;     /* total number of beacons  */
    unsigned long nb_pkt;     /* total number of packets  */
    unsigned long nb_data;    /* number of  data packets  */
    unsigned long nb_data_old;/* number of data packets/sec*/
    int nb_dataps;  /* number of data packets/sec*/
    struct timeval tv;        /* time for data per second */

    unsigned char bssid[6];   /* the access point's MAC   */
    unsigned char essid[256]; /* ascii network identifier */

    unsigned char lanip[4];   /* last detected ip address */
                              /* if non-encrypted network */

    unsigned char **uiv_root; /* unique iv root structure */
                              /* if wep-encrypted network */

    int    rx_quality;        /* percent of captured beacons */
    int    fcapt;             /* amount of captured frames   */
    int    fmiss;             /* amount of missed frames     */
    unsigned int    last_seq; /* last sequence number        */
    struct timeval ftimef;    /* time of first frame         */
    struct timeval ftimel;    /* time of last frame          */
    struct timeval ftimer;    /* time of restart             */

    char *key;		      /* if wep-key found by dict */
    int wpa_state;           /* wpa handshake state       */
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
    char probes[NB_PRB][256];/* probed ESSIDs ring buffer */
    int ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
    int power;               /* last signal power         */
    struct timeval ftimer;   /* time of restart           */
    int missed;              /* number of missed packets  */
    unsigned int lastseq;    /* last seen sequnce number  */
};

/* bunch of global stuff */

struct globals
{
    struct AP_info *ap_1st, *ap_end;
    struct ST_info *st_1st, *st_end;

    unsigned char prev_bssid[6];
    unsigned char f_bssid[6];
    unsigned char f_netmask[6];
    char *dump_prefix;
    char *keyout;
    char *f_cap_name;

    int f_index;            /* outfiles index       */
    FILE *f_txt;            /* output csv file      */
    FILE *f_gps;            /* output gps file      */
    FILE *f_cap;            /* output cap file      */
    FILE *f_ivs;            /* output ivs file      */
    FILE *f_xor;            /* output prga file     */

    char * batt;            /* Battery string       */
    int channel[MAX_CARDS];           /* current channel #    */
    int ch_pipe[2];         /* current channel pipe */
    int cd_pipe[2];	    /* current card pipe    */
    int gc_pipe[2];         /* gps coordinates pipe */
    float gps_loc[5];       /* gps coordinates      */
    int save_gps;           /* keep gps file flag   */
    int usegpsd;            /* do we use GPSd?      */
    int * channels;
    int singlechan;         /* channel hopping set 1*/
    int chswitch;	    /* switching method     */
    int f_encrypt;          /* encryption filter    */
    int update_s;	    /* update delay in sec  */

    int is_wlanng[MAX_CARDS];          /* set if wlan-ng       */
    int is_orinoco[MAX_CARDS];         /* set if orinoco       */
    int is_madwifing[MAX_CARDS];       /* set if madwifi-ng    */
    int is_zd1211rw[MAX_CARDS];       /* set if zd1211rw    */
    int do_exit;            /* interrupt flag       */
    struct winsize ws;      /* console window size  */

    char * elapsed_time;	/* capture time			*/

    int one_beacon;         /* Record only 1 beacon?*/

    unsigned char sharedkey[3][512]; /* array for 3 packets with a size of \
                               up to 512Byte */
    time_t sk_start;
    char *prefix;
    int sk_len;

    int * own_channels;	    /* custom channel list  */

    int record_data;		/* do we record data?   */
    int asso_client;        /* only show associated clients */

    char * iwpriv;
    char * iwconfig;
    char * wlanctlng;
    char * wl;

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    int s_ioctl;
#endif

    unsigned char wpa_bssid[6];   /* the wpa handshake bssid   */
}
G;

/* Convert a 16-bit little-endian value to CPU endianness. */
uint16_t le16_to_cpu(uint16_t le16)
{
    uint16_t ret;

    ret =  (uint16_t)(((uint8_t *)&le16)[0]);
    ret |= (uint16_t)(((uint8_t *)&le16)[1]) << 8;

    return ret;
}

/* Convert a 32-bit little-endian value to CPU endianness. */
uint32_t le32_to_cpu(uint32_t le32)
{
    uint32_t ret;

    ret =  (uint32_t)(((uint8_t *)&le32)[0]);
    ret |= (uint32_t)(((uint8_t *)&le32)[1]) << 8;
    ret |= (uint32_t)(((uint8_t *)&le32)[2]) << 16;
    ret |= (uint32_t)(((uint8_t *)&le32)[3]) << 24;

    return ret;
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024];
    char text[256];
    char prga[512];
    unsigned int long crc;

    if((unsigned)caplen > sizeof(G.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - G.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(G.sharedkey, '\x00', 512*3);
        G.sk_start = time(NULL);
    }

    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(G.sharedkey[0], h80211, caplen);
                G.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(G.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(G.sharedkey[1], h80211, caplen);
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(G.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = G.sk_len;

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, G.sharedkey[0]+24, textlen);

    /* increment sequence number from 2 to 3 */
    text[2] = text[2]+1;

    crc = 0xFFFFFFFF;

    for( n = 0; n < textlen; n++ )
        crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    /* append crc32 over body */
    text[textlen]     = (crc      ) & 0xFF;
    text[textlen+1]   = (crc >>  8) & 0xFF;
    text[textlen+2]   = (crc >> 16) & 0xFF;
    text[textlen+3]   = (crc >> 24) & 0xFF;

    /* cleartext XOR cypher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ G.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = G.sharedkey[1][24] & 0xFF;
    prga[1] = G.sharedkey[1][25] & 0xFF;
    prga[2] = G.sharedkey[1][26] & 0xFF;
    prga[3] = G.sharedkey[1][27] & 0xFF;

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", G.prefix, G.f_index,
              *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5), "xor" );

    G.f_xor = fopen( ofn, "w");
    if(G.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), G.f_xor);

    fflush(G.f_xor);

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    memset(G.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

char usage[] =

"\n"
"  %s - (C) 2006,2007,2008 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: airodump-ng <options> <interface>[,<interface>,...]\n"
"\n"
"  Options:\n"
"      --ivs               : Save only captured IVs\n"
"      --gpsd              : Use GPSd\n"
"      --write    <prefix> : Dump file prefix\n"
"      -w                  : same as --write \n"
"      --beacons           : Record all beacons in dump file\n"
"      --update     <secs> : Display update delay in seconds\n"
"\n"
"  Filter options:\n"
"      --encrypt   <suite> : Filter APs by cypher suite\n"
"      --netmask <netmask> : Filter APs by mask\n"
"      --bssid     <bssid> : Filter APs by BSSID\n"
"      -a                  : Filter unassociated clients\n"
"\n"
"  By default, airodump-ng hop on 2.4Ghz channels.\n"
"  You can make it capture on other/specific channel(s) by using:\n"
"      --channel <channels>: Capture on specific channels\n"
"      --band <abg>        : Band on which airodump-ng should hop\n"
"      --cswitch  <method> : Set channel switching method\n"
"                    0     : FIFO (default)\n"
"                    1     : Round Robin\n"
"                    2     : Hop on last\n"
"      -s                  : same as --cswitch\n"
"\n"
"      --help              : Displays this usage screen\n"
"\n";

int is_filtered_netmask(uchar *bssid)
{
    uchar mac1[6];
    uchar mac2[6];
    int i;

    for(i=0; i<6; i++)
    {
        mac1[i] = bssid[i]     & G.f_netmask[i];
        mac2[i] = G.f_bssid[i] & G.f_netmask[i];
    }

    if( memcmp(mac1, mac2, 6) != 0 )
    {
        return( 1 );
    }

    return 0;
}

void update_rx_quality( )
{
    unsigned int time_diff, capt_time, miss_time;
    int missed_frames;
    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct timeval cur_time;

    ap_cur = G.ap_1st;
    st_cur = G.st_1st;

    gettimeofday( &cur_time, NULL );

    /* accesspoints */
    while( ap_cur != NULL )
    {
        time_diff = 1000000 * (cur_time.tv_sec  - ap_cur->ftimer.tv_sec )
                            + (cur_time.tv_usec - ap_cur->ftimer.tv_usec);

        if(ap_cur->fcapt >= QLT_COUNT || time_diff > (QLT_TIME * 1000000) )
        {
            if(ap_cur->fcapt > 1)
            {
                capt_time =   ( 1000000 * (ap_cur->ftimel.tv_sec  - ap_cur->ftimef.tv_sec )    //time between first and last captured frame
                                        + (ap_cur->ftimel.tv_usec - ap_cur->ftimef.tv_usec) );

                miss_time =   ( 1000000 * (ap_cur->ftimef.tv_sec  - ap_cur->ftimer.tv_sec )    //time between timer reset and first frame
                                        + (ap_cur->ftimef.tv_usec - ap_cur->ftimer.tv_usec) )
                            + ( 1000000 * (cur_time.tv_sec  - ap_cur->ftimel.tv_sec )          //time between last frame and this moment
                                        + (cur_time.tv_usec - ap_cur->ftimel.tv_usec) );

                //number of frames missed at the time where no frames were captured; extrapolated by assuming a constant framerate
                if(capt_time > 0 && miss_time > 200000)
                {
                    missed_frames = ((float)((float)miss_time/(float)capt_time) * ((float)ap_cur->fcapt + (float)ap_cur->fmiss));
                    ap_cur->fmiss += missed_frames;
                }

                ap_cur->rx_quality = ((float)((float)ap_cur->fcapt / ((float)ap_cur->fcapt + (float)ap_cur->fmiss)) * 100.0);
            }
            else ap_cur->rx_quality = 0;

            if(ap_cur->rx_quality > 100) ap_cur->rx_quality = 100;
            if(ap_cur->rx_quality < 0  ) ap_cur->rx_quality =   0;

            ap_cur->fcapt = 0;
            ap_cur->fmiss = 0;
            gettimeofday( &(ap_cur->ftimer) ,NULL);
        }
        ap_cur = ap_cur->next;
    }

    /* stations */
    while( st_cur != NULL )
    {
        time_diff = 1000000 * (cur_time.tv_sec  - st_cur->ftimer.tv_sec )
                            + (cur_time.tv_usec - st_cur->ftimer.tv_usec);

        if( time_diff > 10000000 )
        {
            st_cur->missed = 0;
            gettimeofday( &(st_cur->ftimer), NULL );
        }

        st_cur = st_cur->next;
    }

}

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

    G.prefix = (char*) malloc(strlen(prefix)+2);
    snprintf(G.prefix, strlen(prefix)+1, "%s", prefix);

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

        G.f_cap_name = (char*) malloc(128);
        snprintf(G.f_cap_name, 127, "%s",ofn);

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

int update_dataps()
{
    struct timeval tv;
    struct AP_info *ap_cur;
    int sec, usec, diff, ps;
    float pause;

    gettimeofday(&tv, NULL);

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        sec = (tv.tv_sec - ap_cur->tv.tv_sec);
        usec = (tv.tv_usec - ap_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = ap_cur->nb_data - ap_cur->nb_data_old;
            ps = (int)(((float)diff)/pause);
            ap_cur->nb_dataps = ps;
            ap_cur->nb_data_old = ap_cur->nb_data;
            gettimeofday(&(ap_cur->tv), NULL);
        }
        ap_cur = ap_cur->prev;
    }
    return(0);
}

int dump_add_packet( unsigned char *h80211, int caplen, int power, int cardnum )
{
    int i, n, z, seq, msd, offset;
    int type, length, numuni=0, numauth=0;
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

    /* grab the sequence number */
    seq = ((h80211[22]>>4)+(h80211[23]<<4));

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;
        default: memcpy( bssid, h80211 +  4, 6 ); break;
    }

    if( memcmp(G.f_bssid, NULL_MAC, 6) != 0 )
    {
        if( memcmp(G.f_netmask, NULL_MAC, 6) != 0 )
        {
            if(is_filtered_netmask(bssid)) return(1);
        }
        else
        {
            if( memcmp(G.f_bssid, bssid, 6) != 0 ) return(1);
        }
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
        ap_cur->security   = 0;

        ap_cur->uiv_root = uniqueiv_init();

        ap_cur->nb_dataps = 0;
        ap_cur->nb_data_old = 0;
        gettimeofday(&(ap_cur->tv), NULL);

        ap_cur->dict_started = 0;

        ap_cur->key = NULL;

        G.ap_end = ap_cur;

        ap_cur->nb_bcn     = 0;

        ap_cur->rx_quality = 0;
        ap_cur->fcapt      = 0;
        ap_cur->fmiss      = 0;
        ap_cur->last_seq   = 0;
        gettimeofday( &(ap_cur->ftimef), NULL);
        gettimeofday( &(ap_cur->ftimel), NULL);
        gettimeofday( &(ap_cur->ftimer), NULL);

        ap_cur->ssid_length = 0;
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

        /* every packet in here comes from the AP */

//        printf("seqnum: %i\n", seq);

        if(ap_cur->fcapt == 0 && ap_cur->fmiss == 0) gettimeofday( &(ap_cur->ftimef), NULL);
        if(ap_cur->last_seq != 0) ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
        ap_cur->last_seq = seq;
        ap_cur->fcapt++;
        gettimeofday( &(ap_cur->ftimel), NULL);

        if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
    }

    if( h80211[0] == 0x80 )
        ap_cur->nb_bcn++;

    ap_cur->nb_pkt++;

    /* find wpa handshake */
    if( h80211[0] == 0x10 )
    {
        /* reset the WPA handshake state */

        if( ap_cur != NULL && ap_cur->wpa_state != 0xFF )
            ap_cur->wpa_state = 0;
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
        st_cur->missed  = 0;
        st_cur->lastseq = 0;
        gettimeofday( &(st_cur->ftimer), NULL);

        for( i = 0; i < NB_PRB; i++ )
        {
            memset( st_cur->probes[i], 0, sizeof(
                    st_cur->probes[i] ) );
            st_cur->ssid_length[i] = 0;
        }

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

        if(st_cur->lastseq != 0)
        {
            msd = seq - st_cur->lastseq - 1;
            if(msd > 0 && msd < 1000)
                st_cur->missed += msd;
        }
        st_cur->lastseq = seq;
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
//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                for( i = 0; i < n; i++ )
                    if( p[2 + i] > 0 && p[2 + i] < ' ' )
                        goto skip_probe;

                /* got a valid ASCII probed ESSID, check if it's
                   already in the ring buffer */

                for( i = 0; i < NB_PRB; i++ )
                    if( memcmp( st_cur->probes[i], p + 2, n ) == 0 )
                        goto skip_probe;

                st_cur->probe_index = ( st_cur->probe_index + 1 ) % NB_PRB;
                memset( st_cur->probes[st_cur->probe_index], 0, 256 );
                memcpy( st_cur->probes[st_cur->probe_index], p + 2, n ); //twice?!
                st_cur->ssid_length[st_cur->probe_index] = n;

                for( i = 0; i < n; i++ )
                {
                    c = p[2 + i];
                    if( c == 0 || ( c > 126 && c < 160 ) ) c = '.';  //could also check ||(c>0 && c<32)
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
        if( !(ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) )
        {
            if( ( h80211[34] & 0x10 ) >> 4 ) ap_cur->security |= STD_WEP|ENC_WEP;
            else ap_cur->security |= STD_OPN;
        }

        ap_cur->preamble = ( h80211[34] & 0x20 ) >> 5;

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

    /* packet parsing: Beacon */

    if( h80211[0] == 0x80 && caplen > 38)
    {
        p=h80211+36;         //ignore hdr + fixed params

        while( p < h80211 + caplen )
        {
            type = p[0];
            length = p[1];

            if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == 0x30) )
            {
                ap_cur->security &= ~(STD_WEP|ENC_WEP|STD_WPA);

                offset = 0;

                if(type == 0xDD)
                {
                    //WPA defined in vendor specific tag -> WPA1 support
                    ap_cur->security |= STD_WPA;
                    offset = 4;
                }

                if(type == 0x30)
                {
                    ap_cur->security |= STD_WPA2;
                    offset = 0;
                }

//                printf("sec, length: %d, %d\n", ap_cur->security, length);

                if(length < (18+offset))
                {
                    p += length+2;
                    continue;
                }

                numuni  = p[8+offset] + (p[9+offset]<<8);
                numauth = p[(10+offset) + 4*numuni] + (p[(11+offset) + 4*numuni]<<8);

                p += (10+offset);

//                printf("numuni: %d\n", numuni);
//                printf("numauth: %d\n", numauth);

                for(i=0; i<numuni; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= ENC_WEP;
                        break;
                    case 0x02:
                        ap_cur->security |= ENC_TKIP;
                        break;
                    case 0x03:
                        ap_cur->security |= ENC_WRAP;
                        break;
                    case 0x04:
                        ap_cur->security |= ENC_CCMP;
                        break;
                    case 0x05:
                        ap_cur->security |= ENC_WEP104;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numuni;

                for(i=0; i<numauth; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= AUTH_MGT;
                        break;
                    case 0x02:
                        ap_cur->security |= AUTH_PSK;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numauth;

                if( type == 0x30 ) p += 2;

            }
            else p += length+2;
        }
    }

    /* packet parsing: Authentication Request */

    if( h80211[0] == 0xB0 )
    {
        if( ap_cur->security & STD_WEP )
        {
            ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
            if(h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
            if(h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
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
            ap_cur->channel = G.channel[cardnum];

        /* check the SNAP header to see if data is encrypted */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        if( z + 26 > caplen )
            goto write_packet;

        if( h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03 )
        {
//            if( ap_cur->encryption < 0 )
//                ap_cur->encryption = 0;

            /* if ethertype == IPv4, find the LAN address */

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00 &&
                ( h80211[1] & 3 ) == 0x01 )
                    memcpy( ap_cur->lanip, &h80211[z + 20], 4 );

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06 )
                memcpy( ap_cur->lanip, &h80211[z + 22], 4 );
        }
//        else
//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5 );


        if(ap_cur->security == 0)
        {
            if( (h80211[1] & 0x40) != 0x40 )
            {
                ap_cur->security |= STD_OPN;
            }
            else
            {
                if((h80211[z+3] & 0x20) == 0x20)
                {
                    ap_cur->security |= STD_WPA;
                }
                else
                {
                    ap_cur->security |= STD_WEP;
                    if(h80211[z+3] >= 0x01 && h80211[z+3] <= 0x03)
                    {
                        ap_cur->security |= ENC_WEP40;
                    }
                    else
                    {
                        ap_cur->security |= ENC_WEP;
                    }
                }
            }
        }

        if( z + 10 > caplen )
            goto write_packet;

        if( ap_cur->security & STD_WEP )
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

                        /* Special handling for spanning-tree packets */
                        if( memcmp( h80211 +  4, SPANTREE_ADDR, 6 ) == 0 ||
                            memcmp( h80211 + 16, SPANTREE_ADDR, 6 ) == 0 )
                        {
                            iv_info[ 4] = (iv_info[ 4] ^ 0x42) ^ 0xAA;
                            iv_info[ 5] = (iv_info[ 5] ^ 0x42) ^ 0xAA;
                        }
                    }
                    else
                    {
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                        memcpy( iv_info     , ap_cur->bssid,  6 );
                        memcpy( iv_info + 6 , &h80211[z    ], 3 );
                        memcpy( iv_info + 9 , &h80211[z + 4], 2 );
                        n = 11;

                        /* Special handling for spanning-tree packets */
                        if( memcmp( h80211 +  4, SPANTREE_ADDR, 6 ) == 0 ||
                            memcmp( h80211 + 16, SPANTREE_ADDR, 6 ) == 0 )
                        {
                            iv_info[ 9] = (iv_info[ 9] ^ 0x42) ^ 0xAA;
                            iv_info[10] = (iv_info[10] ^ 0x42) ^ 0xAA;
                        }
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
        {
            ap_cur->nb_data++;
        }

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        if( z + 26 > caplen )
            goto write_packet;

        z += 6;     //skip LLC header

        /* check ethertype == EAPOL */
        if( h80211[z] == 0x88 && h80211[z + 1] == 0x8E && (h80211[1] & 0x40) != 0x40 )
        {
            z += 2;     //skip ethertype

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) != 0 &&
                ( h80211[z + 5] & 0x01 ) == 0 )
            {
                ap_cur->wpa_state = 1;
            }

            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

            if( z+17+32 > caplen )
                goto write_packet;

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                ( h80211[z + 6] & 0x40 ) == 0 &&
                ( h80211[z + 6] & 0x80 ) == 0 &&
                ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                        ap_cur->wpa_state |= 2;
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
                        ap_cur->wpa_state |= 4;
                }
                ap_cur->wpa_state |= 8;
                if( ap_cur->wpa_state == 15)
                        memcpy( G.wpa_bssid, ap_cur->bssid, 6 );
            }
        }

    }


write_packet:

    if(ap_cur != NULL)
    {
        if( h80211[0] == 0x80 && G.one_beacon){
            if( !ap_cur->beacon_logged )
                ap_cur->beacon_logged = 1;
            else return ( 0 );
        }
    }

    if(G.record_data)
    {
        if( ( (h80211[0] & 0x0C) == 0x00 ) && ( (h80211[0] & 0xF0) == 0xB0 ) )
        {
            /* authentication packet */
            check_shared_key(h80211, caplen);
        }
    }

    if(ap_cur != NULL)
    {
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            return(1);
        }
    }

    if( G.f_cap != NULL && caplen >= 10)
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
#if defined(linux)
    char buf[128];
    int batteryTime = 0;
    FILE *apm;
    int flag;
    char units[32];
    int ret;

    if (linux_apm == 1)
    {
        if ((apm = fopen("/proc/apm", "r")) != NULL ) {
            if ( fgets(buf, 128,apm) != NULL ) {
                int charging, ac;
                fclose(apm);

                ret = sscanf(buf, "%*s %*d.%*d %*x %x %x %x %*d%% %d %s\n", &ac,
                        				&charging, &flag, &batteryTime, units);

				if(!ret) return 0;

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
#elif defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    int value;
    size_t len;

    len = 1;
    value = 0;
    sysctlbyname("hw.acpi.acline", &value, &len, NULL, 0);
    if (value == 0)
    {
	    sysctlbyname("hw.acpi.battery.time", &value, &len, NULL, 0);
	    value = value * 60;
    }
    else
    {
	    value = 0;
    }

    return( value );
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

void dump_print( int ws_row, int ws_col, int if_num )
{
    time_t tt;
    struct tm *lt;
    int nlines, i, n;
    char strbuf[512];
    char buffer[512];
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    int columns_ap = 83;
    int columns_sta = 65;

    if(!G.singlechan) columns_ap -= 4; //no RXQ in scan mode

    nlines = 2;

    if( nlines >= ws_row )
        return;

    tt = time( NULL );
    lt = localtime( &tt );

    /*
     *  display the channel, battery, position (if we are connected to GPSd)
     *  and current time
     */

    memset( strbuf, '\0', 512 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    snprintf(strbuf, sizeof(strbuf)-1, " CH %2d", G.channel[0]);
    for(i=1; i<if_num; i++)
    {
        memset( buffer, '\0', 512 );
        snprintf(buffer, 512 , ",%2d", G.channel[i]);
        strncat(strbuf, buffer, (512-strlen(strbuf)));
    }

    memset( buffer, '\0', 512 );

    if (G.gps_loc[0]) {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ GPS %8.3f %8.3f %8.3f %6.2f "
              "][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ", G.batt,
              G.gps_loc[0], G.gps_loc[1], G.gps_loc[2], G.gps_loc[3],
              G.elapsed_time , 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }
    else
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
              G.batt, G.elapsed_time, 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }

    strncat(strbuf, buffer, (512-strlen(strbuf)));

    memset( buffer, '\0', 512 );

    if(memcmp(G.wpa_bssid, NULL_MAC, 6) !=0 )
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
              G.wpa_bssid[0], G.wpa_bssid[1], G.wpa_bssid[2],
              G.wpa_bssid[3], G.wpa_bssid[4], G.wpa_bssid[5]);

        strncat(strbuf, buffer, (512-strlen(strbuf)));
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

    if(G.singlechan)
    {
        memcpy( strbuf, " BSSID              PWR RXQ  Beacons"
                        "    #Data, #/s  CH  MB  ENC  CIPHER AUTH ESSID", columns_ap );
    }
    else
    {
        memcpy( strbuf, " BSSID              PWR  Beacons"
                        "    #Data, #/s  CH  MB  ENC  CIPHER AUTH ESSID", columns_ap );
    }

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

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        nlines++;

        if( nlines > (ws_row-1) )
            return;

        fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
                ap_cur->bssid[0], ap_cur->bssid[1],
                ap_cur->bssid[2], ap_cur->bssid[3],
                ap_cur->bssid[4], ap_cur->bssid[5] );

        if(G.singlechan)
        {
            fprintf( stderr, "  %3d %3d %8ld %8ld %4d",
                     ap_cur->avg_power,
                     ap_cur->rx_quality,
                     ap_cur->nb_bcn,
                     ap_cur->nb_data,
                     ap_cur->nb_dataps );
        }
        else
        {
            fprintf( stderr, "  %3d %8ld %8ld %4d",
                     ap_cur->avg_power,
                     ap_cur->nb_bcn,
                     ap_cur->nb_data,
                     ap_cur->nb_dataps );
        }

        fprintf( stderr, " %3d %3d%c ",
                 ap_cur->channel, ap_cur->max_speed,
                 ( ap_cur->preamble ) ? '.' : ' ' );

        if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) fprintf( stderr, "    " );
        else if( ap_cur->security & STD_WPA2 ) fprintf( stderr, "WPA2" );
        else if( ap_cur->security & STD_WPA  ) fprintf( stderr, "WPA " );
        else if( ap_cur->security & STD_WEP  ) fprintf( stderr, "WEP " );
        else if( ap_cur->security & STD_OPN  ) fprintf( stderr, "OPN " );

        fprintf( stderr, " ");

        if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) fprintf( stderr, "       ");
        else if( ap_cur->security & ENC_CCMP   ) fprintf( stderr, "CCMP   ");
        else if( ap_cur->security & ENC_WRAP   ) fprintf( stderr, "WRAP   ");
        else if( ap_cur->security & ENC_TKIP   ) fprintf( stderr, "TKIP   ");
        else if( ap_cur->security & ENC_WEP104 ) fprintf( stderr, "WEP104 ");
        else if( ap_cur->security & ENC_WEP40  ) fprintf( stderr, "WEP40  ");
        else if( ap_cur->security & ENC_WEP    ) fprintf( stderr, "WEP    ");

        if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) fprintf( stderr, "   ");
        else if( ap_cur->security & AUTH_MGT   ) fprintf( stderr, "MGT");
        else if( ap_cur->security & AUTH_PSK   )
		{
			if( ap_cur->security & STD_WEP )
				fprintf( stderr, "SKA");
			else
				fprintf( stderr, "PSK");
		}
        else if( ap_cur->security & AUTH_OPN   ) fprintf( stderr, "OPN");

        if( ws_col > (columns_ap - 4) )
        {
            memset( strbuf, 0, sizeof( strbuf ) );
            if(ap_cur->essid[0] != 0x00)
            {
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "%-256s", ap_cur->essid );
            }
            else
            {
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "<length:%3d>%-256s", ap_cur->ssid_length, "\x00" );
            }
            strbuf[ws_col - (columns_ap - 4)] = '\0';
            fprintf( stderr, "  %s", strbuf );
        }

        fprintf( stderr, "\n" );

        ap_cur = ap_cur->prev;
    }

    /* print some informations about each detected station */

    nlines += 3;

    if( nlines >= (ws_row-1) )
        return;

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    memcpy( strbuf, " BSSID              STATION "
            "           PWR  Lost  Packets  Probes", columns_sta );
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

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if( nlines >= (ws_row-1) )
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

            if( ! memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) && G.asso_client )
            {
                st_cur = st_cur->prev;
                continue;
            }

            nlines++;

            if( ws_row != 0 && nlines >= ws_row )
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

            fprintf( stderr, "  %3d", st_cur->power  );
            fprintf( stderr, "  %4d", st_cur->missed );
            fprintf( stderr, " %8ld", st_cur->nb_pkt );

            if( ws_col > (columns_sta - 6) )
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
                strbuf[ws_col - (columns_sta - 6)] = '\0';
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
    int i, j, n;
    struct tm *ltime;
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    if (! G.record_data)
    	return 0;

    fseek( G.f_txt, 0, SEEK_SET );

    fprintf( G.f_txt,
        "\r\nBSSID, First time seen, Last time seen, channel, Speed, "
        "Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n" );

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
        if( memcmp( ap_cur->bssid, BROADCAST_ADDR, 6 ) == 0 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
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

        if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) fprintf( G.f_txt, "    " );
        else
        {
            if( ap_cur->security & STD_WPA2 ) fprintf( G.f_txt, "WPA2" );
            if( ap_cur->security & STD_WPA  ) fprintf( G.f_txt, "WPA " );
            if( ap_cur->security & STD_WEP  ) fprintf( G.f_txt, "WEP " );
            if( ap_cur->security & STD_OPN  ) fprintf( G.f_txt, "OPN " );
        }

        fprintf( G.f_txt, ",");

        if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) fprintf( G.f_txt, "       ");
        else
        {
            if( ap_cur->security & ENC_CCMP   ) fprintf( G.f_txt, " CCMP");
            if( ap_cur->security & ENC_WRAP   ) fprintf( G.f_txt, " WRAP");
            if( ap_cur->security & ENC_TKIP   ) fprintf( G.f_txt, " TKIP");
            if( ap_cur->security & ENC_WEP104 ) fprintf( G.f_txt, " WEP104");
            if( ap_cur->security & ENC_WEP40  ) fprintf( G.f_txt, " WEP40");
            if( ap_cur->security & ENC_WEP    ) fprintf( G.f_txt, " WEP");
        }

        fprintf( G.f_txt, ",");

        if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) fprintf( G.f_txt, "   ");
        else
        {
            if( ap_cur->security & AUTH_MGT   ) fprintf( G.f_txt, " MGT");
            if( ap_cur->security & AUTH_PSK   )
			{
				if( ap_cur->security & STD_WEP )
					fprintf( G.f_txt, "SKA");
				else
					fprintf( G.f_txt, "PSK");
			}
            if( ap_cur->security & AUTH_OPN   ) fprintf( G.f_txt, " OPN");
        }

        fprintf( G.f_txt, ", %3d, %8ld, %8ld, ",
                 ap_cur->avg_power,
                 ap_cur->nb_bcn,
                 ap_cur->nb_data );

        fprintf( G.f_txt, "%3d.%3d.%3d.%3d, ",
                 ap_cur->lanip[0], ap_cur->lanip[1],
                 ap_cur->lanip[2], ap_cur->lanip[3] );

        fprintf( G.f_txt, "%3d, ", ap_cur->ssid_length);

        for(i=0; i<ap_cur->ssid_length; i++)
        {
            fprintf( G.f_txt, "%c", ap_cur->essid[i] );
        }
        fprintf( G.f_txt, ", " );


        if(ap_cur->key != NULL)
        {
            for(i=0; i<(int)strlen(ap_cur->key); i++)
            {
                fprintf( G.f_txt, "%02X", ap_cur->key[i]);
                if(i<(int)(strlen(ap_cur->key)-1))
                    fprintf( G.f_txt, ":");
            }
        }

        fprintf( G.f_txt, "\r\n");

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
                      "%c", ( i > 0 ) ? ',' : ' ' );

            for(j=0; j<st_cur->ssid_length[i]; j++)
            {
                snprintf( ssid_list + n + 1 + j, sizeof( ssid_list ) - n - 2 - j,
                          "%c", st_cur->probes[i][j]);
            }

            n += ( 1 + st_cur->ssid_length[i] );
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
    int gpsd_sock, unused;
    char line[256], *p;
    struct sockaddr_in gpsd_addr;
    int ret;

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

        ret = sscanf( line + 7, "%f %f", &G.gps_loc[0], &G.gps_loc[1] );

        if( ( p = strstr( line, "V=" ) ) == NULL ) continue;
        ret = sscanf( p + 2, "%f", &G.gps_loc[2] ); /* speed */

        if( ( p = strstr( line, "T=" ) ) == NULL ) continue;
        ret = sscanf( p + 2, "%f", &G.gps_loc[3] ); /* heading */

        if( ( p = strstr( line, "A=" ) ) == NULL ) continue;
        ret = sscanf( p + 2, "%f", &G.gps_loc[4] ); /* altitude */

        if (G.record_data)
        	fputs( line, G.f_gps );

        G.save_gps = 1;

        unused = write( G.gc_pipe[1], G.gps_loc, sizeof( float ) * 5 );
        kill( getppid(), SIGUSR2 );
    }
}

void sighandler( int signum)
{
    int card, unused;

	card = 0;

    signal( signum, sighandler );

    if( signum == SIGUSR1 )
    {
		unused = read( G.cd_pipe[0], &card, sizeof(int) );
        unused = read( G.ch_pipe[0], &(G.channel[card]), sizeof( int ) );
    }

    if( signum == SIGUSR2 )
        unused = read( G.gc_pipe[0], &G.gps_loc, sizeof( float ) * 5 );

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

#if defined(linux)
int disable_wep_key( char *interface, int fd_raw )
{
    struct iwreq wrq;

    memset( &wrq, 0, sizeof( struct iwreq ) );
    strncpy( wrq.ifr_name, interface, IFNAMSIZ );
    wrq.u.data.flags = IW_ENCODE_DISABLED | IW_ENCODE_NOKEY;

    return( ioctl( fd_raw, SIOCSIWENCODE, &wrq ) != 0 );
}
#endif /* linux */

#if defined(linux)
int set_channel( char *interface, int fd_raw, int channel, int cardnum )
{
    char s[32];
    int pid, status, unused;
    struct iwreq wrq;

    memset( s, 0, sizeof( s ) );

    if( G.is_wlanng[cardnum] )
    {
        snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
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

    if( G.is_orinoco[cardnum] )
    {
        snprintf( s,  sizeof( s ) - 1, "%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( G.iwpriv, "iwpriv", interface,
                    "monitor", "1", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );
        return 0;
    }

    if( G.is_zd1211rw[cardnum] )
    {
        snprintf( s,  sizeof( s ) - 1, "%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( G.iwconfig, "iwconfig", interface,
                    "channel", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );
        return 0;
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
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
/*
    this function, as a few others, presents a slightly
    reduced set of parameters, because we don't need some
    of them, for example the card number or references
    to linux-only structs needed to make hardware behave.
*/
int set_channel( char *interface, int channel )
{
    struct ieee80211req ifr;

    if (G.s_ioctl == -1)
    {
		if ( ( G.s_ioctl = socket( PF_INET, SOCK_DGRAM, 0 ) ) == -1 )
		{
			perror( "socket() failed" );
			return( 1 );
		}
    }

    strncpy( ifr.i_name, interface, IFNAMSIZ - 1 );
    ifr.i_type = IEEE80211_IOC_CHANNEL;

    if ( ioctl( G.s_ioctl, SIOCG80211, &ifr ) == -1 )
    {
		perror( "ioctl(SIOCG80211) failed" );
		return( 1 );
    }

    ifr.i_val = channel;

    if ( ioctl( G.s_ioctl, SIOCS80211, &ifr ) == -1 )
    {
		perror( "ioctl(SIOCS80211) failed" );
		return( 1 );
    }

    return( 0 );
}
#endif /* __FreeBSD__ */

#if defined(linux)
int set_monitor( char *interface, int fd_raw, int cardnum )
{
    char s[32];
    int pid, status, channel, unused;
    struct iwreq wrq;

    channel = (G.channel[0] == 0 ) ? 10 : G.channel[0];

    if( strcmp(interface,"prism0") == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
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
        if( G.is_wlanng[cardnum] )
        {
            snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );
            if( ( pid = fork() ) == 0 )
            {
                close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
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

    set_channel( interface, fd_raw, (G.channel[cardnum] == 0 ) ? 10 : G.channel[cardnum], cardnum);

    return( 0 );
}
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
/*
    this function, as a few others, presents a slightly
    reduced set of parameters, because we don't need some
    of them, for example the card number or references
    to linux-only structs needed to make hardware behave.
*/
int set_monitor( char *interface, int cardnum )
{
    int s, i, *mw, ahd;
    struct ifreq ifr;
    struct ifmediareq ifmr;

    if( ( s = socket( PF_INET, SOCK_RAW, 0 ) ) == -1 )
    {
		perror( "socket() failed" );
		return( 1 );
    }

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, interface, IFNAMSIZ - 1 );

    if( ioctl( s, SIOCGIFFLAGS, &ifr ) == -1 )
    {
		perror( "ioctl(SIOCGIFFLAGS) failed" );
		return( 1 );
    }

    memset( &ifmr, 0, sizeof( ifmr ) );
    strncpy( ifmr.ifm_name, interface, IFNAMSIZ - 1 );

    if( ioctl(s, SIOCGIFMEDIA, &ifmr ) == -1)
    {
		perror( "ioctl(SIOCGIFMEDIA) failed" );
		return( 1 );
    }

    if( ifmr.ifm_count == 0 )
    {
		perror( "ioctl(SIOCGIFMEDIA), no media words" );
		return( 1 );
    }

    mw = calloc( (size_t) ifmr.ifm_count, sizeof( int ) );
    if( mw == NULL )
    {
		perror( "calloc()" );
		return( 1 );
    }

    ifmr.ifm_ulist = mw;
    strncpy( ifmr.ifm_name, interface, IFNAMSIZ - 1 );
    if ( ioctl(s, SIOCGIFMEDIA, &ifmr ) == -1 )
    {
		perror( "ioctl(SIOCGIFMEDIA)" );
		return( 1 );
    }

    for( i = 0; i < ifmr.ifm_count; i++ )
    {
		if( ifmr.ifm_ulist[i] & IFM_IEEE80211_MONITOR )
		{
			i =  ifmr.ifm_count  + 1;
		}
    }

    if( i == ( ifmr.ifm_count  + 1 ) )
    {
		return( 1 );
    }

    /*
	A few interfaces on FreeBSD have a specific operating
	mode called adhoc demo, which is an adhoc mode that
	sends no beacons. The pratical effect of such a mode
	is that's possible to monitor *and* write raw frames
	down the pipe without messing with things we don't
	know about ;)
	here we try first to use the adhoc demo mode and then
	fallback to monitor if it's not available.
	why?
	because aireplay while opening the raw bpf stuff will
	don't mess with the interface... smooooth operations.
    */

    /* check if interface supports adhoc + flag0 */
    ahd = 0;
    for( i = 0; i < ifmr.ifm_count && ahd == 0; i++ )
	{
	    if( ifmr.ifm_ulist[i] & IFM_IEEE80211_ADHOC )
	    {
			if( ifmr.ifm_ulist[i] & IFM_FLAG0 )
			{
				ahd = 1;
				break;
			}
		}
    }

    if( ahd == 0 )
    {
		/* no. fallback to monitor mode */
		for( i = 0; i < ifmr.ifm_count; i++ )
		{
			if( ifmr.ifm_ulist[i] & IFM_IEEE80211_MONITOR )
			{
				i = ifmr.ifm_count + 1;
				break;
			}
		}

		if( i != ( ifmr.ifm_count + 1 ) )
		{
			/* crap, neither monitor mode! */
			fprintf(stderr,
			"interface %s is missing monitor mode\n",
			interface);
			return( 1 );
		}
    }

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, interface, IFNAMSIZ - 1 );

    ifr.ifr_media = IFM_IEEE80211 | IFM_AUTO;
    if (ahd == 0)
		ifr.ifr_media |= IFM_IEEE80211_MONITOR;
    else
		ifr.ifr_media |= IFM_IEEE80211_ADHOC | IFM_FLAG0;

    if( ioctl( s, SIOCSIFMEDIA, &ifr ) == -1 )
    {
		perror( "ioctl(SIOCSIFMEDIA) failed" );
		return( 1 );
    }

    if( ioctl( s, SIOCGIFMEDIA, &ifmr ) == -1 )
    {
		perror( "ioctl(SIOCGIFMEDIA) failed" );
		return( 1 );
    }

    if( ioctl( s, SIOCSIFMEDIA, &ifr ) == -1 )
    {
		perror( "ioctl(SIOCSIFMEDIA) failed" );
		return( 1 );
    }

    i = ( ifr.ifr_flags & 0xffff ) | ( ifr.ifr_flagshigh << 16 );
    if( !( i & IFF_UP ) )
    {
		i |= IFF_UP;

		ifr.ifr_flags = i & 0xffff;
		ifr.ifr_flagshigh = i >> 16;

		if ( ioctl( s, SIOCSIFFLAGS, &ifr ) == -1 )
		{
			perror( "ioctl(SIOCSIFFLAGS) failed" );
			return( 1 );
		}
    }

    close(s);

    set_channel( interface, (G.channel[cardnum] == 0 ) ? 10 : G.channel[cardnum] );

    return( 0 );
}
#endif /* __FreeBSD__ */

int getchancount(int valid)
{
    int i=0, chan_count=0;

    while(G.channels[i])
    {
        i++;
        if(G.channels[i] != -1)
            chan_count++;
    }

    if(valid) return chan_count;
    return i;
}

#if defined(linux)
void channel_hopper( char *interface[], int fd_raw[], int if_num, int chan_count )
{

    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;
    int round=0, nfirst=0, quick=1, stime=100000, tries=0, unused;

    nfirst = chan_count / if_num + 1;

    while( getppid() != 1 )
    {
        tries=0;
        for(j=0; j<if_num; j++)
        {
            again=1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if(tries>chan_count)
            {
                exit( 0 );
            }

            if( G.chswitch == 2 && !first)
            {
                j=(if_num - 1);
                card = if_num-1;
                if( getchancount(1) > if_num )
                {
                    while( again )
                    {
                        again=0;
                        for(k=0; k<(if_num-1); k++)
                        {
                            if(G.channels[ch_idx] == G.channel[k])
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.channels[ch_idx] == -1 )
            {
                tries++;
                j--;
                cai--;
                continue;
            }

            ch = G.channels[ch_idx];


            if( set_channel( interface[card], fd_raw[card], ch, card ) == 0 )
            {
                G.channel[card] = ch;
                unused = write( G.cd_pipe[1], &card, sizeof(int) );
                unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                if( strncmp( interface[card], "rtap", 4) )
                {
                    G.channels[ch_idx] = -1;      /* remove invalid channel */
                    j--;
                    cai--;
                }
                continue;
            }
        }
        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }
        if(first)
        {
            first = 0;
        }

        if( round > nfirst*3 && quick )
        {
            quick = 0;
            stime = 350000;
        }

        usleep( stime );

        if(quick) round++;
    }

    exit( 0 );
}
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
/*
    this function, as a few others, presents a slightly
    reduced set of parameters, because we don't need some
    of them, for example the card number or references
    to linux-only structs needed to make hardware behave.
*/
void channel_hopper( char *interface[], int if_num, int chan_count )
{
    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;

    while( getppid() != 1 )
    {
        for( j = 0; j < if_num; j++ )
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if( G.chswitch == 2 && !first )
            {
                j = if_num - 1;
                card = if_num - 1;

                if( getchancount(1) > if_num )
                {
                    while( again )
                    {
                        again = 0;
                        for( k = 0; k < ( if_num - 1 ); k++ )
                        {
                            if( G.channels[ch_idx] == G.channel[k] )
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.channels[ch_idx] == -1 )
            {
                j--;
                cai--;
                continue;
            }

            ch = G.channels[ch_idx];

            if( set_channel( interface[card], ch ) == 0 )
            {
                G.channel[card] = ch;
                write( G.cd_pipe[1], &card, sizeof(int) );
                write( G.ch_pipe[1], &ch, sizeof( int ) );
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                G.channels[ch_idx] = -1;      /* remove invalid channel */
                j--;
                cai--;
                continue;
            }
        }

        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }

        if(first)
        {
            first = 0;
        }

        usleep( (350000) );
    }

    exit( 0 );
}
#endif /* __FreeBSD__ */

int invalid_channel(int chan)
{
    int i=0;

    do
    {
        if (chan == abg_chans[i] && chan != 0 )
            return 0;
    } while (abg_chans[++i]);
    return 1;
}

/* parse a string, for example "1,2,3-7,11" */

int getchannels(const char *optarg)
{
    unsigned int i=0,chan_cur=0,chan_first=0,chan_last=0,chan_max=128,chan_remain=0;
    char *optchan = NULL;
    char *token = NULL;
    int *tmp_channels;

    //got a NULL pointer?
    if(optarg == NULL)
        return -1;

    chan_remain=chan_max;

    //create a writable string
    optchan = (char*) malloc(strlen(optarg)+1);
    strncpy(optchan, optarg, strlen(optarg));
    optchan[strlen(optarg)]='\0';

    tmp_channels = (int*) malloc(sizeof(int)*(chan_max+1));

    //split string in tokens, separated by ','
    while( (token = strsep(&optchan,",")) != NULL)
    {
        //range defined?
        if(strchr(token, '-') != NULL)
        {
            //only 1 '-' ?
            if(strchr(token, '-') == strrchr(token, '-'))
            {
                //are there any illegal characters?
                for(i=0; i<strlen(token); i++)
                {
                    if( (token[i] < '0') && (token[i] > '9') && (token[i] != '-'))
                    {
                        free(tmp_channels);
                        free(optchan);
                        return -1;
                    }
                }

                if( sscanf(token, "%d-%d", &chan_first, &chan_last) != EOF )
                {
                    if(chan_first > chan_last)
                    {
                        free(tmp_channels);
                        free(optchan);
                        return -1;
                    }
                    for(i=chan_first; i<=chan_last; i++)
                    {
                        if( (! invalid_channel(i)) && (chan_remain > 0) )
                        {
                                tmp_channels[chan_max-chan_remain]=i;
                                chan_remain--;
                        }
                    }
                }
                else
                {
                    free(tmp_channels);
                    free(optchan);
                    return -1;
                }

            }
            else
            {
                free(tmp_channels);
                free(optchan);
                return -1;
            }
        }
        else
        {
            //are there any illegal characters?
            for(i=0; i<strlen(token); i++)
            {
                if( (token[i] < '0') && (token[i] > '9') )
                {
                    free(tmp_channels);
                    free(optchan);
                    return -1;
                }
            }

            if( sscanf(token, "%d", &chan_cur) != EOF)
            {
                if( (! invalid_channel(chan_cur)) && (chan_remain > 0) )
                {
                        tmp_channels[chan_max-chan_remain]=chan_cur;
                        chan_remain--;
                }

            }
            else
            {
                free(tmp_channels);
                free(optchan);
                return -1;
            }
        }
    }

    G.own_channels = (int*) malloc(sizeof(int)*(chan_max - chan_remain + 1));

    for(i=0; i<(chan_max - chan_remain); i++)
    {
        G.own_channels[i]=tmp_channels[i];
    }

    G.own_channels[i]=0;

    free(tmp_channels);
    free(optchan);
    if(i==1) return G.own_channels[0];
    if(i==0) return -1;
    return 0;
}

#if defined(linux)
int setup_card(char *iface, struct ifreq *ifr, struct packet_mreq *mr, struct sockaddr_ll *sll, int *fd_raw, int *arptype, int cardnum)
{
    int pid=0, n=0, unused;
    uchar *buffer;
    FILE *check_madwifing;
    FILE *f;

    /* reserve the buffer space */

    if( ( buffer = (unsigned char *) malloc( 65536 ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }

    memset( ifr, 0, sizeof( *ifr ) );
    strncpy( ifr->ifr_name, iface, sizeof( ifr->ifr_name ) - 1 );

    if( ioctl( *fd_raw, SIOCGIFINDEX, ifr ) < 0 )
    {
        fprintf( stderr, "%s is not a network interface.\n", iface );
        return( 1 );
    }

    /* Exit if ndiswrapper : check iwpriv ndis_reset */

    if ( is_ndiswrapper(iface, G.iwpriv) ) {
        printf("Ndiswrapper doesn't support monitor mode.\n");
        return (1);
    }

    if( strcmp(iface,"prism0") == 0 )
        G.wl = wiToolsPath("wl");

    memset( sll, 0, sizeof( *sll ) );
    sll->sll_family   = AF_PACKET;
    sll->sll_ifindex  = ifr->ifr_ifindex;
    sll->sll_protocol = htons( ETH_P_ALL );

    if( memcmp( iface, "wlan", 4 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )     /* wlan-ng brain damage */
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "wlanctl-ng", "wlanctl-ng", iface,
                    "lnxreq_ifstate", "ifstate=enable", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            G.is_wlanng[cardnum] = 1;

        if( ! fork() )                  /* hostap card reset */
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "reset", "1", NULL );
            exit( 1 );
        }
        wait( NULL );
    }

    /* test if orinoco */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_port3", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            G.is_orinoco[cardnum] = 1;
    }

    /* test if zd1211rw */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_regdomain", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            G.is_zd1211rw[cardnum] = 1;
    }

    /* Check if madwifi-ng */

    G.is_madwifing[cardnum] = 0;
    memset( buffer,0, 65536 );
    snprintf( (char*) buffer, strlen( iface ) + 23,
        "/proc/sys/net/%s/%%parent", iface );
    check_madwifing = fopen( (char*) buffer,"r");

    if (check_madwifing != NULL) {
        fclose(check_madwifing);
        G.is_madwifing[cardnum] = 1;
        memset(buffer,0, 65536);

        sprintf((char *) buffer, "/proc/sys/net/%s/dev_type", iface);
        f = fopen( (char *) buffer,"w");
        if (f != NULL) {
            fprintf(f, "802\n");
            fclose(f);
        }
        /* Force prism2 header on madwifi-ng */
    }
    memset(buffer,0, 65536);

    /* make sure the interface is up */

    ifr->ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;

    if( ioctl( *fd_raw, SIOCSIFFLAGS, ifr ) < 0 )
    {
        perror( "ioctl(SIOCSIFFLAGS) failed" );
        return( 1 );
    }

    if (set_monitor( iface, *fd_raw, cardnum ))
    {
        printf("Error setting monitor mode on %s\n",iface);
        return( 1 );
    }

    /* bind the raw socket to the interface */

    if( bind( *fd_raw, (struct sockaddr *) sll,
              sizeof( *sll ) ) < 0 )
    {
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* couple of iwprivs to enable the prism header */

    if( ! fork() )  /* hostap */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "monitor_type", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* r8180 */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* prism54 */
    {
        close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "set_prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    /* make sure the WEP key is off */

    if ( strncmp( iface, "rtap", 4) )
        disable_wep_key( iface, *fd_raw );

    /* lookup the hardware type */

    if( ioctl( *fd_raw, SIOCGIFHWADDR, ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    *arptype = ifr->ifr_hwaddr.sa_family;

    if( *arptype != ARPHRD_IEEE80211 &&
        *arptype != ARPHRD_IEEE80211_PRISM &&
        *arptype != ARPHRD_IEEE80211_FULL )
    {
        if( *arptype == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     *arptype );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\n\n", iface, iface );
        return( 1 );
    }

    /* enable promiscuous mode */

    memset( mr, 0, sizeof( *mr ) );
    mr->mr_ifindex = sll->sll_ifindex;
    mr->mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( *fd_raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    mr, sizeof( *mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
/*
    this function, as a few others, presents a slightly
    reduced set of parameters, because we don't need some
    of them, for example the card number or references
    to linux-only structs needed to make hardware behave.
*/
int setup_card(char *iface, struct ifreq *ifr, int *fd_raw, int cardnum)
{
    unsigned int i;

    /* bind interface iface to the bpf */
    memset( ifr, 0, sizeof(ifr) );
    strncpy( ifr->ifr_name, iface, IFNAMSIZ - 1 );

    if( ioctl( *fd_raw, BIOCSETIF, ifr ) == -1 )
    {
	perror( "ioctl(BIOCSETIF) failed" );
	return( 1 );
    }

    /* set a meaningful datalink type */
    i = DLT_IEEE802_11_RADIO;
    if( ioctl( *fd_raw, BIOCSDLT, &i ) == -1 )
    {
	perror( "ioctl(BIOCSDLT) failed" );
	return( 1 );
    }

    /* set immediate mode (doesn't wait for buffer fillup) */
    i = 1;
    if( ioctl( *fd_raw, BIOCIMMEDIATE, &i ) == -1 )
    {
	perror( "ioctl(BIOCIMMEDIATE) failed" );
	return( 1 );
    }

    /* set bpf's promiscuous mode */
    if( ioctl( *fd_raw, BIOCPROMISC, NULL) == -1 )
    {
	perror( "ioctl(BIOCPROMISC) failed" );
	return( 1 );
    }

    /* lock bpf for further messing */
    if( ioctl( *fd_raw, BIOCLOCK, NULL ) == -1 )
    {
	perror( "ioctl(BIOCLOCK) failed" );
	return( 1 );
    }

    /* set monitor mode in interface iface */
    if( set_monitor( iface, cardnum ) == 1 )
    {
	return( 1 );
    }

    return( 0 );
}
#endif /* __FreeBSD__ */

#if defined(linux)
int init_cards(const char* cardstr, char *iface[], struct ifreq ifr[], struct packet_mreq mr[], struct sockaddr_ll sll[], int fd_raw[], int arptype[])
{
    char *buffer;
    int if_count=0;
    int i=0, again=0;

    buffer = (char*) malloc(sizeof(char)*1025);
    strncpy(buffer, cardstr, 1025);
    buffer[1024] = '\0';

    while( ((iface[if_count]=strsep(&buffer, ",")) != NULL) && (if_count < MAX_CARDS) )
    {
        again=0;
        for(i=0; i<if_count; i++)
        {
            if(strcmp(iface[i], iface[if_count]) == 0)
            again=1;
        }
        if(again) continue;
        if(setup_card(iface[if_count], &(ifr[if_count]), &(mr[if_count]), &(sll[if_count]), &(fd_raw[if_count]), &(arptype[if_count]), if_count) != 0)
            return -1;
        if_count++;
    }

    return if_count;
}
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
/*
    this function, as a few others, presents a slightly
    reduced set of parameters, because we don't need some
    of them, for example the card number or references
    to linux-only structs needed to make hardware behave.
*/
int init_cards(const char* cardstr, char *iface[], struct ifreq ifr[], int fd_raw[])
{
    char *buffer;
    int if_count=0;

    buffer = (char*) malloc( sizeof(char) * 1025 );
    strncpy( buffer, cardstr, 1025 );
    buffer[1024] = '\0';

    while( ((iface[if_count]=strsep(&buffer, ",")) != NULL) && (if_count < MAX_CARDS) )
    {
        if(setup_card(iface[if_count], &(ifr[if_count]), &(fd_raw[if_count]), if_count) != 0)
            return -1;
        if_count++;
    }

    return if_count;
}
#endif /* __FreeBSD__ */

int get_if_num(const char* cardstr)
{
    char *buffer;
    int if_count=0;

    buffer = (char*) malloc(sizeof(char)*1025);
    strncpy(buffer, cardstr, 1025);
    buffer[1024] = '\0';

    while( (strsep(&buffer, ",") != NULL) && (if_count < MAX_CARDS) )
    {
        if_count++;
    }

    return if_count;
}

int set_encryption_filter(const char* input)
{
    if(input == NULL) return 1;

    if(strlen(input) < 3) return 1;

    if(strcasecmp(input, "opn") == 0)
        G.f_encrypt |= STD_OPN;

    if(strcasecmp(input, "wep") == 0)
        G.f_encrypt |= STD_WEP;

    if(strcasecmp(input, "wpa") == 0)
    {
        G.f_encrypt |= STD_WPA;
        G.f_encrypt |= STD_WPA2;
    }

    if(strcasecmp(input, "wpa1") == 0)
        G.f_encrypt |= STD_WPA;

    if(strcasecmp(input, "wpa2") == 0)
        G.f_encrypt |= STD_WPA2;

    return 0;
}

int main( int argc, char *argv[] )
{
    long time_slept, cycle_time, unused;
    int n, caplen, i, cards, fdh, fd_is_set, chan_count;
    int fd_raw[MAX_CARDS], arptype[MAX_CARDS];
    int ivs_only, power;
    int valid_channel, chanoption;
    int freq [2];
    time_t tt1, tt2, tt3, start_time;

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    int j, k;
    char *bnbuf;
    unsigned int buf;
    struct bpf_hdr *bpfp;
    struct ieee80211_radiotap_header *rtp;
    unsigned char *r;
    size_t buflen = 0;
#endif /* __FreeBSD__ */

    unsigned char      *buffer;
    unsigned char      *h80211;
    char               *iface[MAX_CARDS];

    struct ifreq       ifr[MAX_CARDS];

#if defined(linux)
    struct packet_mreq mr[MAX_CARDS];
    struct sockaddr_ll sll[MAX_CARDS];
#endif /* linux */

    struct timeval     tv0;
    struct timeval     tv1;
    struct timeval     tv2;
    struct timeval     tv3;
    struct winsize     ws;
    struct tm          *lt;

    /*
    struct sockaddr_in provis_addr;
    */

    fd_set             rfds;

    /* initialize a bunch of variables */

    memset( &G, 0, sizeof( G ) );

    ivs_only       =  0;
    chanoption     =  0;
    power          = -1;
//    fd_raw         = -1;
//    arptype        =  0;
    cards	   =  0;
    fdh		   =  0;
    fd_is_set	   =  0;
    chan_count	   =  0;
    time_slept     =  0;
    G.batt         =  NULL;
    G.chswitch     =  0;
    valid_channel  =  0;
    G.usegpsd      =  0;
    G.channels     =  bg_chans;
//    G.channel      =  0;
    G.one_beacon   =  1;
    G.singlechan  =  0;
    G.dump_prefix    =  NULL;
    G.record_data  =  0;
    G.f_cap        =  NULL;
    G.f_ivs        =  NULL;
    G.f_txt        =  NULL;
    G.f_gps        =  NULL;
    G.keyout = NULL;
    G.f_xor        =  NULL;
    G.sk_len       =  0;
    G.sk_start     =  0;
    G.prefix       =  NULL;
    G.f_encrypt    =  0;
    G.asso_client  =  0;
    G.update_s     =  0;
    memset(G.sharedkey, '\x00', 512*3);

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    G.s_ioctl = -1;
#endif

    gettimeofday( &tv0, NULL );

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    /* cast to accomodate a warning on FreeBSD 6-stable */
    lt = localtime( (time_t *) &tv0.tv_sec );
#else
    lt = localtime( &tv0.tv_sec );
#endif

    G.keyout = (char*) malloc(512);
    memset( G.keyout, 0, 512 );
    snprintf( G.keyout,  511,
              "keyout-%02d%02d-%02d%02d%02d.keys",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    for(i=0; i<MAX_CARDS; i++)
    {
        arptype[i]=0;
        fd_raw[i]=-1;
        G.channel[i]=0;
    }

    memset(G.f_bssid, '\x00', 6);
    memset(G.f_netmask, '\x00', 6);
    memset(G.wpa_bssid, '\x00', 6);


    #if defined(linux)
        linux_acpi =  1;
        linux_apm  =  1;
    #endif /* linux */

    /* check the arguments */

    do
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"band",    1, 0, 'b'},
            {"beacon",  0, 0, 'e'},
            {"beacons", 0, 0, 'e'},
            {"cswitch", 1, 0, 's'},
            {"netmask", 1, 0, 'm'},
            {"bssid",   1, 0, 'd'},
            {"channel", 1, 0, 'c'},
            {"gpsd",    0, 0, 'g'},
            {"ivs",     0, 0, 'i'},
            {"write",   1, 0, 'w'},
            {"encrypt", 1, 0, 't'},
            {"update",  1, 0, 'u'},
            {"help",    0, 0, 'H'},
            {0,         0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "b:c:egiw:s:t:u:m:d:aH",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':':

	    		printf("\"%s --help\" for help.\n", argv[0]);
            	return( 1 );

            case '?':

	    		printf("\"%s --help\" for help.\n", argv[0]);
            	return( 1 );

            case 'e':

                G.one_beacon = 0;
                break;

            case 'a':

                G.asso_client = 1;
                break;

            case 'c' :

                if (G.channel[0] > 0 || chanoption == 1) {
                    if (chanoption == 1)
                        printf( "Notice: Channel range already given\n" );
                    else
                        printf( "Notice: Channel already given (%d)\n", G.channel[0]);
                    break;
                }

                G.channel[0] = getchannels(optarg);

                if ( G.channel[0] < 0 )
                    goto usage;

                chanoption = 1;
/*                if (G.channel[0] != 0)
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
                else */
                if( G.channel[0] == 0 )
                {
                    G.channels = G.own_channels;
//                  chanoption = 1;
                    break;
                }
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
			    		printf("\"%s --help\" for help.\n", argv[0]);
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

            	if (G.dump_prefix != NULL) {
            		printf( "Notice: dump prefix already given\n" );
            		break;
            	}
                /* Write prefix */
                G.dump_prefix   = optarg;
                G.record_data = 1;
                break;

            case 's':

                if (atoi(optarg) > 2) {
                    goto usage;
                }
                if (G.chswitch != 0) {
                    printf("Notice: switching method already given\n");
                    break;
                }
                G.chswitch = atoi(optarg);
                break;

            case 'u':

                G.update_s = atoi(optarg);

                /* If failed to parse or value <= 0, use default, 100ms */
                if (G.update_s <= 0)
                	G.update_s = REFRESH_RATE;

                break;

            case 'm':

                if ( memcmp(G.f_netmask, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: netmask already given\n");
                    break;
                }
                if(getmac(optarg, 1, G.f_netmask) != 0)
                {
                    printf("Notice: invalid netmask\n");
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'd':

                if ( memcmp(G.f_bssid, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: bssid already given\n");
                    break;
                }
                if(getmac(optarg, 1, G.f_bssid) != 0)
                {
                    printf("Notice: invalid bssid\n");
		    		printf("\"%s --help\" for help.\n", argv[0]);

                    return( 1 );
                }
                break;

            case 't':

                set_encryption_filter(optarg);
                break;

            case 'H':

  	            printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
  	            return( 1 );

            default : goto usage;
        }
    } while ( 1 );

    if( argc - optind != 1 )
    {
        if(argc == 1)
        {
usage:
            printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
        }
	    if( argc - optind == 0)
	    {
	    	printf("No interface specified.\n");
	    }
	    if(argc > 1)
	    {
    		printf("\"%s --help\" for help.\n", argv[0]);
	    }
        return( 1 );
    }

    if( ( memcmp(G.f_netmask, NULL_MAC, 6) != 0 ) && ( memcmp(G.f_bssid, NULL_MAC, 6) == 0 ) )
    {
        printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
   		printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if ( ivs_only && !G.record_data ) {
        printf( "Missing dump prefix (-w)\n" );
   		printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    /* Check if we have root privileges */

    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }

#if defined(linux)
    /* Check iwpriv existence */

	G.iwpriv = wiToolsPath("iwpriv");

	/* Check iwpriv existence */
	G.iwconfig = wiToolsPath("iwconfig");

	/* Try to find wlanctl-ng in case that's a wlan-ng driver */
    G.wlanctlng = wiToolsPath("wlanctl-ng");

    if (! (G.iwpriv && G.iwconfig) )
    {
        fprintf(stderr, "Can't find wireless tools, exiting.\n");
        return (1);
    }
#endif /* linux */

    cards = get_if_num(argv[argc-1]);

    /* create the raw socket and drop privileges */

#if defined(linux)
    for(i=0; i<cards; i++)
    {
        fd_raw[i] = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) );

        if( fd_raw[i] < 0 )
        {
            perror( "socket(PF_PACKET) failed" );
            if( getuid() != 0 )
                fprintf( stderr, "This program requires root privileges.\n" );
            return( 1 );
        }
            if( fd_raw[i] > fdh)
                fdh=fd_raw[i];
    }

    setuid( getuid() );

    /* reserve the buffer space */

    if( ( buffer = (unsigned char *) malloc( 65536 ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    /*
	since under FreeBSD the socktype PF_PACKET is not available
	we have to read our frames from a BPF, with a few consequences
	you'll find later on
    */
    for( i = 0; i < cards; i++ )
    {
	for( j = 0; j < 256; j++ )
	{
	    if( asprintf( &bnbuf, "/dev/bpf%d", j ) <= 0 )
	    {
		perror( "asprintf() failed" );
		exit( 1 );
	    }

	    fd_raw[i] = open( bnbuf, O_RDWR );

	    if( fd_raw[i] < 0 )
	    {
		if( errno != EBUSY )
		{
		    perror( "can't open /dev/bpf" );
		    exit( 1 );
		}
		continue;
	    }

	    free( bnbuf );
	    break;
        }

	if( fd_raw[i] < 0 )
	{
	    perror( "can't open /dev/bpf" );
	    exit( 1);
	}

	if( fd_raw[i] > fdh )
	    fdh = fd_raw[i];

	/*
	    the BPF buffer size must be the same we pass to the
	    read syscall.  we try to get our BPF to accomodate the
            largest useful buffer size *it* wants.
	*/
	for( buf = 65536 ; buf > 4096 ; buf -= 512 )
	{
	    ioctl( fd_raw[i], BIOCSBLEN, &buf );

	    if( buf > 0 )
	    {
		buflen = buf;
		break;
	    }
	}

	/* this is a real problem */
	if( buflen <= 0 )
	{
	    perror( "cannot allocate bpf buffer space" );
	    exit(1);
	}

    }

    setuid( getuid() );

    if( ( buffer = (unsigned char *) malloc( buflen ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }
#endif /* __FreeBSD__ */

    /* initialize cards */
#if defined(linux)
    cards = init_cards(argv[argc-1], iface, ifr, mr, sll, fd_raw, arptype);
#elif defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
    cards = init_cards(argv[argc-1], iface, ifr, fd_raw);
#endif

    if(cards <= 0)
	return( 1 );

    chan_count = getchancount(0);

    /* find the interface index */
    /* start a child to hop between channels */

    if( G.channel[0] == 0 )
    {
		unused = pipe( G.ch_pipe );
		unused = pipe( G.cd_pipe );

		signal( SIGUSR1, sighandler );

		if( ! fork() )
		{
#if defined(linux)
            channel_hopper( iface, fd_raw, cards, chan_count );
#elif defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
            channel_hopper( iface, cards, chan_count );
#endif
            exit( 1 );
        }
    }
    else
    {
		for( i=0; i<cards; i++ )
		{
#if defined(linux)
            set_channel( iface[i], fd_raw[i], G.channel[0], i );
#elif defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
            set_channel( iface[i], G.channel[0] );
#endif

	    	G.channel[i] = G.channel[0];
		}
        G.singlechan = 1;
    }

    /* open or create the output files */

    if (G.record_data)
    	if( dump_initialize( G.dump_prefix, ivs_only ) )
    	    return( 1 );

    signal( SIGINT,   sighandler );
    signal( SIGSEGV,  sighandler );
    signal( SIGTERM,  sighandler );
    signal( SIGWINCH, sighandler );

    sighandler( SIGWINCH );

    /* start the GPS tracker */

    if (G.usegpsd)
    {
        unused = pipe( G.gc_pipe );
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
    gettimeofday( &tv3, NULL );

    G.batt     = getBatteryString();

    G.elapsed_time = (char *) calloc( 1, 4 );
    strcpy(G.elapsed_time,"0 s");

    while( 1 )
    {
        if( G.do_exit )
        {
            break;
        }

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

        gettimeofday( &tv1, NULL );

        cycle_time = 1000000 * ( tv1.tv_sec  - tv3.tv_sec  )
                             + ( tv1.tv_usec - tv3.tv_usec );

        if( cycle_time > 500000 )
        {
            gettimeofday( &tv3, NULL );
            update_rx_quality( );
        }

        /* capture one packet */

        FD_ZERO( &rfds );
        for(i=0; i<cards; i++)
        {
            FD_SET( fd_raw[i], &rfds );
        }

        tv0.tv_sec  = G.update_s;
        tv0.tv_usec = (G.update_s == 0) ? REFRESH_RATE : 0;

        gettimeofday( &tv1, NULL );

        if( select( fdh + 1, &rfds, NULL, NULL, &tv0 ) < 0 )
        {
            if( errno == EINTR )
            {
                gettimeofday( &tv2, NULL );

                time_slept += 1000000 * ( tv2.tv_sec  - tv1.tv_sec  )
                                      + ( tv2.tv_usec - tv1.tv_usec );

                continue;
            }
            perror( "select failed" );

            /* Restore terminal */
            fprintf( stderr, "\33[?25h" );
    		fflush( stdout );

            return( 1 );
        }

        gettimeofday( &tv2, NULL );

        time_slept += 1000000 * ( tv2.tv_sec  - tv1.tv_sec  )
                              + ( tv2.tv_usec - tv1.tv_usec );

        if( time_slept > REFRESH_RATE && time_slept > G.update_s * 1000000)
        {
            time_slept = 0;

            update_dataps();

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
            dump_print( ws.ws_row, ws.ws_col, cards );
            fprintf( stderr, "\33[J" );
            fflush( stdout );
            continue;
        }

        fd_is_set = 0;

        for(i=0; i<cards; i++)
        {
            if( FD_ISSET( fd_raw[i], &rfds ) )
            {

#if defined(linux)
                memset( buffer, 0, 4096 );

                if( ( caplen = read( fd_raw[i], buffer, 65535 ) ) < 0 )
                {
                    perror( "read failed" );
                    /* Restore terminal */
                    fprintf( stderr, "\33[?25h" );
    				fflush( stdout );

                    return( 1 );
                }
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
                memset( buffer, 0, buflen );

		/* buffer size have to be as big as BPF buffer */
                if( ( caplen = read(  fd_raw[i], buffer, buflen ) ) < 0 )
                {
                    perror( "read failed" );
					/* Restore terminal */
                    fprintf( stderr, "\33[?25h" );
    				fflush( stdout );

                    return( 1 );
                }
#endif /* __FreeBSD__ */

#if defined(linux)
                /* if device is an atheros, remove the FCS */

                if( ! memcmp( iface[i], "ath", 3 ) && (! G.is_madwifing[i]) )
                    caplen -= 4;

                /* prism (wlan-ng) header parsing */

                h80211 = buffer;

                if( arptype[i] == ARPHRD_IEEE80211_PRISM )
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

                        if( ! memcmp( iface[i], "ath", 3 ) )
                            power -= *(int *)( buffer + 0x68 );

                        n = *(int *)( buffer + 4 );
                    }

                    if( n <= 0 || n >= caplen )
                        continue;

                    h80211 += n;
                    caplen -= n;
                }

                /* radiotap header parsing */

                if( arptype[i] == ARPHRD_IEEE80211_FULL )
                {
                    if( buffer[0] != 0 )
                    {
//                        fprintf( stderr, "Wrong radiotap header version.\n" );
//                        return( 1 );
                        continue;
                    }

                    n = le16_to_cpu(*(uint16_t *)( buffer + 2 ));

                    /* ipw2200 1.0.7 */
                    if( le32_to_cpu(*(uint32_t *)( buffer + 4 )) == 0x0000082E )
                        power = buffer[14];

                    /* ipw2200 1.2.0 */
                    if( le32_to_cpu(*(uint32_t *)( buffer + 4 )) == 0x0000086F )
                        power = buffer[15];

                    /* zd1211rw-patched */
                    if(G.is_zd1211rw[i] &&
                       le32_to_cpu(*(uint32_t *)( buffer + 4 )) == 0x0000006E )
                        power = buffer[14];

                    if( n <= 0 || n >= caplen )
                        continue;

                    h80211 += n;
                    caplen -= n;
                }
#endif /* linux */

#if defined(__FreeBSD__) || defined( __FreeBSD_kernel__)
		/*
		    radiotap under FreeBSD is well defined and decently
		    supported from any driver that actually can support
		    monitor mode, so we need no trick on pointer mechs
		    for different drivers
		*/
		h80211 = buffer;

		/*
		    since we're reading from a BPF with a datalink type
		    of IEEE802_11_RADIO, our readed frame will start with
		    a variable size BPF header (struct bpf_hdr) and a
		    variable size radiotap header.
		    we need to know their lenght to pass a clean 802.11
		    frame to dump_add_packet()
		*/
		bpfp = (struct bpf_hdr *)buffer;
		rtp = (struct ieee80211_radiotap_header *)(buffer + bpfp->bh_hdrlen);

		/*
		    radiotap header parsing stuff
		    we walk thru every possible field of the base set of
		    radiotap informations, looking for what we need,
		    specifically the flags map and the power levels
		*/

		/* position our pointer to the end of it_present field */
		r = (unsigned char *)&rtp->it_present;
		r += sizeof(u_int32_t);

		for( k = 0; k <= 13 ; k++ )
		{
		    if( le32_to_cpu(rtp->it_present) & ( 1 << k ) )
		    {
			switch( k )
			{
			  case IEEE80211_RADIOTAP_TSFT:

			    /* we have no use for this, let's skip over */
			    r += sizeof(u_int64_t);
			    break;

			  case IEEE80211_RADIOTAP_FLAGS:

			    if( *r & IEEE80211_RADIOTAP_F_FCS )
			    {
				/*
				    this frame has 4 FCS bytes at
				    his end, and we need to avoid them
				*/
				caplen -= 4;
			    }
			    r += sizeof( u_int8_t ); /* and go on.. */
			    break;

			  case IEEE80211_RADIOTAP_RATE:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int8_t );
			    break;

			  case IEEE80211_RADIOTAP_CHANNEL:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int16_t ) * 2;
			    break;

			  case IEEE80211_RADIOTAP_FHSS:

			    /* we have no use for this, let's skip over */
			    r += sizeof(u_int16_t);
			    break;

			  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:

			    /* we could like this field... mhmhm! */
			    memcpy( &power, r, sizeof( int8_t ) );
			    r += sizeof( int8_t ); /* and go on.. */
			    break;

			  case IEEE80211_RADIOTAP_DBM_ANTNOISE:

			    /* we have no use for this, let's skip over */
			    r += sizeof( int8_t );
			    break;

			  case IEEE80211_RADIOTAP_LOCK_QUALITY:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int16_t );
			    break;

			  case IEEE80211_RADIOTAP_TX_ATTENUATION:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int16_t );
			    break;

			  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int16_t );
			    break;

			  case IEEE80211_RADIOTAP_DBM_TX_POWER:

			    /* we have no use for this, let's skip over */
			    r += sizeof( int8_t );
			    break;

			  case IEEE80211_RADIOTAP_ANTENNA:

			    /* we have no use for this, let's skip over */
			    r += sizeof( u_int8_t );
			    break;

			  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:

			    /* we could like this field... mhmhm! */
			    power = (int) *r;
			    r += sizeof( u_int8_t ); /* and go on.. */
			    break;

			  case IEEE80211_RADIOTAP_DB_ANTNOISE:

			    /* we have no use for this, let's skip over */
			    r += sizeof(u_int8_t);
			    break;

			  default:
			    break;
		    }
		}
	    }

	    /*
		n is the offset of the real frame from the beginning
		of the capture (bpf header lenght + radiotap header
		lenght)
	    */
	    n = bpfp->bh_hdrlen + le16_to_cpu(rtp->it_len);

	    if( n <= 0 || n >= caplen )
		continue;

	    h80211 += n;
	    caplen -= n;
#endif /* __FreeBSD__ */

                dump_add_packet( h80211, caplen, power, i );
			}
		}
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
