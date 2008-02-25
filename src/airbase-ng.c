/*
 *  802.11 monitor AP
 *  based on airtun-ng
 *
 *  Copyright (C) 2008 Thomas d'Otreppe
 *  Copyright (C) 2008 Martin Beck
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

#include <fcntl.h>

#include "version.h"
#include "pcap.h"
#include "crypto.h"

#include "osdep/osdep.h"

static struct wif *_wi_in, *_wi_out;

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define CRYPT_NONE 0
#define CRYPT_WEP  1

#ifndef MAX
#define MAX(x,y) ( (x)>(y) ? (x) : (y) )
#endif

#define RTC_RESOLUTION  1024

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

#define PROBE_RSP       \
    "\x50\x00\x3a\x01\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta);
extern char * searchInside(const char * dir, const char * filename);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int check_crc_buf( unsigned char *buf, int len );
extern int add_crc32(unsigned char* data, int length);

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];


char usage[] =
"\n"
"  %s - (C) 2006,2007,2008 Thomas d'Otreppe\n"
"  Original work: Christophe Devine and Martin Beck\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: airbase-ng <options> <replay interface>\n"
"\n"
// "      -x nbpps         : number of packets per second (default: 100)\n"
"      -a bssid         : set Access Point MAC address\n"
"      -i iface         : capture packets from this interface\n"
// "      -y file          : read PRGA from this file\n"
"      -w wepkey        : use this WEP-KEY to en-/decrypt packets\n"
// "      -t tods          : send frames to AP (1) or to client (0)\n"
// "      -r file          : read frames out of pcap file\n"
"      -q               : quiet (do not print statistics)\n"
"\n"
"  Filter options:\n"
// "      --bssid <mac>    : BSSID to repeat\n"
// "      --netmask <mask> : netmask for BSSID filter\n"
"      --essids <file>  : read list of ESSIDs out of that file\n"
"      --essid <ESSID>  : uses a single ESSID\n"
"\n"
"      --help           : Displays this usage screen\n"
"\n";

struct options
{
    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];

    unsigned char f_bssid[6];
    unsigned char f_netmask[6];

    char *s_face;
    char *s_file;
    uchar *prga;

    int r_nbpps;
    int prgalen;
    int tods;

    uchar wepkey[64];
    int weplen, crypt;

    int f_essid;
    int channel;
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;
    struct tif *dv_ti;

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
};

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

int ctrl_c, alarmed;

char * iwpriv;

pthread_t apid;

pESSID_t rESSID;

void sighandler( int signum )
{
    if( signum == SIGINT )
        ctrl_c++;

    if( signum == SIGALRM )
        alarmed++;
}

int addESSID(char* essid, int len)
{
    pESSID_t cur = rESSID;

    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    if(rESSID == NULL)
        return -1;

    while(cur->next != NULL)
        cur = cur->next;

    //alloc mem
    cur->next = (pESSID_t) malloc(sizeof(struct ESSID_list));
    cur = cur->next;

    //set essid
    cur->essid = (char*) malloc(len+1);
    memcpy(cur->essid, essid, len);
    cur->essid[len] = 0x00;
    cur->len = len;

    cur->next = NULL;

    return 0;
}

int delESSID(char* essid, int len)
{
    pESSID_t old, cur = rESSID;

    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    if(rESSID == NULL)
        return -1;

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
                return 0;
            }
        }
        cur = cur->next;
    }

    return -1;
}

int gotESSID(char* essid, int len)
{
    pESSID_t old, cur = rESSID;

    if(essid == NULL)
        return -1;

    if(len <= 0 || len > 255)
        return -1;

    if(rESSID == NULL)
        return -1;

    while(cur->next != NULL)
    {
        old = cur->next;
        if(old->len == len)
        {
            if(memcmp(old->essid, essid, len) == 0)
            {
                return 1;
            }
        }
        cur = cur->next;
    }

    return 0;
}

char* getESSID(int *len)
{
    if(rESSID == NULL)
        return NULL;

    if(rESSID->next == NULL)
        return NULL;

    *len = rESSID->next->len;

    return rESSID->next->essid;
}

int getESSIDcount()
{
    pESSID_t cur = rESSID;
    int count=0;

    if(rESSID == NULL)
        return -1;

    while(cur->next != NULL)
    {
        cur = cur->next;
        count++;
    }

    return count;
}

int addESSIDfile(char* filename)
{
    FILE *list;
    char essid[256];

    list = fopen(filename, "r");
    if(list == NULL)
    {
        perror("Unable to open ESSID list");
        return -1;
    }

    while( fgets(essid, 256, list) != NULL )
    {
        addESSID(essid, strlen(essid));
    }

    fclose(list);

    return 0;
}

int is_filtered_netmask(uchar *bssid)
{
    uchar mac1[6];
    uchar mac2[6];
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

#define PCT { struct tm *lt; time_t tc = time( NULL ); \
              lt = localtime( &tc ); printf( "%02d:%02d:%02d  ", \
              lt->tm_hour, lt->tm_min, lt->tm_sec ); }

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

void print_packet ( uchar h80211[], int caplen )
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
    if(packet == NULL) return 1;

    if(opt.prga == NULL)
    {
        printf("Please specify a PRGA file (-y).\n");
        return 1;
    }

    /* insert IV+index */
    memcpy(packet+24, opt.prga, 4);

    return 0;
}

int encrypt_data(unsigned char *dest, unsigned char* data, int length)
{
    unsigned char cipher[2048];
    int n;

    if(dest == NULL)                return 1;
    if(data == NULL)                return 1;
    if(length < 1 || length > 2044) return 1;

    if(opt.prga == NULL)
    {
        printf("Please specify a PRGA file (-y).\n");
        return 1;
    }

    if(opt.prgalen-4 < length)
    {
        printf("Please specify a longer PRGA file (-y) with at least %i bytes.\n", (length+4));
        return 1;
    }

    /* encrypt data */
    for(n=0; n<length; n++)
    {
        cipher[n] = (data[n] ^ opt.prga[4+n]) & 0xFF;
    }

    memcpy(dest, cipher, length);

    return 0;
}

int create_wep_packet(unsigned char* packet, int *length)
{
    if(packet == NULL) return 1;

    /* write crc32 value behind data */
    if( add_crc32(packet+24, *length-24) != 0 )               return 1;

    /* encrypt data+crc32 and keep a 4byte hole */
    if( encrypt_data(packet+28, packet+24, *length-20) != 0 ) return 1;

    /* write IV+IDX right in front of the encrypted data */
    if( set_IVidx(packet) != 0 )                              return 1;

    /* set WEP bit */
    packet[1] = packet[1] | 0x40;

    *length+=8;
    /* now you got yourself a shiny, brand new encrypted wep packet ;) */

    return 0;
}

int packet_xmit(uchar* packet, int length)
{
    uchar K[64];
    uchar buf[4096];

    memcpy(h80211, IEEE80211_LLC_SNAP, 32);
    memcpy(h80211+32, packet+14, length-14);
    memcpy(h80211+30, packet+12, 2);

    if(opt.tods)
    {
        h80211[1] |= 0x01;
        memcpy(h80211+4,  opt.r_bssid, 6);  //BSSID
        memcpy(h80211+10, packet+6,    6);  //SRC_MAC
        memcpy(h80211+16, packet,      6);  //DST_MAC
    }
    else
    {
        h80211[1] |= 0x02;
        memcpy(h80211+10, opt.r_bssid, 6);  //BSSID
        memcpy(h80211+16, packet+6,    6);  //SRC_MAC
        memcpy(h80211+4,  packet,      6);  //DST_MAC
    }

    length = length+32-14; //32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE

    if( opt.crypt == CRYPT_WEP)
    {
        K[0] = rand() & 0xFF;
        K[1] = rand() & 0xFF;
        K[2] = rand() & 0xFF;
        K[3] = 0x00;

        /* write crc32 value behind data */
        if( add_crc32(h80211+24, length-24) != 0 ) return 1;

        length += 4; //icv
        memcpy(buf, h80211+24, length-24);
        memcpy(h80211+28, buf, length-24);

        memcpy(h80211+24, K, 4);
        length += 4; //iv

        memcpy( K + 3, opt.wepkey, opt.weplen );

        encrypt_wep( h80211+24+4, length-24-4, K, opt.weplen+3 );

        h80211[1] = h80211[1] | 0x40;
    }
    else if( opt.prgalen > 0 )
    {
        if(create_wep_packet(h80211, &length) != 0) return 1;
    }

    send_packet(h80211, length);

    return 0;
}

uchar* parse_tags(unsigned char *flags, unsigned char type, int length, int *taglen)
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

int packet_recv(uchar* packet, int length, struct AP_conf *apc)
{
    uchar K[64];
    uchar bssid[6];
    uchar smac[6];
    uchar dmac[6];
    int trailer=0;
    uchar *tag=NULL;
    int len, i;
    uchar *buffer;
    struct timeval tv1;
    u_int64_t timestamp;
    char *fessid;

    int z;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z)
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

    /* Got a data packet with our bssid set and ToDS==1*/
    if( memcmp( bssid, opt.r_bssid, 6) == 0 && ( packet[0] & 0x08 ) == 0x08 && (packet[1] & 0x03) == 0x01 )
    {
        /* To our mac? */
        if( memcmp( dmac, opt.r_bssid, 6) == 0 )
        {
            /* Is encrypted */
            if( (packet[z] != packet[z + 1] || packet[z + 2] != 0x03) && (packet[1] & 0x40) == 0x40 )
            {
                /* check the extended IV flag */
                /* WEP and we got the key */
                if( ( packet[z + 3] & 0x20 ) == 0 && opt.crypt == CRYPT_WEP )
                {
                    memcpy( K, packet + z, 3 );
                    memcpy( K + 3, opt.wepkey, opt.weplen );

                    if (decrypt_wep( packet + z + 4, length - z - 4,
                                    K, 3 + opt.weplen ) == 0 )
                    {
                        printf("ICV check failed!\n");
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
                    /* its a packet for us, but we either don't have the key or its WPA -> throw it away */
                    return 0;
                }
            }
            else
            {
                /* unencrypted data packet, nothing special, send it through dev_ti */
            }
        }
        else
        {
            /* Our bssid, ToDS=1, but to a different destination MAC -> send it through both interfaces */
            packet[1] &= 0xFC; //clear ToDS/FromDS
            packet[1] |= 0x02; //set FromDS=1
            memcpy(packet +  4, dmac, 6);
            memcpy(packet + 10, bssid, 6);
            memcpy(packet + 16, smac, 6);

            send_packet(h80211, length);

            /* Is encrypted */
            if( (packet[z] != packet[z + 1] || packet[z + 2] != 0x03) && (packet[1] & 0x40) == 0x40 )
            {
                /* check the extended IV flag */
                /* WEP and we got the key */
                if( ( packet[z + 3] & 0x20 ) == 0 && opt.crypt == CRYPT_WEP )
                {
                    memcpy( K, packet + z, 3 );
                    memcpy( K + 3, opt.wepkey, opt.weplen );

                    if (decrypt_wep( packet + z + 4, length - z - 4,
                                    K, 3 + opt.weplen ) == 0 )
                    {
                        printf("ICV check failed!\n");
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
                    /* its a packet we can't decrypt -> just replay it through the wireless interface */
                    return 0;
                }
            }

        }

        memcpy( h80211,   dmac, 6);  //DST_MAC
        memcpy( h80211+6, smac, 6);  //SRC_MAC

        memcpy( h80211+12, packet+z+6, 2);  //copy ether type

        if( length <= z+8 )
            return 1;

        memcpy( h80211+14, packet+z+8, length-z-8);
        length = length -z-8+14;

        //ethernet frame must be atleast 60 bytes without fcs
        if(length < 60)
        {
            trailer = 60 - length;
            bzero(h80211 + length, trailer);
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
            if(tag != NULL && tag[0] >= 32 && tag[0] < 127)
            {
                if( !opt.f_essid || gotESSID((char*)tag, len) == 1)
                {
                    //transform into probe response
                    packet[0] = 0x50;

                    //store the tagged parameters and insert the fixed ones
                    buffer = (uchar*) malloc(length-z);
                    memcpy(buffer, packet+z, length-z);

                    memcpy(packet+z, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information
                    packet[z+8] = (apc->interval) & 0xFF;       //beacon interval
                    packet[z+9] = (apc->interval >> 8) & 0xFF;
                    memcpy(packet+z+10, apc->capa, 2);          //capability

                    //set timestamp
                    gettimeofday( &tv1,  NULL );
                    timestamp=tv1.tv_sec*1000000 + tv1.tv_usec;

                    //copy timestamp into response; a mod 2^64 counter incremented each microsecond
                    for(i=0; i<8; i++)
                    {
                        packet[z+i] = ( timestamp >> (i*8) ) & 0xFF;
                    }

                    //insert tagged parameters
                    memcpy(packet+z+12, buffer, length-z);
                    length += 12;
                    free(buffer);

                    //add channel
                    packet[length]   = 0x03;
                    packet[length+1] = 0x01;
                    packet[length+2] = wi_get_channel(_wi_in);

                    length += 3;

                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, opt.r_bssid, 6);
                    memcpy(packet + 16, opt.r_bssid, 6);

                    send_packet(packet, length);
                    return 0;
                }
            }
            else
            {
                if(!opt.f_essid)
                {
                    //transform into probe response
                    packet[0] = 0x50;

                    //store the tagged parameters and insert the fixed ones
                    buffer = (uchar*) malloc(length-z);
                    memcpy(buffer, packet+z, length-z);

                    memcpy(packet+z, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information
                    packet[z+8] = (apc->interval) & 0xFF;       //beacon interval
                    packet[z+9] = (apc->interval >> 8) & 0xFF;
                    memcpy(packet+z+10, apc->capa, 2);          //capability

                    //set timestamp
                    gettimeofday( &tv1,  NULL );
                    timestamp=tv1.tv_sec*1000000 + tv1.tv_usec;

                    //copy timestamp into response; a mod 2^64 counter incremented each microsecond
                    for(i=0; i<8; i++)
                    {
                        packet[z+i] = ( timestamp >> (i*8) ) & 0xFF;
                    }

                    //insert essid
                    fessid = getESSID(&len);
                    if(fessid == NULL)
                    {
                        fessid = "default";
                        len = strlen(fessid);
                    }
                    packet[z+12] = 0x00;
                    packet[z+13] = len;
                    memcpy(packet+z+14, fessid, len);

                    //insert tagged parameters
                    memcpy(packet+z+14+len, buffer, length-z); //now we got 2 essid tags... ignore that

                    length += 12; //fixed info
                    free(buffer);
                    length += 2+len; //default essid

                    //add channel
                    packet[length]   = 0x03;
                    packet[length+1] = 0x01;
                    packet[length+2] = wi_get_channel(_wi_in);

                    length += 3;

                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, opt.r_bssid, 6);
                    memcpy(packet + 16, opt.r_bssid, 6);

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
                memcpy(packet +  4, smac, 6);
                memcpy(packet + 10, dmac, 6);
                packet[z+2] = 0x02;
                send_packet(packet, length);
                return 0;
            }
            else //shared key auth
            {
                //first response
                if(packet[z+2] == 0x01 && (packet[1] & 0x40) == 0x00 )
                {
                    memcpy(packet +  4, smac, 6);
                    memcpy(packet + 10, dmac, 6);
                    packet[z+2] = 0x02;

                    //add challenge
                    packet[length] = 0x10;
                    packet[length+1] = 0x80;
                    length += 2;

                    for(i=0; i<128; i++)
                    {
                        packet[length+i] = rand() & 0xFF;
                    }

                    length += 128;
                    send_packet(packet, length);
                    return 0;
                }

                //second response
                if( (packet[1] & 0x40) == 0x40 )
                {
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
                }
            }
        }

        //asso req
        if(packet[0] == 0x00 && memcmp( bssid, opt.r_bssid, 6) == 0 )
        {
            packet[0] = 0x10;
            memcpy(packet +  4, smac, 6);
            memcpy(packet + 10, dmac, 6);

            //store the tagged parameters and insert the fixed ones
            buffer = (uchar*) malloc(length-z-4);
            memcpy(buffer, packet+z+4, length-z-4);

            packet[z+2] = 0x00;
            packet[z+3] = 0x00;
            packet[z+4] = 0x01;
            packet[z+5] = 0xC0;

            memcpy(packet+z+6, buffer, length-z-4);
            length +=2;
            free(buffer);

            send_packet(packet, length);
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
    float f, ticks[3];

    memcpy(&apc, arg, sizeof(struct AP_conf));

    memcpy(beacon, "\x80\x00\x00\x00", 4);  //type/subtype/framecontrol/duration
    beacon_len+=4;
    memcpy(beacon+beacon_len , BROADCAST, 6);        //destination
    beacon_len+=6;
    memcpy(beacon+beacon_len, apc.bssid, 6);        //source
    beacon_len+=6;
    memcpy(beacon+beacon_len, apc.bssid, 6);        //bssid
    beacon_len+=6;
    memcpy(beacon+beacon_len, "\x00\x00", 2);       //seq+frag
    beacon_len+=2;

    memcpy(beacon+beacon_len, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);  //fixed information
    beacon[beacon_len+8] = (apc.interval) & 0xFF;       //beacon interval
    beacon[beacon_len+9] = (apc.interval >> 8) & 0xFF;
    memcpy(beacon+beacon_len+10, apc.capa, 2);          //capability
    beacon_len+=12;

    beacon[beacon_len] = 0x00; //essid tag
    beacon[beacon_len+1] = apc.essid_len; //essid tag
    beacon_len+=2;
    memcpy(beacon+beacon_len, apc.essid, apc.essid_len); //actual essid
    beacon_len+=apc.essid_len;

    memcpy(beacon+beacon_len, RATES, 16); //rates+extended rates
    beacon_len+=16;

    beacon[beacon_len] = 0x03; //channel tag
    beacon[beacon_len+1] = 0x01;
    beacon[beacon_len+2] = wi_get_channel(_wi_in); //current channel
    beacon_len+=3;

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

            f = 1000000.0 * (float) ( tv2.tv_sec  - tv.tv_sec  )
                        + (float) ( tv2.tv_usec - tv.tv_usec );

            ticks[0] += f / ( 1000000/RTC_RESOLUTION );
            ticks[1] += f / ( 1000000/RTC_RESOLUTION );
            ticks[2] += f / ( 1000000/RTC_RESOLUTION );
        }

        if( ( (double)ticks[2] / (double)RTC_RESOLUTION )  >= ((double)apc.interval/1000.0)*(double)seq )
        {
            /* threshold reach, send one frame */
//            ticks[2] = 0;

            gettimeofday( &tv1,  NULL );
            timestamp=tv1.tv_sec*1000000 + tv1.tv_usec;

            //copy timestamp into beacon; a mod 2^64 counter incremented each microsecond
            for(i=0; i<8; i++)
            {
                beacon[24+i] = ( timestamp >> (i*8) ) & 0xFF;
            }

            beacon[22] = (seq << 4) & 0xFF;
            beacon[23] = (seq >> 4) & 0xFF;

            if( send_packet( beacon, beacon_len ) < 0 )
            {
                printf("Error sending beacon!\n");
                return;
            }

            seq++;
        }
    }
}

int main( int argc, char *argv[] )
{
    int ret_val, len, i, n;
    struct pcap_pkthdr pkh;
    fd_set read_fds;
    unsigned char buffer[4096];
//     unsigned char bssid[6];
    char *s, buf[128], *fessid;
    int caplen;
    struct AP_conf apc;

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );
    memset( &apc, 0, sizeof( struct AP_conf ));

    rESSID = (pESSID_t) malloc(sizeof(struct ESSID_list));
    rESSID->essid = NULL;
    rESSID->len = 0;
    rESSID->next = NULL;

    opt.r_nbpps = 100;
    opt.tods    = 0;


    srand( time( NULL ) );

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"netmask", 1, 0, 'm'},
            {"bssid",   1, 0, 'd'},
            {"essid",   0, 0, 'e'},
            {"essids",  0, 0, 'E'},
            {"help",    0, 0, 'H'},
            {0,         0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "a:h:i:r:t:w:m:d:He:E:c:",
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

/*            case 'x' :

                ret = sscanf( optarg, "%d", &opt.r_nbpps );
                if( opt.r_nbpps < 1 || opt.r_nbpps > 1024 || ret != 1 )
                {
                    printf( "Invalid number of packets per second. [1-1024]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;
*/
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

                break;

            case 'e' :

                if( addESSID(optarg, strlen(optarg)) != 0 )
                {
                    printf( "Invalid ESSID, too long\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.f_essid = 1;

                break;

            case 'E' :

                if( addESSIDfile(optarg) != 0 )
                {
                    printf( "Invalid ESSID, too long\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                opt.f_essid = 1;

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

            case 'm':
                if ( memcmp(opt.f_netmask, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: netmask already given\n");
                    printf("\"%s --help\" for help.\n", argv[0]);
                    break;
                }
                if(getmac(optarg, 1, opt.f_netmask) != 0)
                {
                    printf("Notice: invalid netmask\n");
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'd':
                if ( memcmp(opt.f_bssid, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: bssid already given\n");
                    printf("\"%s --help\" for help.\n", argv[0]);
                    break;
                }
                if(getmac(optarg, 1, opt.f_bssid) != 0)
                {
                    printf("Notice: invalid bssid\n");
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
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

                printf( usage, getVersion("Airbase-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA)  );
                return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
        if(argc == 1)
        {
usage:
            printf( usage, getVersion("Airbase-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA)  );
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

    setuid( getuid() );

    /* XXX */
    if( opt.r_nbpps == 0 )
    {
        if( dev.is_wlanng || dev.is_hostap )
            opt.r_nbpps = 200;
        else
            opt.r_nbpps = 500;
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

    dev.dv_ti = ti_open(NULL);
    if(!dev.dv_ti)
    {
        printf( "error opening tap device: %s\n", strerror( errno ) );
        return -1;
    }
    printf( "created tap interface %s\n", ti_name(dev.dv_ti));

//     if(opt.prgalen <= 0 && opt.crypt == CRYPT_NONE)
//     {
//         printf( "No encryption specified. Sending and receiving frames through %s.\n", argv[optind]);
//     }
//     else if(opt.crypt != CRYPT_NONE)
//     {
//         printf( "WEP encryption specified. Sending and receiving frames through %s.\n", argv[optind] );
//     }
//     else
//     {
//         printf( "WEP encryption by PRGA specified. No reception, only sending frames through %s.\n", argv[optind] );
//     }
//
    if(opt.channel > 0)
        wi_set_channel(_wi_out, opt.channel);

    if( memcmp( opt.r_bssid, NULL_MAC, 6) == 0 )
    {
        wi_get_mac( _wi_out, opt.r_bssid);
    }

    memcpy(apc.bssid, opt.r_bssid, 6);
    if( getESSIDcount() == 1 )
    {
        fessid = getESSID(&(apc.essid_len));
        apc.essid = (char*) malloc(apc.essid_len + 1);
        memcpy(apc.essid, fessid, apc.essid_len);
        apc.essid[apc.essid_len] = 0x00;
    }
    else
    {
        apc.essid = "\x00";
        apc.essid_len = 1;
    }
    apc.interval = 0x0064;
    apc.capa[0] = 0x01;
    if(opt.crypt == CRYPT_WEP)
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

    //start sending beacons
    if( pthread_create( &(apid), NULL, (void *) beacon_thread,
            (void *) &apc ) != 0 )
    {
        perror("pthread_create");
        return( 1 );
    }

    for( ; ; )
    {
        if(opt.s_file != NULL)
        {
            n = sizeof( pkh );

            if( fread( &pkh, n, 1, dev.f_cap_in ) != 1 )
            {
                printf("Finished reading input file %s.\n", opt.s_file);
                opt.s_file = NULL;
                continue;
            }

            if( dev.pfh_in.magic == TCPDUMP_CIGAM )
                SWAP32( pkh.caplen );

            n = caplen = pkh.caplen;

            if( n <= 0 || n > (int) sizeof( h80211 ) )
            {
                printf("Finished reading input file %s.\n", opt.s_file);
                opt.s_file = NULL;
                continue;
            }

            if( fread( h80211, n, 1, dev.f_cap_in ) != 1 )
            {
                printf("Finished reading input file %s.\n", opt.s_file);
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

//             if( opt.repeat )
//             {
//                 if( memcmp(opt.f_bssid, NULL_MAC, 6) != 0 )
//                 {
//                     switch( h80211[1] & 3 )
//                     {
//                         case  0: memcpy( bssid, h80211 + 16, 6 ); break;
//                         case  1: memcpy( bssid, h80211 +  4, 6 ); break;
//                         case  2: memcpy( bssid, h80211 + 10, 6 ); break;
//                         default: memcpy( bssid, h80211 + 10, 6 ); break;
//                     }
//                     if( memcmp(opt.f_netmask, NULL_MAC, 6) != 0 )
//                     {
//                         if(is_filtered_netmask(bssid)) continue;
//                     }
//                     else
//                     {
//                         if( memcmp(opt.f_bssid, bssid, 6) != 0 ) continue;
//                     }
//                 }
//                 send_packet(h80211, caplen);
//             }

            packet_recv( h80211, caplen, &apc);
            msleep( 1000/opt.r_nbpps );
            continue;
        }

        FD_ZERO( &read_fds );
        FD_SET( dev.fd_in, &read_fds );
        FD_SET(ti_fd(dev.dv_ti), &read_fds );
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
            if( FD_ISSET( dev.fd_in, &read_fds ) )
            {
                len = read_packet( buffer, sizeof( buffer ) );
                if( len > 0 )
                {
                    packet_recv( buffer, len, &apc);
                }
            }
        } //if( ret_val > 0 )
    } //for( ; ; )

    ti_close( dev.dv_ti );


    /* that's all, folks */

    return( 0 );
}
