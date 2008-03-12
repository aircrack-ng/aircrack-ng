/*
 *  802.11 WEP network connection tunneling
 *  based on aireplay-ng
 *
 *  Copyright (C) 2006, 2007, 2008 Thomas d'Otreppe
 *  Copyright (C) 2006, 2007, 2008 Martin Beck
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
"  usage: airtun-ng <options> <replay interface>\n"
"\n"
"      -x nbpps         : number of packets per second (default: 100)\n"
"      -a bssid         : set Access Point MAC address\n"
"      -i iface         : capture packets from this interface\n"
"      -y file          : read PRGA from this file\n"
"      -w wepkey        : use this WEP-KEY to encrypt packets\n"
"      -t tods          : send frames to AP (1) or to client (0)\n"
"      -r file          : read frames out of pcap file\n"
"\n"
"  Repeater options:\n"
"      --repeat         : activates repeat mode\n"
"      --bssid <mac>    : BSSID to repeat\n"
"      --netmask <mask> : netmask for BSSID filter\n"
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

    int repeat;
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

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
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

int packet_recv(uchar* packet, int length)
{
    uchar K[64];
    uchar bssid[6];

    int z;

    z = ( ( packet[1] & 3 ) != 3 ) ? 24 : 30;

    if(length < z+8)
    {
        return 1;
    }

    switch( packet[1] & 3 )
    {
        case  0: memcpy( bssid, packet + 16, 6 ); break;
        case  1: memcpy( bssid, packet +  4, 6 ); break;
        case  2: memcpy( bssid, packet + 10, 6 ); break;
        default: memcpy( bssid, packet + 10, 6 ); break;
    }

    if( memcmp( bssid, opt.r_bssid, 6) == 0 && ( packet[0] & 0x08 ) == 0x08 )
    {
        if( (packet[z] != packet[z + 1] || packet[z + 2] != 0x03) && opt.crypt == CRYPT_WEP )
        {
            /* check the extended IV flag */

            if( ( packet[z + 3] & 0x20 ) == 0 )
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
        }

        switch( packet[1] & 3 )
        {
            case 1:
                memcpy( h80211,   packet+16, 6);  //DST_MAC
                memcpy( h80211+6, packet+10, 6);  //SRC_MAC
                break;
            case 2:
                memcpy( h80211,   packet+4 , 6);  //DST_MAC
                memcpy( h80211+6, packet+16, 6);  //SRC_MAC
                break;
            case 3:
                memcpy( h80211,   packet+16, 6);  //DST_MAC
                memcpy( h80211+6, packet+10, 6);  //SRC_MAC
                break;
            default: break;
        }

        memcpy( h80211+12, packet+z+6, 2);  //copy ether type

        if( length <= z+8 )
            return 1;

        memcpy( h80211+14, packet+z+8, length-z-8);
        length = length -z-8+14;

	ti_write(dev.dv_ti, h80211, length);
    }
    else
    {
        return 1;
    }

    return 0;
}

int main( int argc, char *argv[] )
{
    int ret_val, len, i, n, ret;
    struct pcap_pkthdr pkh;
    fd_set read_fds;
    unsigned char buffer[4096];
    unsigned char bssid[6];
    char *s, buf[128];
    int caplen;

    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );

    opt.r_nbpps = 100;
    opt.tods    = 0;

    srand( time( NULL ) );

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"netmask", 1, 0, 'm'},
            {"bssid",   1, 0, 'd'},
            {"repeat",  0, 0, 'f'},
            {"help",  0, 0, 'H'},
            {0,         0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "x:a:h:i:r:y:t:w:m:d:fH",
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
                break;

            case 'h' :

                if( getmac( optarg, 1, opt.r_smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'y' :

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
                if( read_prga(&(opt.prga), optarg) != 0 )
                {
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

            case 't' :

                if( atoi(optarg) ) opt.tods = 1;
                else opt.tods = 0;
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
            case 'f':
                opt.repeat = 1;
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

            	printf( usage, getVersion("Airtun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA)  );
            	return( 1 );

            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
    	if(argc == 1)
    	{
usage:
	        printf( usage, getVersion("Airtun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA)  );
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

    if( memcmp( opt.r_bssid, NULL_MAC, 6) == 0 )
    {
        printf( "Please specify a BSSID (-a).\n" );
   		printf("\"%s --help\" for help.\n", argv[0]);
        return 1;
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

    if(opt.prgalen <= 0 && opt.crypt == CRYPT_NONE)
    {
        printf( "No encryption specified. Sending and receiving frames through %s.\n", argv[optind]);
    }
    else if(opt.crypt != CRYPT_NONE)
    {
        printf( "WEP encryption specified. Sending and receiving frames through %s.\n", argv[optind] );
    }
    else
    {
        printf( "WEP encryption by PRGA specified. No reception, only sending frames through %s.\n", argv[optind] );
    }

    if( opt.tods )
    {
        printf( "ToDS bit set in all frames.\n" );
    }
    else
    {
        printf( "FromDS bit set in all frames.\n" );
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

            if( opt.repeat )
            {
                if( memcmp(opt.f_bssid, NULL_MAC, 6) != 0 )
                {
                    switch( h80211[1] & 3 )
                    {
                        case  0: memcpy( bssid, h80211 + 16, 6 ); break;
                        case  1: memcpy( bssid, h80211 +  4, 6 ); break;
                        case  2: memcpy( bssid, h80211 + 10, 6 ); break;
                        default: memcpy( bssid, h80211 + 10, 6 ); break;
                    }
                    if( memcmp(opt.f_netmask, NULL_MAC, 6) != 0 )
                    {
                        if(is_filtered_netmask(bssid)) continue;
                    }
                    else
                    {
                        if( memcmp(opt.f_bssid, bssid, 6) != 0 ) continue;
                    }
                }
                send_packet(h80211, caplen);
            }


            packet_recv( h80211, caplen);
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
                    packet_recv( buffer, len);
                }
            }
        } //if( ret_val > 0 )
    } //for( ; ; )

    ti_close( dev.dv_ti );


    /* that's all, folks */

    return( 0 );
}
