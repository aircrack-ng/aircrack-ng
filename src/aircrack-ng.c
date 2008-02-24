/*
 *  802.11 WEP / WPA-PSK Key Cracker
 *
 *  Copyright (C) 2006,2007,2008 Thomas d'Otreppe
 *  Copyright (C) 2004,2005 Christophe Devine
 *
 *  Advanced WEP attacks developed by KoreK
 *  WPA-PSK  attack code developed by Joshua Wright
 *  SHA1 MMX assembly code written by Simon Marechal
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

#include <sys/types.h>
#include <sys/termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#include <err.h>

#include "version.h"
#include "crypto.h"
#ifdef WIN32
#include <Windows.h>
#include <airpcap.h>
#endif
#include "pcap.h"
#include "uniqueiv.c"
#include "aircrack-ptw-lib.h"
#include "aircrack-ng.h"

static uchar ZERO[32] =
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

/* stats global data */

struct timeval t_begin;			 /* time at start of attack      */
struct timeval t_stats;			 /* time since last update       */
struct timeval t_kprev;			 /* time at start of window      */
long long int nb_kprev;			 /* last  # of keys tried        */
long long int nb_tried;			 /* total # of keys tried        */

/* IPC global data */

struct AP_info *ap_1st;			 /* first item in linked list    */
pthread_mutex_t mx_ivb;			 /* lock access to ivbuf array   */
pthread_mutex_t mx_apl;			 /* lock write access to ap LL   */
pthread_mutex_t mx_eof;			 /* lock write access to nb_eof  */
pthread_cond_t  cv_eof;			 /* read EOF condition variable  */
int  nb_eof = 0;				 /* # of threads who reached eof */
long nb_pkt = 0;				 /* # of packets read so far     */
int mc_pipe[256][2];			 /* master->child control pipe   */
int cm_pipe[256][2];			 /* child->master results pipe   */
int bf_pipe[256][2];			 /* bruteforcer 'queue' pipe	*/
int bf_nkeys[256];
uchar bf_wepkey[64];
int wepkey_crack_success = 0;

typedef struct
{
	int off1;
	int off2;
	void *buf1;
	void *buf2;
}

read_buf;

int K_COEFF[N_ATTACKS] =
{
	15, 13, 12, 12, 12, 5, 5, 5, 3, 4, 3, 4, 3, 13, 4, 4, -20
};

const uchar R[256] =
{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
	, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40
	, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60
	, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80
	, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100
	, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116
	, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132
	, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148
	, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164
	, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180
	, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196
	, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212
	, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228
	, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244
	, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

char usage[] =
"\n"
"  %s - (C) 2006,2007,2008 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: aircrack-ng [options] <.cap / .ivs file(s)>\n"
"\n"
"  Common options:\n"
"\n"
"      -a <amode> : force attack mode (1/WEP, 2/WPA-PSK)\n"
"      -e <essid> : target selection: network identifier\n"
"      -b <bssid> : target selection: access point's MAC"
"%s"
"      -q         : enable quiet mode (no status output)\n"
"\n"
"  Static WEP cracking options:\n"
"\n"
"      -c         : search alpha-numeric characters only\n"
"      -t         : search binary coded decimal chr only\n"
"      -h         : search the numeric key for Fritz!BOX\n"
"      -d <mask>  : debug - specify mask of the key (A1:XX:CF:YY)\n"
"      -m <maddr> : MAC address to filter usable packets\n"
"      -n <nbits> : WEP key length :  64/128/152/256/512\n"
"      -i <index> : WEP key index (1 to 4), default: any\n"
"      -f <fudge> : bruteforce fudge factor,  default: 2\n"
"      -k <korek> : disable one attack method  (1 to 17)\n"
"      -x or -x0  : disable last keybytes bruteforce\n"
"      -x1        : enable last keybyte bruteforcing (default)\n"
"      -x2        : enable last two keybytes bruteforcing"
"%s"
"      -y         : experimental single bruteforce mode\n"
"      -z         : PTW attack\n"
"      -s         : show ASCII version of the key\n"
"\n"
"  WEP and WPA-PSK cracking options:\n"
"\n"
"      -w <words> : path to a dictionary file (multiple\n"
"                    dictionnaries can be specified.\n"
"                    See manpage for more information)\n"
/*"      -r <table> : path to a WPA PMK table\n" */
"\n"
"      --help     : Displays this usage screen\n"
"\n";

char * progname;

void eof_wait( int *eof_notified )
{
	if( *eof_notified == 0 )
	{
		*eof_notified = 1;

		/* tell the master thread we reached EOF */

		pthread_mutex_lock( &mx_eof );
		nb_eof++;
		pthread_cond_broadcast( &cv_eof );
		pthread_mutex_unlock( &mx_eof );
	}

	usleep( 100000 );
}

/* fread isn't atomic, sadly */

int atomic_read( read_buf *rb, int fd, int len, void *buf )
{
	int n;

	if( rb->buf1 == NULL )
	{
		rb->buf1 = malloc( 65536 );
		rb->buf2 = malloc( 65536 );

		if( rb->buf1 == NULL || rb->buf2 == NULL )
			return( 0 );

		rb->off1 = 0;
		rb->off2 = 0;
	}

	if( len > 65536 - rb->off1 )
	{
		rb->off2 -= rb->off1;

		memcpy( rb->buf2, rb->buf1 + rb->off1, rb->off2 );
		memcpy( rb->buf1, rb->buf2, rb->off2 );

		rb->off1 = 0;
	}

	if( rb->off2 - rb->off1 >= len )
	{
		memcpy( buf, rb->buf1 + rb->off1, len );
		rb->off1 += len;
		return( 1 );
	}
	else
	{
		n = read( fd, rb->buf1 + rb->off2, 65536 - rb->off2 );

		if( n <= 0 )
			return( 0 );

		rb->off2 += n;

		if( rb->off2 - rb->off1 >= len )
		{
			memcpy( buf, rb->buf1 + rb->off1, len );
			rb->off1 += len;
			return( 1 );
		}
	}

	return( 0 );
}

static int is_arp(void *wh, int len)
{
        int arpsize = 8 + 8 + 10*2;

	/* XXX check if broadcast to increase probability of correctness in some
	 * cases?
	 */
	if (wh) {}

        if (len == arpsize || len == 54)
                return 1;

        return 0;
}

static void *get_da(unsigned char *wh)
{
        if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh + 4;
        else
                return wh + 4 + 6*2;
}

static void *get_sa(unsigned char *wh)
{
        if (wh[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh + 4 + 6*2;
        else
                return wh + 4 + 6;
}

static int known_clear(void *clear, unsigned char *wh, int len)
{
        unsigned char *ptr = clear;

        /* IP */
        if (!is_arp(wh, len)) {
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

#if 0
		/* XXX IP ID is not always 0.  Can't use IP packets for PTW,
		 * unless they are our own.  Can we use them for 40-bit keys
		 * though [only 3+5 bytes of keystream needed]?  Or for
		 * calculating only the first 9 bytes of the key?  -sorbo.
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
                return len;
        }
//        printf("Assuming ARP %d\n", len);

        /* arp */
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
        return len;
}

void read_thread( void *arg )
{
	int fd, n, z, fmt;
	int eof_notified = 0;
	read_buf rb;

	uchar bssid[6];
	uchar stmac[6];
	uchar *buffer;
	uchar *h80211;
	uchar *p;

	struct pcap_pkthdr pkh;
	struct pcap_file_header pfh;
	struct AP_info *ap_prv, *ap_cur;
	struct ST_info *st_prv, *st_cur;

	memset( &rb, 0, sizeof( rb ) );

	if( ( buffer = (uchar *) malloc( 65536 ) ) == NULL )
	{
		/* there is no buffer */

		perror( "malloc failed" );
		goto read_fail;
	}

	h80211 = buffer;

	if( ! opt.is_quiet )
		printf( "Opening %s\n", (char *) arg );

	if( strcmp( arg, "-" ) == 0 )
		fd = 0;
	else
	{
		if( ( fd = open( (char *) arg, O_RDONLY | O_BINARY ) ) < 0 )
		{
			perror( "open failed" );
			goto read_fail;
		}
	}

	if( ! atomic_read( &rb, fd, 4, &pfh ) )
	{
		perror( "read(file header) failed" );
		goto read_fail;
	}

	fmt = FORMAT_IVS;

	if( memcmp( &pfh, IVSONLY_MAGIC, 4 ) != 0 )
	{
		fmt = FORMAT_CAP;

		if( pfh.magic != TCPDUMP_MAGIC &&
			pfh.magic != TCPDUMP_CIGAM )
		{
			fprintf( stderr, "Unsupported file format "
				"(not a pcap or IVs file).\n" );
			goto read_fail;
		}

		/* read the rest of the pcap file header */

		if( ! atomic_read( &rb, fd, 20, (uchar *) &pfh + 4 ) )
		{
			perror( "read(file header) failed" );
			goto read_fail;
		}

		/* take care of endian issues and check the link type */

		if( pfh.magic == TCPDUMP_CIGAM )
			SWAP32( pfh.linktype );

		if( pfh.linktype != LINKTYPE_IEEE802_11 &&
			pfh.linktype != LINKTYPE_PRISM_HEADER &&
			pfh.linktype != LINKTYPE_RADIOTAP_HDR )
		{
			fprintf( stderr, "This file is not a regular "
				"802.11 (wireless) capture.\n" );
			goto read_fail;
		}
	} else if (opt.do_ptw)
		errx(1, "Can't do PTW with IV files for now\n"); /* XXX */

	/* avoid blocking on reading the file */

	if( fcntl( fd, F_SETFL, O_NONBLOCK ) < 0 )
	{
		perror( "fcntl(O_NONBLOCK) failed" );
		goto read_fail;
	}

	while( 1 )
	{
		if( fmt == FORMAT_IVS )
		{
			/* read one IV */

			while( ! atomic_read( &rb, fd, 1, buffer ) )
				eof_wait( &eof_notified );

			if( buffer[0] != 0xFF )
			{
				/* new access point MAC */

				bssid[0] = buffer[0];

				while( ! atomic_read( &rb, fd, 5, bssid + 1 ) )
					eof_wait( &eof_notified );
			}

			while( ! atomic_read( &rb, fd, 5, buffer ) )
				eof_wait( &eof_notified );
		}
		else
		{
			while( ! atomic_read( &rb, fd, sizeof( pkh ), &pkh ) )
				eof_wait( &eof_notified );

			if( pfh.magic == TCPDUMP_CIGAM )
				SWAP32( pkh.caplen );

			if( pkh.caplen <= 0 || pkh.caplen > 65535 )
			{
				fprintf( stderr, "\nInvalid packet capture length %d - "
					"corrupted file?\n", pkh.caplen );
				eof_wait( &eof_notified );
				_exit( FAILURE );
			}

			while( ! atomic_read( &rb, fd, pkh.caplen, buffer ) )
				eof_wait( &eof_notified );

			h80211 = buffer;

			if( pfh.linktype == LINKTYPE_PRISM_HEADER )
			{
				/* remove the prism header */

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
				/* remove the radiotap header */

				n = *(unsigned short *)( h80211 + 2 );

				if( n <= 0 || n >= (int) pkh.caplen )
					continue;

				h80211 += n; pkh.caplen -= n;
			}
		}

		/* prevent concurrent access on the linked list */

		pthread_mutex_lock( &mx_apl );

		nb_pkt++;

		if( fmt == FORMAT_CAP )
		{
			/* skip packets smaller than a 802.11 header */

			if( pkh.caplen < 24 )
				goto unlock_mx_apl;

			/* skip (uninteresting) control frames */

			if( ( h80211[0] & 0x0C ) == 0x04 )
				goto unlock_mx_apl;

			/* locate the access point's MAC address */

			switch( h80211[1] & 3 )
			{
				case  0: memcpy( bssid, h80211 + 16, 6 ); break;
				case  1: memcpy( bssid, h80211 +  4, 6 ); break;
				case  2: memcpy( bssid, h80211 + 10, 6 ); break;
				default: memcpy( bssid, h80211 +  4, 6 ); break;
			}
		}

		if( memcmp( bssid, BROADCAST, 6 ) == 0 )
			/* probe request or such - skip the packet */
			goto unlock_mx_apl;

		if( memcmp( opt.maddr, ZERO,      6 ) != 0 &&
			memcmp( opt.maddr, BROADCAST, 6 ) != 0 )
		{
			/* apply the MAC filter */

			if( memcmp( opt.maddr, h80211 +  4, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 10, 6 ) != 0 &&
				memcmp( opt.maddr, h80211 + 16, 6 ) != 0 )
				goto unlock_mx_apl;
		}

		/* search the linked list */

		ap_prv = NULL;
		ap_cur = ap_1st;

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
				break;
			}

			memset( ap_cur, 0, sizeof( struct AP_info ) );

			if( ap_1st == NULL )
				ap_1st = ap_cur;
			else
				ap_prv->next = ap_cur;

			memcpy( ap_cur->bssid, bssid, 6 );

			ap_cur->crypt = -1;

			if (opt.do_ptw == 1)
			{
				ap_cur->ptw = PTW_newattackstate();
				if (!ap_cur->ptw) {
					perror("PTW_newattackstate()");
					free(ap_cur);
					ap_cur = NULL;
					break;
				}
			}
		}

		if( fmt == FORMAT_IVS )
		{
			ap_cur->crypt = 2;

			add_wep_iv:
			/* check for uniqueness first */

			if( ap_cur->nb_ivs == 0 )
				ap_cur->uiv_root = uniqueiv_init();

			if( uniqueiv_check( ap_cur->uiv_root, buffer ) == 0 )
			{
				/* add the IV & first two encrypted bytes */

				n = ap_cur->nb_ivs * 5;

				if( n + 5 > ap_cur->ivbuf_size )
				{
					/* enlarge the IVs buffer */

					ap_cur->ivbuf_size += 131072;
					ap_cur->ivbuf = (uchar *) realloc(
						ap_cur->ivbuf, ap_cur->ivbuf_size );

					if( ap_cur->ivbuf == NULL )
					{
						perror( "realloc failed" );
						break;
					}
				}

				memcpy( ap_cur->ivbuf + n, buffer, 5 );
				uniqueiv_mark( ap_cur->uiv_root, buffer );
				ap_cur->nb_ivs++;
			}

			goto unlock_mx_apl;
		}

		/* locate the station MAC in the 802.11 header */

		st_cur = NULL;

		switch( h80211[1] & 3 )
		{
			case  0: memcpy( stmac, h80211 + 10, 6 ); break;
			case  1: memcpy( stmac, h80211 + 10, 6 ); break;
			case  2:

				/* reject broadcast MACs */

				if( h80211[4] != 0 ) goto skip_station;
				memcpy( stmac, h80211 +  4, 6 ); break;

			default: goto skip_station; break;
		}

		st_prv = NULL;
		st_cur = ap_cur->st_1st;

		while( st_cur != NULL )
		{
			if( ! memcmp( st_cur->stmac, stmac, 6 ) )
				break;

			st_prv = st_cur;
			st_cur = st_cur->next;
		}

		/* if it's a new supplicant, add it */

		if( st_cur == NULL )
		{
			if( ! ( st_cur = (struct ST_info *) malloc(
				sizeof( struct ST_info ) ) ) )
			{
				perror( "malloc failed" );
				break;
			}

			memset( st_cur, 0, sizeof( struct ST_info ) );

			if( ap_cur->st_1st == NULL )
				ap_cur->st_1st = st_cur;
			else
				st_prv->next = st_cur;

			memcpy( st_cur->stmac, stmac, 6 );
		}

		skip_station:

		/* packet parsing: Beacon or Probe Response */

		if( h80211[0] == 0x80 ||
			h80211[0] == 0x50 )
		{
			if( ap_cur->crypt < 0 )
				ap_cur->crypt = ( h80211[34] & 0x10 ) >> 4;

			p = h80211 + 36;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					/* found a non-cloaked ESSID */

					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Request */

		if( h80211[0] == 0x00 )
		{
			p = h80211 + 28;

			while( p < h80211 + pkh.caplen )
			{
				if( p + 2 + p[1] > h80211 + pkh.caplen )
					break;

				if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' )
				{
					n = ( p[1] > 32 ) ? 32 : p[1];

					memset( ap_cur->essid, 0, 33 );
					memcpy( ap_cur->essid, p + 2, n );
				}

				p += 2 + p[1];
			}
		}

		/* packet parsing: Association Response */

		if( h80211[0] == 0x10 )
		{
			/* reset the WPA handshake state */

			if( st_cur != NULL )
				st_cur->wpa.state = 0;
		}

		/* check if data */

		if( ( h80211[0] & 0x0C ) != 0x08 )
			goto unlock_mx_apl;

		/* check minimum size */

		z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;
		if ( ( h80211[0] & 0x80 ) == 0x80 )
			z+=2; /* 802.11e QoS */

		if( z + 16 > (int) pkh.caplen )
			goto unlock_mx_apl;

		/* check the SNAP header to see if data is encrypted */

		if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 )
		{
			ap_cur->crypt = 2;	 /* encryption = WEP */

			/* check the extended IV flag */

			if( ( h80211[z + 3] & 0x20 ) != 0 )
								 /* encryption = WPA */
					ap_cur->crypt = 3;

			/* check the WEP key index */

			if( opt.index != 0 &&
				( h80211[z + 3] >> 6 ) != opt.index - 1 )
				goto unlock_mx_apl;

			if (opt.do_ptw) {
				unsigned char *body = h80211 + 24;
				int dlen = pkh.caplen - (body-h80211) - 4 -4;
				unsigned char clear[2048];
				int clearsize, i;

                                if((h80211[1] & 0x03) == 0x03) //30byte header
                                {
                                    body += 6;
                                    dlen -=6;
                                }

				/* calculate keystream */
				clearsize = known_clear(clear, h80211, dlen);
				if (clearsize < 16)
					goto unlock_mx_apl;
				for (i = 0; i < 16; i++)
					clear[i] ^= body[4+i];

				if (PTW_addsession(ap_cur->ptw, body, clear))
					ap_cur->nb_ivs++;

				goto unlock_mx_apl;
			}

			/* save the IV & first two output bytes */

			memcpy( buffer    , h80211 + z    , 3 );
			memcpy( buffer + 3, h80211 + z + 4, 2 );

            /* Special handling for spanning-tree packets */
            if ( memcmp( h80211 +  4, SPANTREE, 6 ) == 0 ||
                memcmp( h80211 + 16, SPANTREE, 6 ) == 0 )
            {
                buffer[3] = (buffer[3] ^ 0x42) ^ 0xAA;
                buffer[4] = (buffer[4] ^ 0x42) ^ 0xAA;
            }

			goto add_wep_iv;
		}

		if( ap_cur->crypt < 0 )
			ap_cur->crypt = 0;	 /* no encryption */

		/* if ethertype == IPv4, find the LAN address */

		z += 6;

		if( z + 20 < (int) pkh.caplen )
		{
			if( h80211[z] == 0x08 && h80211[z + 1] == 0x00 &&
				( h80211[1] & 3 ) == 0x01 )
				memcpy( ap_cur->lanip, &h80211[z + 14], 4 );

			if( h80211[z] == 0x08 && h80211[z + 1] == 0x06 )
				memcpy( ap_cur->lanip, &h80211[z + 16], 4 );
		}

		/* check ethertype == EAPOL */

		if( h80211[z] != 0x88 || h80211[z + 1] != 0x8E )
			goto unlock_mx_apl;

		z += 2;

		ap_cur->eapol = 1;

		/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

		if( h80211[z + 1] != 0x03 ||
			( h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02 ) )
			goto unlock_mx_apl;

		ap_cur->eapol = 0;
		ap_cur->crypt = 3;		 /* set WPA */

		if( st_cur == NULL )
		{
			pthread_mutex_unlock( &mx_apl );
			continue;
		}

		/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) != 0 &&
			( h80211[z + 5] & 0x01 ) == 0 )
		{
			memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

			/* authenticator nonce set */
			st_cur->wpa.state = 1;
		}

		/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

		if( ( h80211[z + 6] & 0x08 ) != 0 &&
			( h80211[z + 6] & 0x40 ) == 0 &&
			( h80211[z + 6] & 0x80 ) == 0 &&
			( h80211[z + 5] & 0x01 ) != 0 )
		{
			if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
			{
				memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );

								 /* supplicant nonce set */
				st_cur->wpa.state |= 2;
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
				memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );

								 /* authenticator nonce set */
				st_cur->wpa.state |= 4;
			}

			/* copy the MIC & eapol frame */

			st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
				+   h80211[z + 3] + 4;

			memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
			memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
			memset( st_cur->wpa.eapol + 81, 0, 16 );

								 /* eapol frame & keymic set */
			st_cur->wpa.state |= 8;

			/* copy the key descriptor version */

			st_cur->wpa.keyver = h80211[z + 6] & 7;
		}

		if( st_cur->wpa.state == 15 )
		{
			/* got one valid handshake */

			memcpy( st_cur->wpa.stmac, stmac, 6 );
			memcpy( &ap_cur->wpa, &st_cur->wpa,
				sizeof( struct WPA_hdsk ) );
		}

		unlock_mx_apl:

		pthread_mutex_unlock( &mx_apl );
	}

	read_fail:

	kill( 0, SIGTERM );
	_exit( FAILURE );
}

/* timing routine */

float chrono( struct timeval *start, int reset )
{
	float delta;
	struct timeval current;

	gettimeofday( &current, NULL );

	delta = ( current.tv_sec  - start->tv_sec  ) + (float)
		( current.tv_usec - start->tv_usec ) / 1000000;

	if( reset )
		gettimeofday( start, NULL );

	return( delta );
}

/* signal-safe I/O routines */

int safe_read( int fd, void *buf, size_t len )
{
	int n;
	size_t sum = 0;
	char  *off = (char *) buf;

	while( sum < len )
	{
		if( ! ( n = read( fd, (void *) off, len - sum ) ) )
			return( 0 );

		if( n < 0 && errno == EINTR ) continue;
		if( n < 0 ) return( n );

		sum += n;
		off += n;
	}

	return( sum );
}

int safe_write( int fd, void *buf, size_t len )
{
	int n;
	size_t sum = 0;
	char  *off = (char *) buf;

	while( sum < len )
	{
		if( ( n = write( fd, (void *) off, len - sum ) ) < 0 )
		{
			if( errno == EINTR ) continue;
			return( n );
		}

		sum += n;
		off += n;
	}

	return( sum );
}

/* each thread computes the votes over a subset of the IVs */

int crack_wep_thread( void *arg )
{
	long xv, min, max;
	uchar jj[256];
	uchar S[256], Si[256];
	uchar K[64];

	uchar io1, o1, io2, o2;
	uchar Sq, dq, Kq, jq, q;
	uchar S1, S2, J2, t2;

	int i, j, B, cid = (long) arg;
	int votes[N_ATTACKS][256];

	while( 1 )
	{
		if( safe_read( mc_pipe[cid][0], (void *) &B,
			sizeof( int ) ) != sizeof( int ) )
		{
			perror( "read failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}

		min = 5 * ( ( (     cid ) * wep.nb_ivs ) / opt.nbcpu );
		max = 5 * ( ( ( 1 + cid ) * wep.nb_ivs ) / opt.nbcpu );

		q = 3 + B;

		memcpy( K + 3, wep.key, B );
		memset( votes, 0, sizeof( votes ) );

		/* START: KoreK attacks */

		for( xv = min; xv < max; xv += 5 )
		{
			pthread_mutex_lock( &mx_ivb );

			memcpy( K, &wep.ivbuf[xv], 3 );
			memcpy( S,  R, 256 );
			memcpy( Si, R, 256 );

			for( i = j = 0; i < q; i++ )
			{
				jj[i] = j = ( j + S[i] + K[i % (3 + opt.keylen)] ) & 0xFF;
				SWAP( S[i], S[j] );
			}

			i = q; do { i--; SWAP(Si[i],Si[jj[i]]); }
			while( i != 0 );

			o1 = wep.ivbuf[xv + 3] ^ 0xAA; io1 = Si[o1]; S1 = S[1];
			o2 = wep.ivbuf[xv + 4] ^ 0xAA; io2 = Si[o2]; S2 = S[2];

			pthread_mutex_unlock( &mx_ivb );


			Sq = S[q]; dq = Sq + jj[q - 1];

			if( S2 == 0 )
			{
				if( ( S1 == 2 ) && ( o1 == 2 ) )
				{
					Kq = 1 - dq; votes[A_neg][Kq]++;
					Kq = 2 - dq; votes[A_neg][Kq]++;
				}
				else if( o2 == 0 )
				{
					Kq = 2 - dq; votes[A_neg][Kq]++;
				}
			}
			else
			{
				if( ( o2 == 0 ) && ( Sq == 0 ) )
				{
					Kq = 2 - dq; votes[A_u15][Kq]++;
				}
			}

			if( ( S1 == 1 ) && ( o1 == S2 ) )
			{
				Kq = 1 - dq; votes[A_neg][Kq]++;
				Kq = 2 - dq; votes[A_neg][Kq]++;
			}

			if( ( S1 == 0 ) && ( S[0] == 1 ) && ( o1 == 1 ) )
			{
				Kq = 0 - dq; votes[A_neg][Kq]++;
				Kq = 1 - dq; votes[A_neg][Kq]++;
			}

			if( S1 == q )
			{
				if( o1 == q )
				{
					Kq = Si[0] - dq; votes[A_s13][Kq]++;
				}
				else if( ( ( 1 - q - o1 ) & 0xFF ) == 0 )
				{
					Kq = io1 - dq; votes[A_u13_1][Kq]++;
				}
				else if( io1 < q )
				{
					jq = Si[( io1 - q ) & 0xFF];

					if( jq != 1 )
					{
						Kq = jq - dq; votes[A_u5_1][Kq]++;
					}
				}
			}

			if( ( io1 == 2 ) && ( S[q] == 1 ) )
			{
				Kq = 1 - dq; votes[A_u5_2][Kq]++;
			}

			if( S[q] == q )
			{
				if( ( S1 == 0 ) && ( o1 == q ) )
				{
					Kq = 1 - dq; votes[A_u13_2][Kq]++;
				}
				else if( ( ( ( 1 - q - S1 ) & 0xFF ) == 0 ) && ( o1 == S1 ) )
				{
					Kq = 1 - dq; votes[A_u13_3][Kq]++;
				}
				else if( ( S1 >= ( ( -q ) & 0xFF ) )
					&& ( ( ( q + S1 - io1 ) & 0xFF ) == 0 ) )
				{
					Kq = 1 - dq; votes[A_u5_3][Kq]++;
				}
			}

			if( ( S1 < q ) && ( ( ( S1 + S[S1] - q ) & 0xFF ) == 0 )  &&
				( io1 != 1 ) && ( io1 != S[S1] ) )
			{
				Kq = io1 - dq; votes[A_s5_1][Kq]++;
			}

			if( ( S1 > q ) && ( ( ( S2 + S1 - q ) & 0xFF ) == 0 ) )
			{
				if( o2 == S1 )
				{
					jq = Si[(S1 - S2) & 0xFF];

					if( ( jq != 1 ) && ( jq != 2 ) )
					{
						Kq = jq - dq; votes[A_s5_2][Kq]++;
					}
				}
				else if( o2 == ( ( 2 - S2 ) & 0xFF ) )
				{
					jq = io2;

					if( ( jq != 1 ) && ( jq != 2 ) )
					{
						Kq = jq - dq; votes[A_s5_3][Kq]++;
					}
				}
			}

			if( ( S[1] != 2 ) && ( S[2] != 0 ) )
			{
				J2 = S[1] + S[2];

				if( J2 < q )
				{
					t2 = S[J2] + S[2];

					if( ( t2 == q ) && ( io2 != 1 ) && ( io2 != 2 )
						&& ( io2 != J2 ) )
					{
						Kq = io2 - dq; votes[A_s3][Kq]++;
					}
				}
			}

			if( S1 == 2 )
			{
				if( q == 4 )
				{
					if( o2 == 0 )
					{
						Kq = Si[0] - dq; votes[A_4_s13][Kq]++;
					}
					else
					{
						if( ( jj[1] == 2 ) && ( io2 == 0 ) )
						{
							Kq = Si[254] - dq; votes[A_4_u5_1][Kq]++;
						}
						if( ( jj[1] == 2 ) && ( io2 == 2 ) )
						{
							Kq = Si[255] - dq; votes[A_4_u5_2][Kq]++;
						}
					}
				}
				else if( ( q > 4 ) && ( ( S[4] + 2 ) == q ) &&
					( io2 != 1 ) && ( io2 != 4 ) )
				{
					Kq = io2 - dq; votes[A_u5_4][Kq]++;
				}
			}
		}

		/* END: KoreK attacks */

		if( safe_write( cm_pipe[cid][1], votes,
			sizeof( votes ) ) != sizeof( votes ) )
		{
			perror( "write failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}
	}

	return( 0 );
}

/* display the current votes */

void show_wep_stats( int B, int force, PTW_tableentry table[PTW_KEYHSBYTES][PTW_n], int choices[KEYHSBYTES], int depth[KEYHSBYTES], int prod, int keylimit )
{
	float delta;
	struct winsize ws;
	int i, et_h, et_m, et_s;
	static int is_cleared = 0;

	if( ioctl( 0, TIOCGWINSZ, &ws ) < 0 )
	{
		ws.ws_row = 25;
		ws.ws_col = 80;
	}

	if( (chrono( &t_stats, 0 ) < 1.51 || wepkey_crack_success) && force == 0 )
		return;

	chrono( &t_stats, 1 );

	delta = chrono( &t_begin, 0 );

	et_h =   delta / 3600;
	et_m = ( delta - et_h * 3600 ) / 60;
	et_s =   delta - et_h * 3600 - et_m * 60;

	if( is_cleared == 0 )
	{
		is_cleared++;

		if( opt.l33t )
			printf( "\33[40m" );

		printf( "\33[2J" );
	}

	if( opt.l33t )
		printf( "\33[34;1m" );

	printf( "\33[2;%dH%s\n\n", (ws.ws_col - 12) / 2,
		progname );

	if( opt.l33t )
		printf( "\33[33;1m" );

	if(table)
		printf( "\33[5;%dH[%02d:%02d:%02d] Tested %d/%d keys (got %ld IVs)\33[K",
			(ws.ws_col - 44) / 2, et_h, et_m, et_s, prod, keylimit, opt.ap->nb_ivs );
	else
		printf( "\33[5;%dH[%02d:%02d:%02d] Tested %lld keys (got %ld IVs)\33[K",
			(ws.ws_col - 44) / 2, et_h, et_m, et_s, nb_tried, wep.nb_ivs_now );

	if( opt.l33t )
		printf( "\33[32;22m" );

	printf( "\33[7;4HKB    depth   byte(vote)\n" );

	for( i = 0; i <= B; i++ )
	{
		int j, k = ( ws.ws_col - 20 ) / 9;

		if(!table)
		{
			if( opt.l33t )
				printf( "   %2d  \33[1m%3d\33[22m/%3d   ",
					i, wep.depth[i], wep.fudge[i] );
			else
				printf( "   %2d  %3d/%3d   ",
					i, wep.depth[i], wep.fudge[i] );
		}
		else
			printf( "   %2d  %3d/%3d   ",
				i, depth[i], choices[i] );

		if(table)
		{
			for( j = depth[i]; j < k + depth[i]; j++ )
			{
				if( j >= 256 ) break;

				if( opt.l33t )
					printf( "\33[1m%02X\33[22m(%4d) ",
						table[i][j].b,
						table[i][j].votes );
				else
					printf( "%02X(%4d) ",  table[i][j].b,
						table[i][j].votes );
			}
		}
		else
		{
			for( j = wep.depth[i]; j < k + wep.depth[i]; j++ )
			{
				if( j >= 256 ) break;

				if( wep.poll[i][j].val == 32767 )
				{
					if( opt.l33t )
						printf( "\33[1m%02X\33[22m(+inf) ",
							wep.poll[i][j].idx );
					else
						printf( "%02X(+inf) ", wep.poll[i][j].idx );
				}
				else
				{
					if( opt.l33t )
						printf( "\33[1m%02X\33[22m(%4d) ",
							wep.poll[i][j].idx,
							wep.poll[i][j].val );
					else
						printf( "%02X(%4d) ",  wep.poll[i][j].idx,
							wep.poll[i][j].val );
				}
			}
		}
		if (opt.showASCII && !table)
			if(wep.poll[i][wep.depth[i]].idx>=ASCII_LOW_T && wep.poll[i][wep.depth[i]].idx<=ASCII_HIGH_T)
				if(wep.poll[i][wep.depth[i]].val>=ASCII_VOTE_STRENGTH_T || ASCII_DISREGARD_STRENGTH )
					printf( "  %c",wep.poll[i][wep.depth[i]].idx );

		printf( "\n" );
	}

	if( B < opt.keylen - 1 )
		printf( "\33[J" );

	printf( "\n" );
}

static void key_found(unsigned char *wepkey, int keylen, int B)
{
	int nb_ascii = 0;
	int i, n;

	for( i = 0; i < keylen; i++ )
		if( wepkey[i] == 0 ||
		( wepkey[i] >= 32 && wepkey[i] < 127 ) )
			nb_ascii++;

	wepkey_crack_success = 1;
	memcpy(bf_wepkey, wepkey, keylen);

	if( opt.is_quiet )
		printf( "KEY FOUND! [ " );
	else
	{
		if (B != -1)
			show_wep_stats( B - 1, 1, NULL, NULL, NULL, 0, 0 );

		if( opt.l33t )
			printf( "\33[31;1m" );

		n = ( 80 - 14 - keylen * 3 ) / 2;

		if( 100 * nb_ascii > 75 * keylen )
			n -= ( keylen + 4 ) / 2;

		if( n <= 0 ) n = 0;

		printf( "\33[K\33[%dCKEY FOUND! [ ", n );
	}

	for( i = 0; i < keylen - 1; i++ )
		printf( "%02X:", wepkey[i] );
	printf( "%02X ] ",   wepkey[i] );

	if( 100 * nb_ascii > 75 * keylen )
	{
		printf( "(ASCII: " );

		for( i = 0; i < keylen; i++ )
			printf( "%c", ( ( wepkey[i] >  31 && wepkey[i] < 127 ) ||
				wepkey[i] > 160 ) ? wepkey[i] : '.' );

		printf( " )" );
	}

	if( opt.l33t )
		printf( "\33[32;22m" );

	printf( "\n\tDecrypted correctly: %d%%\n", opt.probability );
	printf( "\n" );
}

/* test if the current WEP key is valid */

int check_wep_key( uchar *wepkey, int B, int keylen )
{
	uchar x1, x2;
	unsigned long xv;
	int i, j, n, bad, tests;

	uchar K[64];
	uchar S[256];

	if (keylen<=0)
		keylen = opt.keylen;

	nb_tried++;
	bad = 0;

	memcpy( K + 3, wepkey, keylen );

	tests = 32;

//	printf("keylen: %d\n", keylen);
//	printf("%02X:%02X:%02X:%02X:%02X\n", wepkey[0],wepkey[1],wepkey[2],wepkey[3],wepkey[4]);

	if(opt.dict) tests = wep.nb_ivs;

	if(tests < TEST_MIN_IVS) tests=TEST_MIN_IVS;
	if(tests > TEST_MAX_IVS) tests=TEST_MAX_IVS;

	for( n = 0; n < tests; n++ )
	{
		/* xv = 5 * ( rand() % wep.nb_ivs ); */
		xv = 5 * n;

		pthread_mutex_lock( &mx_ivb );

		memcpy( K, &wep.ivbuf[xv], 3 );
		memcpy( S, R, 256 );

		for( i = j = 0; i < 256; i++ )
		{
			j = ( j + S[i] + K[i % (3 + keylen)]) & 0xFF;
			SWAP( S[i], S[j] );
		}

		i = 1; j = ( 0 + S[i] ) & 0xFF; SWAP(S[i], S[j]);
		x1 = wep.ivbuf[xv + 3] ^ S[(S[i] + S[j]) & 0xFF];

		i = 2; j = ( j + S[i] ) & 0xFF; SWAP(S[i], S[j]);
		x2 = wep.ivbuf[xv + 4] ^ S[(S[i] + S[j]) & 0xFF];

		pthread_mutex_unlock( &mx_ivb );

//		printf("xv: %li x1: %02X  x2: %02X\n", (xv/5), x1, x2);

		if( ( x1 != 0xAA || x2 != 0xAA ) &&
			( x1 != 0xE0 || x2 != 0xE0 ) &&
			( x1 != 0x42 || x2 != 0x42 ) &&
			( x1 != 0x02 || x2 != 0xAA ) )					//llc sub layer management
			bad++;

		if( bad > ((tests*opt.probability)/100) )
			return( FAILURE );
	}

	opt.probability = (((tests-bad)*100)/tests);

	key_found(wepkey, keylen, B);

	return( SUCCESS );
}

/* routine used to sort the votes */

int cmp_votes( const void *bs1, const void *bs2 )
{
	if( ((vote *) bs1)->val < ((vote *) bs2)->val )
		return(  1 );

	if( ((vote *) bs1)->val > ((vote *) bs2)->val )
		return( -1 );

	return( 0 );
}

/* sum up the votes and sort them */

int calc_poll( int B )
{
	int i, n, cid, *vi;
	int votes[N_ATTACKS][256];

	memset(&opt.votes, '\0', sizeof(opt.votes));

	/* send the current keybyte # to each thread */

	for( cid = 0; cid < opt.nbcpu; cid++ )
	{
		n = sizeof( int );

		if( safe_write( mc_pipe[cid][1], &B, n ) != n )
		{
			perror( "write failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}
	}

	/* collect the votes, multiply by the korek coeffs */

	for( i = 0; i < 256; i++ )
	{
		wep.poll[B][i].idx = i;
		wep.poll[B][i].val = 0;
	}

	for( cid = 0; cid < opt.nbcpu; cid++ )
	{
		n = sizeof( votes );

		if( safe_read( cm_pipe[cid][0], votes, n ) != n )
		{
			perror( "read failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}

		for( n = 0, vi = (int *) votes; n < N_ATTACKS; n++ )
			for( i = 0; i < 256; i++, vi++ )
			{
				wep.poll[B][i].val += *vi * K_COEFF[n];
				if(K_COEFF[n]) opt.votes[n] += *vi;
			}
	}

	/* set votes to the max if the keybyte is user-defined */

	if( opt.debug_row[B] )
		wep.poll[B][opt.debug[B]].val = 32767;

	/* if option is set, restrict keyspace to alpha-numeric */

	if( opt.is_alnum )
	{
		for( i = 1; i < 32; i++ )
			wep.poll[B][i].val = -1;

		for( i = 127; i < 256; i++ )
			wep.poll[B][i].val = -1;
	}

	if( opt.is_fritz )
	{
		for( i = 0; i < 48; i++ )
			wep.poll[B][i].val = -1;

		for( i = 58; i < 256; i++ )
			wep.poll[B][i].val = -1;
	}

	/* if option is set, restrict keyspace to BCD hex digits */

	if( opt.is_bcdonly )
	{
		for( i = 1; i < 256; i++ )
			if( i > 0x99 || ( i & 0x0F ) > 0x09 )
				wep.poll[B][i].val = -1;
	}

	/* sort the votes, highest ones first */

	qsort( wep.poll[B], 256, sizeof( vote ), cmp_votes );

	return( SUCCESS );
}

int update_ivbuf( void )
{
	int n;
	struct AP_info *ap_cur;

	/* 1st pass: compute the total number of available IVs */

	wep.nb_ivs_now = 0;
	wep.nb_aps = 0;
	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		if( ap_cur->crypt == 2 && ap_cur->target )
		{
			wep.nb_ivs_now += ap_cur->nb_ivs;
			wep.nb_aps++;
		}

		ap_cur = ap_cur->next;
	}

	/* 2nd pass: create the main IVs buffer if necessary */

	if( wep.nb_ivs == 0 ||
		( opt.keylen ==  5 && wep.nb_ivs_now - wep.nb_ivs > 20000 ) ||
		( opt.keylen >= 13 && wep.nb_ivs_now - wep.nb_ivs > 40000 ) )
	{
		pthread_mutex_lock( &mx_ivb );

		/* one buffer to rule them all */

		if( wep.ivbuf != NULL )
		{
			free( wep.ivbuf );
			wep.ivbuf = NULL;
		}

		wep.nb_ivs = 0;

		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			if( ap_cur->crypt == 2 && ap_cur->target )
			{
				n = ap_cur->nb_ivs;

				if( ( wep.ivbuf = realloc( wep.ivbuf,
					( wep.nb_ivs + n ) * 5 ) ) == NULL )
				{
					pthread_mutex_unlock( &mx_ivb );
					perror( "realloc failed" );
					kill( 0, SIGTERM );
					_exit( FAILURE );
				}

				memcpy( wep.ivbuf + wep.nb_ivs * 5, ap_cur->ivbuf, 5 * n );

				wep.nb_ivs += n;
			}

			ap_cur = ap_cur->next;
		}

		pthread_mutex_unlock( &mx_ivb );

		return( RESTART );
	}

	return( SUCCESS );
}

/* standard attack mode: */
/* this routine gathers and sorts the votes, then recurses until it *
 * reaches B == keylen. It also stops when the current keybyte vote *
 * is lower than the highest vote divided by the fudge factor.      */

int do_wep_crack1( int B )
{
	int i, j, l, m, tsel;
	static int k = 0;

	get_ivs:

	switch( update_ivbuf() )
	{
		case FAILURE: return( FAILURE );
		case RESTART: return( RESTART );
		default: break;
	}

	if( ( wep.nb_ivs_now < 256 && opt.debug[0] == 0 ) ||
		( wep.nb_ivs_now <  32 && opt.debug[0] != 0 ) )
	{
		if( ! opt.no_stdin )
		{
			printf(
				"Not enough IVs available. You need about 250.000 IVs to crack\n"
				"40-bit WEP, and more than 800.000 IVs to crack a 104-bit key.\n" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}
		else
		{
			printf( "Read %ld packets, got %ld IVs...\r",
				nb_pkt, wep.nb_ivs_now );
			fflush( stdout );

			sleep( 1 );
			goto get_ivs;
		}
	}

	/* if last keybyte reached, check if the key is valid */

	if( B == opt.keylen )
	{
		if( ! opt.is_quiet )
			show_wep_stats( B - 1, 0, NULL, NULL, NULL, 0, 0 );

		return( check_wep_key( wep.key, B, 0 ) );
	}

	/* now compute the poll resultst for keybyte B */

	if( calc_poll( B ) != SUCCESS )
		return( FAILURE );

	/* fudge threshold = higest vote divided by fudge factor */

	for( wep.fudge[B] = 1; wep.fudge[B] < 256; wep.fudge[B]++ )
		if( (float) wep.poll[B][wep.fudge[B]].val <
		(float) wep.poll[B][0].val / opt.ffact )
			break;

	/* try the most likely n votes, where n is the fudge threshold */

	for( wep.depth[B] = 0; wep.depth[B] < wep.fudge[B]; ( wep.depth[B] )++ )
	{
		switch( update_ivbuf() )
		{
			case FAILURE: return( FAILURE );
			case RESTART: return( RESTART );
			default: break;
		}

		wep.key[B] = wep.poll[B][wep.depth[B]].idx;

		if( ! opt.is_quiet )
			show_wep_stats( B, 0, NULL, NULL, NULL, 0, 0 );

		if( B == 4 && opt.keylen == 13 )
		{
			/* even when cracking 104-bit WEP, *
			 * check if the 40-bit key matches */

			/* opt.keylen = 5; many functions use keylen. it is dangerous to do this in a multithreaded process */

			if( check_wep_key( wep.key, B, 5 ) == SUCCESS )
			{
				opt.keylen = 5;
				return( SUCCESS );
			}

			/* opt.keylen = 13; */
		}



		if( B + opt.do_brute + 1 == opt.keylen && opt.do_brute )
		{
			/* as noted by Simon Marechal, it's more efficient
			 * to just bruteforce the last two keybytes. */

			if (opt.nbcpu==1 || opt.do_mt_brute==0)
			{

				if (opt.do_brute==4)
				{
					for( l = 0; l < 256; l++)
					{
						wep.key[opt.brutebytes[0]] = l;

						for( m = 0; m < 256; m++ )
						{
							wep.key[opt.brutebytes[1]] = m;

							for( i = 0; i < 256; i++ )
							{
								wep.key[opt.brutebytes[2]] = i;

								for( j = 0; j < 256; j++ )
								{
									wep.key[opt.brutebytes[3]] = j;

									if (check_wep_key( wep.key, B + 1, 0 ) == SUCCESS)
										return SUCCESS;
								}
							}
						}
					}
				}
				else if (opt.do_brute==3)
				{
					for( m = 0; m < 256; m++ )
					{
						wep.key[opt.brutebytes[0]] = m;

						for( i = 0; i < 256; i++ )
						{
							wep.key[opt.brutebytes[1]] = i;

							for( j = 0; j < 256; j++ )
							{
								wep.key[opt.brutebytes[2]] = j;

								if (check_wep_key( wep.key, B + 1, 0 ) == SUCCESS)
									return SUCCESS;
							}
						}
					}
				}
				else if (opt.do_brute==2)
				{
					for( i = 0; i < 256; i++ )
					{
						wep.key[opt.brutebytes[0]] = i;

						for( j = 0; j < 256; j++ )
						{
							wep.key[opt.brutebytes[1]] = j;

							if (check_wep_key( wep.key, B + 1, 0 ) == SUCCESS)
								return SUCCESS;
						}
					}
				}
				else
				{
					for( i = 0; i < 256; i++ )
					{
						wep.key[opt.brutebytes[0]] = i;

						if (check_wep_key( wep.key, B + 1, 0 ) == SUCCESS)
							return SUCCESS;
					}
				}
			}
			else
			{
				/* multithreaded bruteforcing of the last 2 keybytes */
				k = (k+1) % opt.nbcpu;
				do
				{
					for(tsel=0; tsel<opt.nbcpu && !wepkey_crack_success; ++tsel)
					{
						if (bf_nkeys[(tsel+k) % opt.nbcpu]>16)
						{
							usleep(1);
							continue;
						}
						else
						{
							/* write our current key to the pipe so it'll have its last 2 bytes bruteforced */
							bf_nkeys[(tsel+k) % opt.nbcpu]++;

							if (safe_write(bf_pipe[(tsel+k) % opt.nbcpu][1], (void *) wep.key, 64) != 64)
							{
								perror( "write pmk failed" );
								kill( 0, SIGTERM );
								_exit( FAILURE );
							}
							break;
						}
					}
				} while (tsel>=opt.nbcpu && !wepkey_crack_success);

				if (wepkey_crack_success)
				{
					memcpy(wep.key, bf_wepkey, opt.keylen);
					return(SUCCESS);
				}
			}
		}
		else
		{
			switch( do_wep_crack1( B + 1 ) )
			{
				case SUCCESS: return( SUCCESS );
				case RESTART: return( RESTART );
				default: break;
			}
		}
	}

	return( FAILURE );
}

/* experimental single bruteforce attack */

int do_wep_crack2( int B )
{
	int i, j;

	switch( update_ivbuf() )
	{
		case FAILURE: return( FAILURE );
		case RESTART: return( RESTART );
		default: break;
	}

	if( wep.nb_ivs_now / opt.keylen < 60000 )
	{
		printf(
			"Not enough IVs available. This option is only meant to be used\n"
			"if the standard attack method fails with more than %d IVs.\n",
			opt.keylen * 60000 );
		kill( 0, SIGTERM );
		_exit( FAILURE );
	}

	for( i = 0; i <= B; i++ )
	{
		if( calc_poll( i ) != SUCCESS )
			return( FAILURE );

		wep.key[i] = wep.poll[i][0].idx;

		wep.fudge[i] = 1;
		wep.depth[i] = 0;

		if( ! opt.is_quiet )
			show_wep_stats( i, 0, NULL, NULL, NULL, 0, 0 );
	}

	for( wep.fudge[B] = 1; wep.fudge[B] < 256; wep.fudge[B]++ )
		if( (float) wep.poll[B][wep.fudge[B]].val <
		(float) wep.poll[B][0].val / opt.ffact )
			break;

	for( wep.depth[B] = 0; wep.depth[B] < wep.fudge[B]; wep.depth[B]++ )
	{
		switch( update_ivbuf() )
		{
			case FAILURE: return( FAILURE );
			case RESTART: return( RESTART );
			default: break;
		}

		wep.key[B] = wep.poll[B][wep.depth[B]].idx;

		if( ! opt.is_quiet )
			show_wep_stats( B, 0, NULL, NULL, NULL, 0, 0 );

		for( i = B + 1; i < opt.keylen - 2; i++ )
		{
			if( calc_poll( i ) != SUCCESS )
				return( FAILURE );

			wep.key[i] = wep.poll[i][0].idx;

			wep.fudge[i] = 1;
			wep.depth[i] = 0;

			if( ! opt.is_quiet )
				show_wep_stats( i, 0, NULL, NULL, NULL, 0, 0 );
		}

		for( i = 0; i < 256; i++ )
		{
			wep.key[opt.keylen - 2] = i;

			for( j = 0; j < 256; j++ )
			{
				wep.key[opt.keylen - 1] = j;

				if( check_wep_key( wep.key, opt.keylen - 2, 0 ) == SUCCESS )
					return( SUCCESS );
			}
		}
	}

	return( FAILURE );
}

int inner_bruteforcer_thread(void *arg)
{
	int i, j, k, l;
	size_t nthread = (size_t)arg;
	uchar wepkey[64];

	inner_bruteforcer_thread_start:

	if (wepkey_crack_success)
		return(SUCCESS);

	/* we get the key for which we'll bruteforce the last 2 bytes from the pipe */
	if( safe_read( bf_pipe[nthread][0], (void *) wepkey, 64) != 64)
	{
		perror( "read failed" );
		kill( 0, SIGTERM );
		_exit( FAILURE );
	}
	else
		bf_nkeys[nthread]--;

	/* now we test the 256*256 keys... if we succeed we'll save it and exit the thread */
	if (opt.do_brute==4)
	{
		for( l = 0; l < 256; l++ )
		{
			wepkey[opt.brutebytes[0]] = l;

			for( k = 0; k < 256; k++ )
			{
				wepkey[opt.brutebytes[1]] = k;

				for( i = 0; i < 256; i++ )
				{
					wepkey[opt.brutebytes[2]] = i;

					for( j = 0; j < 256; j++ )
					{
						wepkey[opt.brutebytes[3]] = j;

						if( check_wep_key( wepkey, opt.keylen - 2, 0 ) == SUCCESS )
							return(SUCCESS);
					}
				}
			}
		}
	}
	else if (opt.do_brute==3)
	{
		for( k = 0; k < 256; k++ )
		{
			wepkey[opt.brutebytes[0]] = k;

			for( i = 0; i < 256; i++ )
			{
				wepkey[opt.brutebytes[1]] = i;

				for( j = 0; j < 256; j++ )
				{
					wepkey[opt.brutebytes[2]] = j;

					if( check_wep_key( wepkey, opt.keylen - 2, 0 ) == SUCCESS )
						return(SUCCESS);
				}
			}
		}
	}
	else if (opt.do_brute==2)
	{
		for( i = 0; i < 256; i++ )
		{
			wepkey[opt.brutebytes[0]] = i;

			for( j = 0; j < 256; j++ )
			{
				wepkey[opt.brutebytes[1]] = j;

				if( check_wep_key( wepkey, opt.keylen - 2, 0 ) == SUCCESS )
					return(SUCCESS);
			}
		}
	}
	else
	{
		for( j = 0; j < 256; j++ )
		{
			wepkey[opt.brutebytes[0]] = j;

			if( check_wep_key( wepkey, opt.keylen - 2, 0 ) == SUCCESS )
				return(SUCCESS);
		}
	}

	goto inner_bruteforcer_thread_start;

}

#ifndef __i386__
/* derive the PMK from the passphrase and the essid */

void calc_pmk( char *key, char *essid_pre, uchar pmk[40] )
{
	int i, j, slen;
	uchar buffer[65];
	char essid[33+4];
	sha1_context ctx_ipad;
	sha1_context ctx_opad;
	sha1_context sha1_ctx;

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, strlen(essid_pre));
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x36;

	sha1_starts( &ctx_ipad );
	sha1_update( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x6A;

	sha1_starts( &ctx_opad );
	sha1_update( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	hmac_sha1( (uchar *) key, strlen( key ),
		(uchar *) essid, slen, pmk );
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		sha1_update( &sha1_ctx, buffer, 20 );
		sha1_finish( &sha1_ctx, buffer );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		sha1_update( &sha1_ctx, buffer, 20 );
		sha1_finish( &sha1_ctx, buffer );

		for( j = 0; j < 20; j++ )
			pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	hmac_sha1( (uchar *) key, strlen( key ),
		(uchar *) essid, slen, pmk + 20 );
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ )
	{
		memcpy( &sha1_ctx, &ctx_ipad, sizeof( sha1_ctx ) );
		sha1_update( &sha1_ctx, buffer, 20 );
		sha1_finish( &sha1_ctx, buffer );

		memcpy( &sha1_ctx, &ctx_opad, sizeof( sha1_ctx ) );
		sha1_update( &sha1_ctx, buffer, 20 );
		sha1_finish( &sha1_ctx, buffer );

		for( j = 0; j < 20; j++ )
			pmk[j + 20] ^= buffer[j];
	}
}
#endif
/* each thread computes two pairwise master keys at a time */

int crack_wpa_thread( void *arg )
{
	char  essid[36];
	char  key1[128], key2[128];
	uchar pmk1[128], pmk2[128];
        int len1, len2;

	#ifdef __i386__

	uchar k_ipad[128], ctx_ipad[40];
	uchar k_opad[128], ctx_opad[40];
	uchar buffer[128], sha1_ctx[40];
	uchar wrkbuf[640];
	uint i, *u, *v, *w;
	#endif

	int slen, cid = (long) arg;

	/* receive the essid */

	memset( essid, 0, sizeof( essid ) );

	if( safe_read( mc_pipe[cid][0], (void *) essid, 32 ) != 32 )
	{
		perror( "read failed" );
		kill( 0, SIGTERM );
		_exit( FAILURE );
	}

	slen = strlen( essid ) + 4;

	while( 1 )
	{
		/* receive two passphrases */

		memset( key1, 0, sizeof( key1 ) );
		memset( key2, 0, sizeof( key2 ) );

		if( safe_read( mc_pipe[cid][0], (void *) key1, 128 ) != 128 ||
			safe_read( mc_pipe[cid][0], (void *) key2, 128 ) != 128 )
		{
			perror( "read passphrase failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}

		key1[127] = '\0';
		key2[127] = '\0';

                len1 = strlen( key1 );
                len2 = strlen( key1 );
                if(len1 > 64 ) len1 = 64;
                if(len2 > 64 ) len2 = 64;

                if(len1 < 8) len1 = 8;
                if(len2 < 8) len2 = 8;
		#ifdef __i386__

		/* MMX available, so compute two PMKs in a single row */

		memset( k_ipad, 0, sizeof( k_ipad ) );
		memset( k_opad, 0, sizeof( k_opad ) );

		memcpy( k_ipad, key1, len1 );
		memcpy( k_opad, key1, len1 );

		memcpy( k_ipad + 64, key2, len2 );
		memcpy( k_opad + 64, key2, len2 );

		u = (uint *) ( k_ipad      );
		v = (uint *) ( k_ipad + 64 );
		w = (uint *) buffer;

		for( i = 0; i < 16; i++ )
		{
			/* interleave the data */

			*w++ = *u++ ^ 0x36363636;
			*w++ = *v++ ^ 0x36363636;
		}

		shammx_init( ctx_ipad );
		shammx_data( ctx_ipad, buffer, wrkbuf );

		u = (uint *) ( k_opad      );
		v = (uint *) ( k_opad + 64 );
		w = (uint *) buffer;

		for( i = 0; i < 16; i++ )
		{
			*w++ = *u++ ^ 0x5C5C5C5C;
			*w++ = *v++ ^ 0x5C5C5C5C;
		}

		shammx_init( ctx_opad );
		shammx_data( ctx_opad, buffer, wrkbuf );

		memset( buffer, 0, sizeof( buffer ) );

		/* use the buffer, luke */

		buffer[ 40] = buffer[ 44] = 0x80;
		buffer[122] = buffer[126] = 0x02;
		buffer[123] = buffer[127] = 0xA0;

		essid[slen - 1] = '\1';

		hmac_sha1( (uchar *) key1, len1,
			(uchar *) essid, slen,  pmk1 );

		hmac_sha1( (uchar *) key2, len2,
			(uchar *) essid, slen,  pmk2 );

		u = (uint *) pmk1;
		v = (uint *) pmk2;
		w = (uint *) buffer;

		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;

		for( i = 1; i < 4096; i++ )
		{
			memcpy( sha1_ctx, ctx_ipad, 40 );
			shammx_data( sha1_ctx, buffer, wrkbuf );
			shammx_ends( sha1_ctx, buffer );

			memcpy( sha1_ctx, ctx_opad, 40 );
			shammx_data( sha1_ctx, buffer, wrkbuf );
			shammx_ends( sha1_ctx, buffer );

			u = (uint *) pmk1;
			v = (uint *) pmk2;
			w = (uint *) buffer;

			/* de-interleave the digests */

			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
		}

		essid[slen - 1] = '\2';

		hmac_sha1( (uchar *) key1, len1,
			(uchar *) essid, slen,  pmk1 + 20 );

		hmac_sha1( (uchar *) key2, len2,
			(uchar *) essid, slen,  pmk2 + 20 );

		u = (uint *) ( pmk1 + 20 );
		v = (uint *) ( pmk2 + 20 );
		w = (uint *) buffer;

		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;
		*w++ = *u++; *w++ = *v++;

		for( i = 1; i < 4096; i++ )
		{
			memcpy( sha1_ctx, ctx_ipad, 40 );
			shammx_data( sha1_ctx, buffer, wrkbuf );
			shammx_ends( sha1_ctx, buffer );

			memcpy( sha1_ctx, ctx_opad, 40 );
			shammx_data( sha1_ctx, buffer, wrkbuf );
			shammx_ends( sha1_ctx, buffer );

			u = (uint *) ( pmk1 + 20 );
			v = (uint *) ( pmk2 + 20 );
			w = (uint *) buffer;

			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
			*u++ ^= *w++; *v++ ^= *w++;
		}

		#else

		/* not x86, use the generic SHA-1 C code */

		calc_pmk( key1, essid, pmk1 );
		calc_pmk( key2, essid, pmk2 );
		#endif

		/* send the passphrase & master keys */

		if( safe_write( cm_pipe[cid][1], (void *) key1, 128 ) != 128 ||
			safe_write( cm_pipe[cid][1], (void *) key2, 128 ) != 128 ||
			safe_write( cm_pipe[cid][1], (void *) pmk1,  32 ) !=  32 ||
			safe_write( cm_pipe[cid][1], (void *) pmk2,  32 ) !=  32 )
		{
			perror( "write pmk failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}
	}
}

/* display the current wpa key info, matrix-like */

void show_wpa_stats( char *key, int keylen, uchar pmk[32], uchar ptk[64],
uchar mic[16], int force )
{
	float delta;
	int i, et_h, et_m, et_s;
	char tmpbuf[28];

	#ifdef __i386__
	__asm__( "emms" );			 /* clean up the fp regs */
	#endif

	if( chrono( &t_stats, 0 ) < 0.08 && force == 0 )
		return;

	chrono( &t_stats, 1 );

	delta = chrono( &t_begin, 0 );

	et_h =   delta / 3600;
	et_m = ( delta - et_h * 3600 ) / 60;
	et_s =   delta - et_h * 3600 - et_m * 60;

	if( ( delta = chrono( &t_kprev, 0 ) ) >= 6 )
	{
		t_kprev.tv_sec += 3;
		nb_kprev /= 2;
	}

	if( opt.l33t ) printf( "\33[33;1m" );
	printf( "\33[5;20H[%02d:%02d:%02d] %lld keys tested "
		"(%2.2f k/s)", et_h, et_m, et_s,
		nb_tried, (float) nb_kprev / delta );

	memset( tmpbuf, ' ', sizeof( tmpbuf ) );
	memcpy( tmpbuf, key, keylen > 27 ? 27 : keylen );
	tmpbuf[27] = '\0';

	if( opt.l33t ) printf( "\33[37;1m" );
	printf( "\33[8;24HCurrent passphrase: %s\n", tmpbuf );

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[11;7HMaster Key     : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 32; i++ )
	{
		if( i == 16 ) printf( "\n\33[23C" );
		printf( "%02X ", pmk[i] );
	}

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[14;7HTranscient Key : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 64; i++ )
	{
		if( i > 0 && i % 16 == 0 ) printf( "\n\33[23C" );
		printf( "%02X ", ptk[i] );
	}

	if( opt.l33t ) printf( "\33[32;22m" );
	printf( "\33[19;7HEAPOL HMAC     : " );

	if( opt.l33t ) printf( "\33[32;1m" );
	for( i = 0; i < 16; i++ )
		printf( "%02X ", mic[i] );

	printf( "\n" );
}

int next_dict(int nb)
{
	if(opt.dict != NULL)
	{
		if(!opt.stdin_dict) fclose(opt.dict);
		opt.dict = NULL;
	}
	opt.nbdict = nb;
	if(opt.dicts[opt.nbdict] == NULL)
		return( FAILURE );

	while(opt.nbdict < MAX_DICTS && opt.dicts[opt.nbdict] != NULL)
	{
		if( strcmp( opt.dicts[opt.nbdict], "-" ) == 0 )
		{
			opt.stdin_dict = 1;

			if( ( opt.dict = fdopen( fileno(stdin) , "r" ) ) == NULL )
			{
				perror( "fopen(dictionary) failed" );
				opt.nbdict++;
				continue;
			}

			opt.no_stdin = 1;
		}
		else
		{
			opt.stdin_dict = 0;
			if( ( opt.dict = fopen( opt.dicts[opt.nbdict], "r" ) ) == NULL )
			{
				perror( "fopen(dictionary) failed" );
				opt.nbdict++;
				continue;
			}

			fseek(opt.dict, 0L, SEEK_END);

			if ( ftell( opt.dict ) <= 0L )
			{
				fclose( opt.dict );
				opt.dict = NULL;
				printf( "Empty dictionnary\n" );
				opt.nbdict++;
				continue;
			}

			rewind( opt.dict );
		}
		break;
	}

	if(opt.nbdict >= MAX_DICTS || opt.dicts[opt.nbdict] == NULL)
	    return( FAILURE );

	return( 0 );
}

int do_wpa_crack( struct AP_info *ap )
{
	int i, j, cid, len1, len2, num_cpus;
	char key1[128], key2[128];

	uchar pke[100];
	uchar pmk1[40], ptk1[80];
	uchar pmk2[40], ptk2[80];
	uchar mic1[20], mic2[20];

        i=0;

	num_cpus = opt.nbcpu;

	/* send the ESSID to each thread */

	for( cid = 0; cid < num_cpus; cid++ )
	{
		if( safe_write( mc_pipe[cid][1], (void *) ap->essid, 32 ) != 32 )
		{
			perror( "write essid failed" );
			kill( 0, SIGTERM );
			_exit( FAILURE );
		}
	}

	/* pre-compute the key expansion buffer */

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

	memset( key1, 0, sizeof( key1 ) );
	memset( key2, 0, sizeof( key1 ) );

	if( ! opt.is_quiet )
	{
		if( opt.l33t )
			printf( "\33[37;40m" );

		printf( "\33[2J" );

		if( opt.l33t )
			printf( "\33[34;1m" );

		printf("\33[2;34H%s",progname);
	}

	while( num_cpus > 0 )
	{
		for( cid = 0; cid < num_cpus; cid++ )
		{
			/* read a couple of keys (skip those < 8 chars) */

			if(opt.dict == NULL)
			{
				printf( "\nPassphrase not in dictionnary \n" );
				return( FAILURE );
			}

			do
			{
				if( fgets( key1, sizeof( key1 ), opt.dict ) == NULL )
				{
					if( opt.l33t )
						printf( "\33[32;22m" );

					/* printf( "\nPassphrase not in dictionnary %s \n", opt.dicts[opt.nbdict] );*/
					if(next_dict(opt.nbdict+1) != 0)
					{
						/* no more words, but we still have to collect results from words sent to previous cpus */
						num_cpus = cid;
						goto collect_and_test;
						/* return( FAILURE ); */
					}
					else
					{
						continue;
					}
				}

				i = strlen( key1 );
                                if( i < 8 ) continue;
                                if( i > 64 ) i = 64;

				if( key1[i - 1] == '\n' ) key1[--i] = '\0';
				if( key1[i - 1] == '\r' ) key1[--i] = '\0';
				if( key1[i - 1] == '\n' ) key1[--i] = '\0';
				if( key1[i - 1] == '\r' ) key1[--i] = '\0';

                                for(j=0; j<i; j++)
                                    if(!isascii(key1[j]) || key1[j] < 32) i=0;
			}
			while( i < 8 );

			do
			{
				if( fgets( key2, sizeof( key2 ), opt.dict ) == NULL )
				{
					if(next_dict(opt.nbdict+1) != 0)
					{
						break;
					}
					else
					{
						continue;
					}
				}

				i = strlen( key2 );

                                if( i < 8 ) continue;
                                if( i > 64 ) i = 64;

				if( key2[i - 1] == '\n' ) key2[--i] = '\0';
				if( key2[i - 1] == '\r' ) key2[--i] = '\0';
				if( key2[i - 1] == '\n' ) key2[--i] = '\0';
				if( key2[i - 1] == '\r' ) key2[--i] = '\0';

                                for(j=0; j<i; j++)
                                    if(!isascii(key2[j]) || key2[j] < 32 ) i=0;
			}
			while( i < 8 );

			/* send the keys */

			if( safe_write( mc_pipe[cid][1], (void *) key1, 128 ) != 128 ||
				safe_write( mc_pipe[cid][1], (void *) key2, 128 ) != 128 )
			{
				perror( "write passphrase failed" );
				return( FAILURE );
			}
		}

collect_and_test:

		for( cid = 0; cid < num_cpus; cid++ )
		{
			/* collect and test the master keys */

			if( safe_read( cm_pipe[cid][0], (void *) key1, 128 ) != 128 ||
				safe_read( cm_pipe[cid][0], (void *) key2, 128 ) != 128 ||
				safe_read( cm_pipe[cid][0], (void *) pmk1,  32 ) !=  32 ||
				safe_read( cm_pipe[cid][0], (void *) pmk2,  32 ) !=  32 )
			{
				perror( "read pmk failed" );
				return( FAILURE );
			}

			len1 = strlen( key1 );
			len2 = strlen( key2 );

                        if( len1 < 8 ) len1=8;
                        if( len1 > 64 ) len1 = 64;

                        if( len2 < 8 ) len2=8;
                        if( len2 > 64 ) len2 = 64;

			/* compute the pairwise transient key and the frame MIC */

			for( i = 0; i < 4; i++ )
			{
				pke[99] = i;
				hmac_sha1( pmk1, 32, pke, 100, ptk1 + i * 20 );
				hmac_sha1( pmk2, 32, pke, 100, ptk2 + i * 20 );
			}

			if( ap->wpa.keyver == 1 )
			{
				hmac_md5( ptk1, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic1 );
				hmac_md5( ptk2, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic2 );
			}
			else
			{
				hmac_sha1( ptk1, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic1 );
				hmac_sha1( ptk2, 16, ap->wpa.eapol, ap->wpa.eapol_size, mic2 );
			}

			if( memcmp( mic1, ap->wpa.keymic, 16 ) == 0 )
			{
				memcpy( key2, key1, 128 );
				memcpy( pmk2, pmk1,  32 );
				memcpy( ptk2, ptk1,  64 );
				memcpy( mic2, mic1,  16 );
			}

			if( memcmp( mic2, ap->wpa.keymic, 16 ) == 0 )
			{
				if( opt.is_quiet )
				{
					printf( "KEY FOUND! [ %s ]\n", key2 );
					return( SUCCESS );
				}

				show_wpa_stats( key2, len1, pmk2, ptk2, mic2, 1 );

				if( opt.l33t )
					printf( "\33[31;1m" );

				printf( "\33[8;%dH\33[2KKEY FOUND! [ %s ]\33[11B\n",
					( 80 - 15 - (int) len1 ) / 2, key2 );

				if( opt.l33t )
					printf( "\33[32;22m" );

				return( SUCCESS );
			}

			nb_tried += 2;
			nb_kprev += 2;

			if( ! opt.is_quiet )
				show_wpa_stats( key1, len1, pmk1, ptk1, mic1, 0 );
		}
	}

	printf( "\nPassphrase not in dictionnary \n" );
	return( FAILURE );
}

int intr_read = 0;

void sighandler( int signum )
{
	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
	#endif
	signal( signum, sighandler );

	if( signum == SIGQUIT )
		_exit( SUCCESS );

	if( signum == SIGTERM )
		_exit( FAILURE );

	if( signum == SIGINT )
	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
		_exit( FAILURE );
	#else
	intr_read++;
	#endif

	if( signum == SIGWINCH )
		printf( "\33[2J\n" );
}

int next_key( char **key, int keysize )
{
	char *tmp, *tmp2;
	int i, rtn;
	unsigned int dec;
	char *hex;

	tmp2 = tmp = (char*) malloc(1024);

	while(1)
	{
		rtn = 0;
		tmp = tmp2;
		if(opt.dict == NULL)
		{
			printf( "\nPassphrase not in dictionnary \n" );
			free(tmp);
			return( FAILURE );
		}

		if( opt.hexdict[opt.nbdict] )
		{
			if( fgets( tmp, ((keysize*2)+(keysize-1)), opt.dict ) == NULL )
			{
				if( opt.l33t )
					printf( "\33[32;22m" );

//				printf( "\nPassphrase not in dictionnary \"%s\" \n", opt.dicts[opt.nbdict] );
				if(next_dict(opt.nbdict+1) != 0)
				{
					free(tmp);
					return( FAILURE );
				}
				else
				{
					continue;
				}
			}

			i=strlen(tmp);

			if( i <= 2 ) continue;

			if( tmp[i - 1] == '\n' ) tmp[--i] = '\0';
			if( tmp[i - 1] == '\r' ) tmp[--i] = '\0';
			if( i <= 0 ) continue;

			i=0;

			hex = strsep(&tmp, ":");

			while( i<keysize && hex != NULL )
			{
				if(strlen(hex) > 2 || strlen(hex) == 0)
				{
					rtn = 1;
					break;
				}
				if(sscanf(hex, "%x", &dec) == 0 )
				{
					rtn = 1;
					break;
				}

				(*key)[i] = dec;
				hex = strsep(&tmp, ":");
				i++;
			}
			if(rtn)
			{
				continue;
			}
		}
		else
		{
			if( fgets( *key, keysize, opt.dict ) == NULL )
			{
				if( opt.l33t )
					printf( "\33[32;22m" );

//				printf( "\nPassphrase not in dictionnary \"%s\" \n", opt.dicts[opt.nbdict] );
				if(next_dict(opt.nbdict+1) != 0)
				{
					free(tmp);
					return( FAILURE );
				}
				else
				{
					continue;
				}
			}

			i=strlen(*key);

			if( i <= 2 ) continue;

			if( (*key)[i - 1] == '\n' ) (*key)[--i] = '\0';
			if( (*key)[i - 1] == '\r' ) (*key)[--i] = '\0';

			if( i <= 0 ) continue;
		}

		break;
	}

	free(tmp);

	return( SUCCESS );
}

int set_dicts(char* optargs)
{
	int len;
	char *optarg;

	opt.nbdict = 0;
	optarg = strsep(&optargs, ",");

	for(len=0; len<MAX_DICTS; len++)
	{
		opt.dicts[len] = NULL;
	}

	while(optarg != NULL && opt.nbdict<MAX_DICTS)
	{
		len = strlen(optarg)+1;
		opt.dicts[opt.nbdict] = (char*)malloc(len * sizeof(char));
		if(opt.dicts[opt.nbdict] == NULL)
		{
			perror("allocation failed!");
			return( FAILURE );
		}
		if(strncasecmp(optarg, "h:", 2) == 0)
		{
			strncpy(opt.dicts[opt.nbdict], optarg+2, len-2);
			opt.hexdict[opt.nbdict] = 1;
		}
		else
		{
			strncpy(opt.dicts[opt.nbdict], optarg, len);
			opt.hexdict[opt.nbdict] = 0;
		}
		optarg = strsep(&optargs, ",");
		opt.nbdict++;
	}

	next_dict(0);

	while(next_dict(opt.nbdict+1) == 0) {}

	next_dict(0);

	return 0;
}

int crack_wep_dict()
{
	struct timeval t_last;
	struct timeval t_now;
	int i, origlen, keysize;
	char *key;

	key = (char*) malloc(sizeof(char) * (opt.keylen + 1));
	keysize = opt.keylen+1;

	update_ivbuf();

	if(wep.nb_ivs < TEST_MIN_IVS)
	{
		printf( "\nYou need to capture at least %d IVs!\n", TEST_MIN_IVS );
		return( FAILURE );
	}

	gettimeofday( &t_last, NULL );
	t_last.tv_sec--;

	while(1)
	{
		if( next_key( &key, keysize ) != SUCCESS) return( FAILURE );

		i = strlen( key );

		origlen = i;

		while(i<opt.keylen)
		{
			key[i] = key[i - origlen];
			i++;
		}

		key[i] = '\0';

		if( ! opt.is_quiet )
		{
			gettimeofday( &t_now, NULL );
			if( (t_now.tv_sec - t_last.tv_sec) > 0)
			{
				show_wep_stats(opt.keylen - 1, 1, NULL, NULL, NULL, 0, 0);
				gettimeofday( &t_last, NULL);
			}
		}

		for(i=0; i<=opt.keylen; i++)
		{
			wep.key[i] = (uchar)key[i];
		}

		if(check_wep_key(wep.key, opt.keylen, 0) == SUCCESS)
			return( SUCCESS );
	}
}

static int crack_wep_ptw(struct AP_info *ap_cur)
{
	int len = 0;

	opt.ap = ap_cur;

	if(PTW_computeKey(ap_cur->ptw, wep.key, 13, (KEYLIMIT*opt.ffact)) == 1)
		len = 13;
	else if(PTW_computeKey(ap_cur->ptw, wep.key, 5, (KEYLIMIT*opt.ffact)/10) == 1)
		len = 5;

	if (!len)
		return FAILURE;

	opt.probability = 100;
	key_found(wep.key, len, -1);

	return SUCCESS;
}

int main( int argc, char *argv[] )
{
	int i, n, ret, max_cpu, option, j, ret1, cpudetectfailed, unused, showhelp;
	char *s, buf[128];
	struct AP_info *ap_cur;

	ret = FAILURE;
	cpudetectfailed = 0;
	showhelp = 0;

	progname = getVersion("Aircrack-ng", _MAJ, _MIN, _SUB_MIN, _REVISION);

	memset( &opt, 0, sizeof( opt ) );

	srand( time( NULL ) );

	#ifdef _SC_NPROCESSORS_ONLN

	max_cpu   = sysconf(_SC_NPROCESSORS_ONLN);
	/* Fails on some archs */
	cpudetectfailed = ( max_cpu < 1 );
	if (cpudetectfailed)
		max_cpu = 1;
	opt.nbcpu = max_cpu;

	#else

	cpudetectfailed = 1;
	max_cpu   = 255;
	opt.nbcpu =   1;
	#endif
	j=0;
	/* check the arguments */

	opt.do_brute    = 1;
	opt.do_mt_brute = 1;
	opt.showASCII   = 0;
	opt.probability = 51;
        opt.next_ptw_try= 0;

	while( 1 )
	{

        int option_index = 0;

        static struct option long_options[] = {
            {"bssid",   1, 0, 'b'},
            {"debug",   1, 0, 'd'},
            {"help",    0, 0, 'H'},
            {0,         0, 0,  0 }
        };

		if ( max_cpu == 1 )
			option = getopt_long( argc, argv, "a:e:b:qcthd:m:n:i:f:k:x::ysw:0Hz",
                        long_options, &option_index );
		else
			option = getopt_long( argc, argv, "a:e:b:p:qcthd:m:n:i:f:k:x::Xysw:0Hz",
                        long_options, &option_index );

		if( option < 0 ) break;

		switch( option )
		{

			case ':' :

	    		printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case '?' :

	    		printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case 'a' :

				ret1 = sscanf( optarg, "%d", &opt.amode );

				if ( strcasecmp( optarg, "wep" ) == 0 )
					opt.amode = 1;

				else if ( strcasecmp( optarg, "wpa" ) == 0 )
					opt.amode = 2;

				if( opt.amode != 1 && opt.amode != 2 )
				{
					printf( "Invalid attack mode. [1,2] or [wep,wpa]\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'e' :

				memset(  opt.essid, 0, sizeof( opt.essid ) );
				strncpy( opt.essid, optarg, sizeof( opt.essid ) - 1 );
				opt.essid_set = 1;
				break;

			case 'b' :

				if (getmac(optarg, 1, opt.bssid) != 0)
				{
						printf( "Invalid BSSID (not a MAC).\n" );
			    		printf("\"%s --help\" for help.\n", argv[0]);
						return( FAILURE );
				}

				opt.bssid_set = 1;
				break;

			case 'p' :
				if( sscanf( optarg, "%d", &opt.nbcpu ) != 1 ||
					opt.nbcpu < 1 || opt.nbcpu > max_cpu )
				{
					printf( "Invalid number of processes. [1-%d]\n", max_cpu );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'q' :

				opt.is_quiet = 1;

				break;

			case 'c' :

				opt.is_alnum = 1;
				break;

			case 'h' :

				opt.is_fritz = 1;
				break;

			case 't' :

				opt.is_bcdonly = 1;
				break;

			case 'd' :

				i = 0 ;
				n = 0;
				s = optarg;
				while( s[i] != '\0' )
				{
					if (s[i] == 'x')
						s[i] = 'X';
					if (s[i] == 'y')
						s[i] = 'Y';
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
				while( ( sscanf( buf, "%x", &n ) == 1 ) || ( buf[0] == 'X' && buf[1] == 'X' ) || ( buf[0] == 'Y' && buf[1] == 'Y' ))
				{
					if ( buf[0] == 'X' && buf[1] == 'X' ) {
						opt.debug_row[i++] = 0 ;
					} else if ( buf[0] == 'Y' && buf[1] == 'Y' ) {
						opt.brutebytes[j++] = i++;
					} else {
						if ( n < 0 || n > 255 )
						{
							printf( "Invalid debug key.\n" );
				    		printf("\"%s --help\" for help.\n", argv[0]);
							return( FAILURE );
						}
						opt.debug[i] = n ;
						opt.debug_row[i++] = 1;
					}
					if( i >= 64 ) break;
					s += 2;
					buf[0] = s[0];
					buf[1] = s[1];
				}
				break;


			case 'm' :

				if ( getmac(optarg, 1, opt.maddr) != 0)
				{
					printf( "Invalid MAC address filter.\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'n' :

				if( sscanf( optarg, "%d", &opt.keylen ) != 1 ||
					( opt.keylen !=  64 && opt.keylen != 128 &&
					opt.keylen != 152 && opt.keylen != 256 &&
					opt.keylen != 512 ) )
				{
					printf( "Invalid WEP key length. [64,128,152,256,512]\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				opt.keylen = ( opt.keylen / 8 ) - 3;

				break;

			case 'i' :

				if( sscanf( optarg, "%d", &opt.index ) != 1 ||
					opt.index < 1 || opt.index > 4 )
				{
					printf( "Invalid WEP key index. [1-4]\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'f' :

				if( sscanf( optarg, "%f", &opt.ffact ) != 1 ||
					opt.ffact < 1 || opt.ffact > 32 )
				{
					printf( "Invalid fudge factor. [1-32]\n" );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				break;

			case 'k' :

				if( sscanf( optarg, "%d", &opt.korek ) != 1 ||
					opt.korek < 1 || opt.korek > N_ATTACKS )
				{
					printf( "Invalid KoreK attack strategy. [1-%d]\n", N_ATTACKS );
		    		printf("\"%s --help\" for help.\n", argv[0]);
					return( FAILURE );
				}

				K_COEFF[(opt.korek) - 1] = 0;

				break;

			case 'x' :

				opt.do_brute = 0;

				if (optarg)
				{
					if (sscanf(optarg, "%d", &opt.do_brute)!=1
						|| opt.do_brute<0 || opt.do_brute>4)
					{
						printf("Invalid option -x%s. [0-4]\n", optarg);
			    		printf("\"%s --help\" for help.\n", argv[0]);
						return FAILURE;
					}
				}

				break;

			case 'X' :

				opt.do_mt_brute = 0;
				break;

			case 'y' :

				opt.do_testy = 1;
				break;

			case 'z' :
				opt.do_ptw = 1;
				break;

			case 's' :
				opt.showASCII = 1;
				break;

			case 'w' :
				if(set_dicts(optarg) != 0)
				{
		    		printf("\"%s --help\" for help.\n", argv[0]);
				    return FAILURE;
				}
				break;

			case '0' :

				opt.l33t = 1;
				break;

			case 'H' :

				showhelp = 1;
				goto usage;
				break;

			default : goto usage;
		}
	}

	if( argc - optind < 1 )
	{
		if(argc == 1)
		{
usage:
			printf (usage, progname,
				( max_cpu == 1 && cpudetectfailed == 0) ? "\n" : "\n      -p <nbcpu> : # of CPU to use (by default, all CPUs)\n",
				( max_cpu == 1 && cpudetectfailed == 0) ? "\n" : "\n      -X         : disable bruteforce multithreading (SMP only)\n");

			/* The user only asked for help */
			if (showhelp == 1)
				exit(0);
		}
		if( argc - optind == 0)
	    {
	    	printf("No file to crack specified.\n");
	    }
	    if(argc > 1)
	    {
    		printf("\"%s --help\" for help.\n", argv[0]);
	    }
		return( ret );
	}

	if( opt.amode == 2 && opt.dict == NULL )
	{
		nodict:
		printf( "Please specify a dictionary (option -w).\n" );
		goto exit_main;
	}

	if( (! opt.essid_set && ! opt.bssid_set) && ( opt.is_quiet || opt.no_stdin ) )
	{
		printf( "Please specify an ESSID or BSSID.\n" );
		goto exit_main;
	}

	/* start one thread per input file */

	signal( SIGINT,  sighandler );
	signal( SIGQUIT, sighandler );
	signal( SIGTERM, sighandler );
	signal( SIGALRM, SIG_IGN );

	pthread_mutex_init( &mx_apl, NULL );
	pthread_mutex_init( &mx_eof, NULL );
	pthread_mutex_init( &mx_ivb, NULL );
	pthread_cond_init(  &cv_eof, NULL );

	ap_1st = NULL;

	n = argc - optind;

	do
	{
		pthread_t tid;

		if( strcmp( argv[optind], "-" ) == 0 )
			opt.no_stdin = 1;

		if( pthread_create( &tid, NULL, (void *) read_thread,
			(void *) argv[optind] ) != 0 )
		{
			perror( "pthread_create failed" );
			goto exit_main;
		}

		usleep( 131071 );
	}
	while( ++optind < argc );

	/* wait until each thread reaches EOF */

	pthread_mutex_lock( &mx_eof );

	if( ! opt.is_quiet )
	{
		printf( "Reading packets, please wait...\r" );
		fflush( stdout );
	}

	while( nb_eof < n && ! intr_read )
		pthread_cond_wait( &cv_eof, &mx_eof );

	pthread_mutex_unlock( &mx_eof );

	if( ! opt.is_quiet && ! opt.no_stdin )
		printf( "\33[KRead %ld packets.\n\n", nb_pkt );

	#ifndef DO_PGO_DUMP
	signal( SIGINT, SIG_DFL );	 /* we want sigint to stop and dump pgo data */
	#endif

	if( ap_1st == NULL )
	{
		printf( "No networks found, exiting.\n" );
		goto exit_main;
	}

	if( ! opt.essid_set && ! opt.bssid_set )
	{
		/* ask the user which network is to be cracked */

		printf( "   #  BSSID%14sESSID%21sEncryption\n\n", "", "" );

		i = 1;

		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			printf( "%4d  %02X:%02X:%02X:%02X:%02X:%02X  %-24s  ",
				i, ap_cur->bssid[0], ap_cur->bssid[1],
				ap_cur->bssid[2], ap_cur->bssid[3],
				ap_cur->bssid[4], ap_cur->bssid[5],
				ap_cur->essid );

			if( ap_cur->eapol )
				printf( "EAPOL+" );

			switch( ap_cur->crypt )
			{
				case  0: printf( "None (%d.%d.%d.%d)\n",
					ap_cur->lanip[0], ap_cur->lanip[1],
					ap_cur->lanip[2], ap_cur->lanip[3] );
				break;

				case  1: printf( "No data - WEP or WPA\n" );
				break;

				case  2: printf( "WEP (%ld IVs)\n",
					ap_cur->nb_ivs );
				break;

				case  3: printf( "WPA (%d handshake)\n",
					ap_cur->wpa.state == 15 );
				break;

				default: printf( "Unknown\n" );
				break;
			}

			i++; ap_cur = ap_cur->next;
		}

		printf( "\n" );

		if( ap_1st->next != NULL )
		{
			do
			{
				printf( "Index number of target network ? " );
				fflush( stdout );
				ret1 = 0;
				while(!ret1) ret1 = scanf( "%127s", buf );

				if( ( n = atoi( buf ) ) < 1 )
					continue;

				i = 1; ap_cur = ap_1st;
				while( ap_cur != NULL && i < n )
					{ i++; ap_cur = ap_cur->next; }
			}
			while( n < 0 || ap_cur == NULL );
		}
		else
		{
			printf( "Choosing first network as target.\n" );
			sleep( 2 );
			ap_cur = ap_1st;
		}

		printf( "\n" );

		memcpy( opt.bssid, ap_cur->bssid,  6 );
		opt.bssid_set = 1;
	}

	/* mark the targeted access point(s) */

	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		if( memcmp( opt.maddr, BROADCAST, 6 ) == 0 ||
			( opt.bssid_set && ! memcmp( opt.bssid, ap_cur->bssid, 6 ) ) ||
			( opt.essid_set && ! strcmp( opt.essid, ap_cur->essid    ) ) )
			ap_cur->target = 1;

		ap_cur = ap_cur->next;
	}

	ap_cur = ap_1st;

	while( ap_cur != NULL )
	{
		if( ap_cur->target )
			break;

		ap_cur = ap_cur->next;
	}

	if( ap_cur == NULL )
	{
		printf( "No matching network found - check your %s.\n",
			( opt.essid_set ) ? "essid" : "bssid" );

		goto exit_main;
	}

	if( ap_cur->crypt < 2 )
	{
		switch( ap_cur->crypt )
		{
			case  0:
				printf( "Target network doesn't seem encrypted.\n" );
				break;

			default:
				printf( "Got no data packets from target network!\n" );
				break;
		}

		goto exit_main;
	}

	/* create the cracker<->master communication pipes */

	for( i = 0; i < opt.nbcpu; i++ )
	{
		unused = pipe( mc_pipe[i] );
		unused = pipe( cm_pipe[i] );

		if (opt.amode<=1 && opt.nbcpu>1 && opt.do_brute && opt.do_mt_brute)
		{
			unused = pipe(bf_pipe[i]);
			bf_nkeys[i] = 0;
		}
	}

	/* launch the attack */

	nb_tried = 0;
	nb_kprev = 0;

	chrono( &t_begin, 1 );
	chrono( &t_stats, 1 );
	chrono( &t_kprev, 1 );

	signal( SIGWINCH, sighandler );

	if( opt.amode == 1 )
		goto crack_wep;

	if( opt.amode == 2 )
		goto crack_wpa;

	if( ap_cur->crypt == 2 )
	{
		crack_wep:

		if( opt.keylen == 0 )
			opt.keylen = 13;

		if(j + opt.do_brute > 4)
		{
			printf( "Specified more then 4 bytes to bruteforce!" );
			goto exit_main;
		}

		for( i=0; i<opt.do_brute; i++)
		{
			opt.brutebytes[j+i] = opt.keylen -1 -i;
		}

		opt.do_brute += j;

		if( opt.ffact == 0 )
		{
                        if( opt.do_ptw ) opt.ffact = 2;
                        else
                        {
                            if( ! opt.do_testy )
                            {
                                if( opt.keylen == 5 )
                                    opt.ffact = 5;
                                else
                                    opt.ffact = 2;
                            }
                            else
                                opt.ffact = 30;
                        }
                }

		memset( &wep, 0, sizeof( wep ) );

		if (opt.do_ptw)
		{
			if(!opt.is_quiet)
				printf("Attack will be restarted every %d captured ivs.\n", PTW_TRY_STEP);
			opt.next_ptw_try = ap_cur->nb_ivs - (ap_cur->nb_ivs % PTW_TRY_STEP);
			do
			{
				if(ap_cur->nb_ivs >= opt.next_ptw_try)
				{
					if(!opt.is_quiet)
						printf("Starting PTW attack with %ld ivs.\n", ap_cur->nb_ivs);
					ret = crack_wep_ptw(ap_cur);
					if(ret)
					{
						opt.next_ptw_try += PTW_TRY_STEP;
						printf("Failed. Next try with %d IVs.\n", opt.next_ptw_try);
					}
				}
				if(ret)
					usleep(10000);
			}while(ret != 0);
		}
		else if(opt.dict != NULL)
		{
			ret = crack_wep_dict();
		}
		else
		{
			for( i = 0; i < opt.nbcpu; i++ )
			{
				/* start one thread per cpu */

				pthread_t tid;

				if (opt.amode<=1 && opt.nbcpu>1 && opt.do_brute && opt.do_mt_brute)
				{
					if (pthread_create( &tid, NULL, (void *) inner_bruteforcer_thread,
						(void *) (long) i ) != 0)
					{
						perror( "pthread_create failed" );
						goto exit_main;
					}
				}

				if( pthread_create( &tid, NULL, (void *) crack_wep_thread,
					(void *) (long) i ) != 0 )
				{
					perror( "pthread_create failed" );
					goto exit_main;
				}
			}

			if( ! opt.do_testy )
			{
				do   { ret = do_wep_crack1( 0 ); }
				while( ret == RESTART );

				if( ret == FAILURE )
				{
					printf( "   Attack failed. Possible reasons:\n\n"
						"     * Out of luck: you must capture more IVs. Usually, 104-bit WEP\n"
						"       can be cracked with about one million IVs, sometimes more.\n\n"
						"     * If all votes seem equal, or if there are many negative votes,\n"
						"       then the capture file is corrupted, or the key is not static.\n\n"
						"     * A false positive prevented the key from being found.  Try to\n"
						"       disable each korek attack (-k 1 .. 17), raise the fudge factor\n"
						"       (-f)" );
					if (opt.do_testy)
						printf( "and try the experimental bruteforce attacks (-y)." );
					printf( "\n" );
				}
			}
			else
			{
				for( i = opt.keylen - 3; i < opt.keylen - 2; i++ )
				{
					do   { ret = do_wep_crack2( i ); }
					while( ret == RESTART );

					if( ret == SUCCESS )
						break;
				}

				if( ret == FAILURE )
				{
					printf( "   Attack failed. Possible reasons:\n\n"
						"     * Out of luck: you must capture more IVs. Usually, 104-bit WEP\n"
						"       can be cracked with about one million IVs, sometimes more.\n\n"
						"     * If all votes seem equal, or if there are many negative votes,\n"
						"       then the capture file is corrupted, or the key is not static.\n\n"
						"     * A false positive prevented the key from being found.  Try to\n"
						"       disable each korek attack (-k 1 .. 17), raise the fudge factor\n"
						"       (-f)" );
					if (opt.do_testy)
						printf( "or try the standard attack mode instead (no -y option)." );
					printf( "\n" );
				}
			}
		}
	}

	if( ap_cur->crypt == 3 )
	{
		crack_wpa:

		if ( opt.dict == NULL )
			goto nodict;

		ap_cur = ap_1st;

		while( ap_cur != NULL )
		{
			if( ap_cur->target && ap_cur->wpa.state == 15 )
				break;

			ap_cur = ap_cur->next;
		}

		if( ap_cur == NULL )
		{
			printf( "No valid WPA handshakes found.\n" );
			goto exit_main;
		}

		if( memcmp( ap_cur->essid, ZERO, 32 ) == 0 && ! opt.essid_set )
		{
			printf( "An ESSID is required. Try option -e.\n" );
			goto exit_main;
		}

		if( opt.essid_set && ap_cur->essid[0] == '\0' )
		{
			memset(  ap_cur->essid, 0, sizeof( ap_cur->essid ) );
			strncpy( ap_cur->essid, opt.essid, sizeof( ap_cur->essid ) - 1 );
		}

		for( i = 0; i < opt.nbcpu; i++ )
		{
			/* start one thread per cpu */

			pthread_t tid;

			if( pthread_create( &tid, NULL, (void *) crack_wpa_thread,
				(void *) (long) i ) != 0 )
			{
				perror( "pthread_create failed" );
				goto exit_main;
			}
		}

		ret = do_wpa_crack( ap_cur );
	}

	exit_main:

	#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
	#endif
	if( ! opt.is_quiet )
		printf( "\n" );

	fflush( stdout );

	if( ret == SUCCESS ) kill( 0, SIGQUIT );
	if( ret == FAILURE ) kill( 0, SIGTERM );

	_exit( ret );
}
