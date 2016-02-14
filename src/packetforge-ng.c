/*
 *  802.11 ARP-request WEP packet forgery
 *  UDP, ICMP and custom packet forging developped by Martin Beck
 *
 *  Copyright (C) 2006-2016 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005  Christophe Devine (arpforge)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <getopt.h>
#include "version.h"
#include "pcap.h"
#include "crypto.h"
#include "osdep/byteorder.h"
#include "common.h"

#define ARP_REQ \
    "\x08\x00\x02\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x80\x01\xAA\xAA\x03\x00" \
    "\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xCC\xCC\xCC\xCC" \
    "\xCC\xCC\x11\x11\x11\x11\x00\x00\x00\x00\x00\x00\x22\x22\x22\x22" \
    "\x00\x00\x00\x00\x00\x00\x00\x00"

#define UDP_PACKET      \
    "\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"  \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"  \
    "\x45\x00\x00\x1D\x00\x00\x40\x00\x40\x11\x00\x00\xC3\xBE\x8E\x74"  \
    "\xC1\x16\x02\x01\x83\x86\x86\x29\x00\x00\x00\x00\x05"

#define ICMP_PACKET      \
    "\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"  \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"  \
    "\x45\x00\x00\x1C\x00\x00\x40\x00\x40\x01\x00\x00\xC3\xBE\x8E\x74"  \
    "\xC1\x16\x02\x01\x08\x00\x83\xDC\x74\x22\x00\x01"

#define NULL_PACKET      \
    "\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"  \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern int getmac(char * macAddress, int strict, unsigned char * mac);
extern int add_crc32(unsigned char* data, int length);


char usage[] =
"\n"
"  %s - (C) 2006-2015 Thomas d\'Otreppe\n"
"  Original work: Martin Beck\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  Usage: packetforge-ng <mode> <options>\n"
"\n"
"  Forge options:\n"
"\n"
"      -p <fctrl>     : set frame control word (hex)\n"
"      -a <bssid>     : set Access Point MAC address\n"
"      -c <dmac>      : set Destination  MAC address\n"
"      -h <smac>      : set Source       MAC address\n"
"      -j             : set FromDS bit\n"
"      -o             : clear ToDS bit\n"
"      -e             : disables WEP encryption\n"
"      -k <ip[:port]> : set Destination IP [Port]\n"
"      -l <ip[:port]> : set Source      IP [Port]\n"
"      -t ttl         : set Time To Live\n"
"      -w <file>      : write packet to this pcap file\n"
"      -s <size>      : specify size of null packet\n"
"      -n <packets>   : set number of packets to generate\n"
"\n"
"  Source options:\n"
"\n"
"      -r <file>      : read packet from this raw file\n"
"      -y <file>      : read PRGA from this file\n"
"\n"
"  Modes:\n"
"\n"
"      --arp          : forge an ARP packet    (-0)\n"
"      --udp          : forge an UDP packet    (-1)\n"
"      --icmp         : forge an ICMP packet   (-2)\n"
"      --null         : build a null packet    (-3)\n"
"      --custom       : build a custom packet  (-9)\n"
"\n"
"      --help         : Displays this usage screen\n"
"\n";

struct options
{
    unsigned char bssid[6];
    unsigned char dmac[6];
    unsigned char smac[6];
    unsigned char dip[4];
    unsigned char sip[4];
    unsigned char fctrl[2];
    unsigned char *prga;

    char *cap_out;
    char *raw_file;

    int mode;
    int pktlen;
    int prgalen;
    int ttl;
    int size;

    unsigned short sport;
    unsigned short dport;

    char tods;
    char fromds;
    char encrypt;

    FILE* ivs2;
    unsigned char prev_bssid[6];
    int first_packet;

    int num_packets;
} opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
}
dev;

unsigned char h80211[2048];
unsigned char tmpbuf[2048];

int capture_ask_packet( int *caplen )
{
    time_t tr;
    struct timeval tv;

    long nb_pkt_read;
    int i, j, n, mi_b, mi_s, mi_d;
    int ret;

    struct pcap_pkthdr pkh;

    tr = time( NULL );

    nb_pkt_read = 0;

    if(opt.raw_file == NULL)
    {
        printf("Please specify an input file (-r).\n");
        return 1;
    }

    while( 1 )
    {
        if( time( NULL ) - tr > 0 )
        {
            tr = time( NULL );
            printf( "\rRead %ld packets...\r", nb_pkt_read );
            fflush( stdout );
        }

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

        nb_pkt_read++;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
            default: mi_b = 10; mi_d = 16; mi_s = 24; break;
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
        ret=0;
        while(!ret) ret = scanf( "%s", tmpbuf );
        printf( "\n" );

        if( tmpbuf[0] == 'y' || tmpbuf[0] == 'Y' )
            break;
    }

    return( 0 );
}

int packet_dump(unsigned char* packet, int length)
{
    int i;

    if(packet == NULL) return 1;
    if(length <= 0 || length > 2048) return 1;

    for(i=0; i<length; i++)
    {
        if(i%16 == 0) printf("\n");
        printf("%02X ", packet[i]);
    }
    printf("\n");

    return 0;
}

/* IP address parsing routine */
int getip( char *s, unsigned char *ip , unsigned short *port)
{
    int i = 0, n;

    while( sscanf( s, "%d", &n ) == 1 )
    {
        if( n < 0 || n > 255 )
            return( 1 );

        ip[i] = n;

        if( ++i == 4 ) break;

        if( ! ( s = strchr( s, '.' ) ) )
            break;

        s++;
    }

    if(i != 4) return 1;

    if( ( s = strchr( s, ':' ) ) && i == 4 )
    {
        s++;
        if( sscanf( s, "%d", &n ) == 1 )
        {
            if(n > 0 && n < 65536)
                *port = n;
        }
    }

    return( i != 4 );
}

unsigned short ip_chksum(unsigned short* addr, int count)
{
	unsigned short checksum;
	   /* Compute Internet Checksum for "count" bytes
		*         beginning at location "addr".
		*/

	unsigned long sum = 0;

	while( count > 1 )  {
	   /*  This is the inner loop */
		   sum += *addr;
		   addr++;
		   count -= 2;
	}

	   /*  Add left-over byte, if any */
	if( count > 0 )
		   sum += * (unsigned char *) addr;

	   /*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
	   sum = (sum & 0xffff) + (sum >> 16);

	checksum = ~sum;

    return checksum;
}

int set_tofromds(unsigned char* packet)
{
    if(packet == NULL) return 1;

    /* set TODS,FROMDS bits */
    if( ((opt.tods&1) == 1) && ((opt.fromds&1) == 1) )
    {
        packet[1] = (packet[1] & 0xFC) | 0x03;    /* set TODS=1,FROMDS=1 */
    }

    if( ((opt.tods&1) == 1) && ((opt.fromds&1) == 0) )
    {
        packet[1] = (packet[1] & 0xFC) | 0x01;    /* set TODS=1,FROMDS=0 */
    }

    if( ((opt.tods&1) == 0) && ((opt.fromds&1) == 1) )
    {
        packet[1] = (packet[1] & 0xFC) | 0x02;    /* set TODS=0,FROMDS=1 */
    }

    if( ((opt.tods&1) == 0) && ((opt.fromds&1) == 0) )
    {
        packet[1] = (packet[1] & 0xFC);           /* set TODS=0,FROMDS=0 */
    }

    return 0;
}

int set_bssid(unsigned char* packet)
{
    int mi_b;

    if(packet == NULL) return 1;

    if( memcmp(opt.bssid, NULL_MAC, 6) == 0 )
    {
        printf("Please specify a BSSID (-a).\n");
        return 1;
    }

    switch( packet[1] & 3 )
    {
        case  0: mi_b = 16; break;
        case  1: mi_b =  4; break;
        case  2: mi_b = 10; break;
        default: mi_b = 10; break;
    }

    /* write bssid mac */
    memcpy(packet+mi_b, opt.bssid, 6);

    return 0;
}

int set_dmac(unsigned char* packet)
{
    int mi_d;

    if(packet == NULL) return 1;

    if( memcmp(opt.dmac, NULL_MAC, 6) == 0 )
    {
        printf("Please specify a destination MAC (-c).\n");
        return 1;
    }

    switch( packet[1] & 3 )
    {
        case  0: mi_d =  4; break;
        case  1: mi_d = 16; break;
        case  2: mi_d =  4; break;
        default: mi_d = 16; break;
    }

    /* write destination mac */
    memcpy(packet+mi_d, opt.dmac, 6);

    return 0;
}

int set_smac(unsigned char* packet)
{
    int mi_s;

    if(packet == NULL) return 1;

    if( memcmp(opt.smac, NULL_MAC, 6) == 0 )
    {
        printf("Please specify a source MAC (-h).\n");
        return 1;
    }

    switch( packet[1] & 3 )
    {
        case  0: mi_s = 10; break;
        case  1: mi_s = 10; break;
        case  2: mi_s = 16; break;
        default: mi_s = 24; break;
    }

    /* write source mac */
    memcpy(packet+mi_s, opt.smac, 6);

    return 0;
}

/* offset for ip&&udp = 48, for arp = 56 */
int set_dip(unsigned char* packet, int offset)
{
    if(packet == NULL) return 1;
    if(offset < 0 || offset > 2046) return 1;

    if( memcmp(opt.dip, NULL_MAC, 4) == 0 )
    {
        printf("Please specify a destination IP (-k).\n");
        return 1;
    }

    /* set destination IP */
    memcpy(packet+offset, opt.dip, 4);

    return 0;
}

/* offset for ip&&udp = 44, for arp = 46 */
int set_sip(unsigned char* packet, int offset)
{
    if(packet == NULL) return 1;
    if(offset < 0 || offset > 2046) return 1;

    if( memcmp(opt.sip, NULL_MAC, 4) == 0 )
    {
        printf("Please specify a source IP (-l).\n");
        return 1;
    }

    /* set source IP */
    memcpy(packet+offset, opt.sip, 4);

    return 0;
}

int set_ipid(unsigned char* packet, int offset)
{
    unsigned short id;

    if(packet == NULL) return 1;
    if(offset < 0 || offset > 2046) return 1;

    id = (rand()&0xFFFF);
    /* set IP Identification */
    memcpy(packet+offset, (unsigned char*)&id , 2);

    return 0;
}

int set_dport(unsigned char* packet)
{
    unsigned short port;

    if(packet == NULL) return 1;

    port = ((opt.dport >> 8) & 0xFF) + ((opt.dport << 8) & 0xFF00);
    memcpy(packet+54, &port, 2);

    return 0;
}

int set_sport(unsigned char* packet)
{
    unsigned short port;

    if(packet == NULL) return 1;

    port = ((opt.sport >> 8) & 0xFF) + ((opt.sport << 8) & 0xFF00);
    memcpy(packet+52, &port, 2);

    return 0;
}

int set_ip_ttl(unsigned char* packet)
{
    unsigned char ttl;

    if(packet == NULL) return 1;

    ttl = opt.ttl;
    memcpy(packet+40, &ttl, 1);

    return 0;
}

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

int next_keystream(unsigned char *dest, int size, unsigned char *bssid, int minlen)
{
    struct ivs2_pkthdr ivs2;
    char *buffer;
    int gotit=0;

    if(opt.ivs2 == NULL) return -1;
    if(minlen > size+4) return -1;

    while( fread( &ivs2, sizeof(struct ivs2_pkthdr), 1, opt.ivs2 ) == 1 )
    {
        if(ivs2.flags & IVS2_BSSID)
        {
            if ( (int) fread( opt.prev_bssid, 6, 1, opt.ivs2) != 1)
                return -1;
            ivs2.len -= 6;
        }

        if(ivs2.len == 0)
            continue;

        buffer = (char*) malloc( ivs2.len );
        if(buffer == NULL)
            return -1;

        if( (int) fread( buffer, ivs2.len, 1, opt.ivs2 ) != 1)
        {
            free(buffer);
            return -1;
        }

        if( memcmp(bssid, opt.prev_bssid, 6) != 0 )
        {
            free(buffer);
            continue;
        }

        if( (ivs2.flags & IVS2_XOR) && ivs2.len >= (minlen+4) && !gotit)
        {
            if(size >= ivs2.len)
            {
                memcpy(dest, buffer, ivs2.len);
                opt.prgalen = ivs2.len;
            }
            else
            {
                memcpy(dest, buffer, size);
                opt.prgalen = size;
            }
            gotit=1;
        }
        free(buffer);
        if(gotit)
            return 0;
    }

    if(feof( opt.ivs2 ))
    {
        fseek( opt.ivs2, sizeof(IVS2_MAGIC)+sizeof(struct ivs2_filehdr) -1, SEEK_SET);
        return 1;
    }
    return -1;
}

int encrypt_data(unsigned char *dest, unsigned char* data, int length)
{
    unsigned char cipher[2048];
    int n;

    if(dest == NULL)                return 1;
    if(data == NULL)                return 1;
    if(length < 1 || length > 2044) return 1;

    if(opt.prga == NULL && opt.ivs2 == NULL)
    {
        printf("Please specify a XOR or %s file (-y).\n", IVS2_EXTENSION);
        return 1;
    }

    if( opt.ivs2 != NULL )
    {
        n = next_keystream(opt.prga, 1500, opt.bssid, length);
        if(n < 0)
        {
            printf("Error getting keystream.\n");
            return 1;
        }
        if(n==1)
        {
            if(opt.first_packet == 1)
            {
                printf("Error no keystream in %s file is long enough (%d).\n", IVS2_EXTENSION, length);
                return 1;
            }
            else
                n = next_keystream(opt.prga, 1500, opt.bssid, length);
        }
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
    if( set_IVidx(packet) != 0 )                             return 1;

    /* set WEP bit */
    packet[1] = packet[1] | 0x40;

    *length+=8;
    /* now you got yourself a shiny, brand new encrypted wep packet ;) */

    return 0;
}

int read_raw_packet(unsigned char* dest, char* srcfile, int length)
{
    size_t readblock;
    FILE *f;

    if(dest    == NULL) return 1;
    if(srcfile == NULL) return 1;
    if(length  <= 0   ) return 1;
    if(length  >= 2048) return 1;

    f = fopen(srcfile, "rb");
    if(f == NULL)
    {
        perror("fopen failed.");
        return 1;
    }

    readblock = fread(dest, (size_t)1, (size_t)length, f);
    if(readblock != (size_t)length)
    {
        perror("fread failed");
        fclose(f);
        return 1;
    }

    fclose(f);
    return 0;
}

int write_cap_packet(unsigned char* packet, int length)
{
    FILE *f;
    struct pcap_file_header pfh;
    struct pcap_pkthdr pkh;
    struct timeval tv;
    int n;

    if( opt.cap_out == NULL )
    {
        printf("Please specify an output file (-w).\n");
        return 1;
    }

    if(opt.first_packet)
    {
        if( ( f = fopen( opt.cap_out, "wb+" ) ) == NULL )
        {
            fprintf( stderr, "failed: fopen(%s,wb+)\n", opt.cap_out );
            return( 1 );
        }

        pfh.magic           = TCPDUMP_MAGIC;
        pfh.version_major   = PCAP_VERSION_MAJOR;
        pfh.version_minor   = PCAP_VERSION_MINOR;
        pfh.thiszone        = 0;
        pfh.sigfigs         = 0;
        pfh.snaplen         = 65535;
        pfh.linktype        = LINKTYPE_IEEE802_11;

        n = sizeof( struct pcap_file_header );

        if( fwrite( &pfh, 1, n, f ) != (size_t) n )
        {
            fprintf( stderr, "failed: fwrite(pcap file header)\n" );
            fclose( f );
            return( 1 );
        }
    }
    else
    {
        if( ( f = fopen( opt.cap_out, "ab+" ) ) == NULL )
        {
            fprintf( stderr, "failed: fopen(%s,ab+)\n", opt.cap_out );
            return( 1 );
        }
    }

    gettimeofday( &tv, NULL );

    pkh.tv_sec  = tv.tv_sec;
    pkh.tv_usec = tv.tv_usec;
    pkh.len     = length;
    pkh.caplen  = length;

    n = sizeof( pkh );

    if( fwrite( &pkh, 1, n, f ) != (size_t) n )
    {
        fprintf( stderr, "fwrite(packet header) failed\n" );
        fclose( f );
        return( 1 );
    }

    n = length;

    if( fwrite( packet, 1, n, f ) != (size_t) n )
    {
        fprintf( stderr, "fwrite(packet data) failed\n");
        fclose( f );
        return( 1 );
    }

    fclose( f );

    if(opt.first_packet)
        opt.first_packet = 0;

    return 0;
}

int read_prga(unsigned char **dest, char *file)
{
    FILE *f;
    int size;
    struct ivs2_filehdr fivs2;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (unsigned char*) malloc(1501);

    if( memcmp( file+(strlen(file)-4), ".xor", 4 ) != 0 && memcmp( file+(strlen(file)-4), "."IVS2_EXTENSION, 4 ) != 0 )
    {
        printf("Is this really a PRGA file: %s?\n", file);
    }

    f = fopen(file, "rb");

    if(f == NULL)
    {
         printf("Error opening %s\n", file);
         return( 1 );
    }

    fseek(f, 0, SEEK_END);
    size = (int)ftell(f);
    rewind(f);

    if(size > 1500) size = 1500;

    if( (int)fread( (*dest), size, 1, f ) != 1 )
    {
        fprintf( stderr, "fread failed\n" );
        fclose( f );
        return( 1 );
    }

    if( memcmp((*dest), IVS2_MAGIC, 4 ) == 0 )
    {
        if( (unsigned) size < sizeof(struct ivs2_filehdr) + 4)
        {
            fprintf( stderr, "No valid %s file.", IVS2_EXTENSION);
            fclose( f );
            return( 1 );
        }
        memcpy( &fivs2, (*dest) + 4, sizeof(struct ivs2_filehdr));
        if(fivs2.version > IVS2_VERSION)
        {
            printf( "Error, wrong %s version: %d. Supported up to version %d.\n", IVS2_EXTENSION, fivs2.version, IVS2_VERSION );
        }

        opt.ivs2 = f;
        fseek(f, sizeof(IVS2_MAGIC)+sizeof(struct ivs2_filehdr)-1, SEEK_SET);
    }
    else
    {
        //assuming old xor file
        if( (*dest)[3] > 0x03 )
        {
            printf("Are you really sure that this is a valid keystream? Because the index is out of range (0-3): %02X\n", (*dest)[3] );
        }

        opt.prgalen = size;
        fclose( f );
    }
    return( 0 );
}

int forge_arp()
{

    /* use arp request */
    opt.pktlen = 60;
    memcpy( h80211, ARP_REQ, opt.pktlen );

    memcpy( opt.dmac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );

    if( set_tofromds(h80211) != 0 ) return 1;
    if( set_bssid(h80211)    != 0 ) return 1;
    if( set_smac(h80211)     != 0 ) return 1;
    if( set_dmac(h80211)     != 0 ) return 1;

    memcpy( h80211 + 40, opt.smac, 6 );

    if( set_dip(h80211, 56)  != 0 ) return 1;
    if( set_sip(h80211, 46)  != 0 ) return 1;

    return 0;
}

int forge_udp()
{
    unsigned short chksum;

    opt.pktlen = 61;
    memcpy(h80211, UDP_PACKET, opt.pktlen);

    if( set_tofromds(h80211) != 0 ) return 1;
    if( set_bssid(h80211)    != 0 ) return 1;
    if( set_smac(h80211)     != 0 ) return 1;
    if( set_dmac(h80211)     != 0 ) return 1;

    if( set_dip(h80211, 48)  != 0 ) return 1;
    if( set_sip(h80211, 44)  != 0 ) return 1;
    if( opt.ttl != -1 )
        if( set_ip_ttl(h80211) != 0 ) return 1;

    if( set_ipid(h80211, 36)  != 0 ) return 1;

    /* set udp length */
    h80211[57] = '\x09';

    /* generate + set ip checksum */
    chksum = ip_chksum((unsigned short*)(h80211+32), 20);
    memcpy(h80211+42, &chksum, 2);

    return 0;
}

int forge_icmp()
{
    unsigned short chksum;

    opt.pktlen = 60;
    memcpy(h80211, ICMP_PACKET, opt.pktlen);

    if(memcmp(opt.dmac, NULL_MAC, 6) == 0)
    {
        memcpy( opt.dmac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );
    }

    if( set_tofromds(h80211) != 0 ) return 1;
    if( set_bssid(h80211)    != 0 ) return 1;
    if( set_smac(h80211)     != 0 ) return 1;
    if( set_dmac(h80211)     != 0 ) return 1;

    if( set_dip(h80211, 48)  != 0 ) return 1;
    if( set_sip(h80211, 44)  != 0 ) return 1;
    if( opt.ttl != -1 )
        if( set_ip_ttl(h80211) != 0 ) return 1;

    if( set_ipid(h80211, 36)  != 0 ) return 1;

    /* generate + set ip checksum */
    chksum = ip_chksum((unsigned short*)(h80211+32), 20);
    memcpy(h80211+42, &chksum, 2);

    return 0;
}

int forge_null()
{
    opt.pktlen = opt.size;
    memcpy(h80211, NULL_PACKET, 24);
    memset(h80211+24, '\0', (opt.pktlen - 24));

    if(memcmp(opt.dmac, NULL_MAC, 6) == 0)
    {
        memcpy( opt.dmac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6 );
    }

    if( set_tofromds(h80211) != 0 ) return 1;
    if( set_bssid(h80211)    != 0 ) return 1;
    if( set_smac(h80211)     != 0 ) return 1;
    if( set_dmac(h80211)     != 0 ) return 1;

    if( opt.pktlen > 26 )
        h80211[26]=0x03;

    return 0;
}

int forge_custom()
{
    if(capture_ask_packet( &opt.pktlen ) != 0) return 1;
//    if(read_raw_packet(h80211, opt.raw_file, opt.pktlen) != 0) return 1;

    if( set_tofromds(h80211) != 0 ) return 1;

    if(memcmp(opt.bssid, NULL_MAC, 6) != 0)
    {
        if( set_bssid(h80211) != 0 ) return 1;
    }
    if(memcmp(opt.dmac, NULL_MAC, 6) != 0)
    {
        if( set_dmac(h80211) != 0 ) return 1;
    }
    if(memcmp(opt.smac, NULL_MAC, 6) != 0)
    {
        if( set_smac(h80211) != 0 ) return 1;
    }

    return 0;
}

void print_usage(void)
{
    char *version_info = getVersion("Packetforge-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
    printf(usage, version_info);
    free(version_info);
}

int main(int argc, char* argv[])
{
    int arg;
    int option_index;
    int ret;
    int n;

    memset( &opt, 0, sizeof( opt ) );

    /* initialise global options */
    memset(opt.bssid, '\x00', 6);
    memset(opt.dmac,  '\x00', 6);
    memset(opt.smac,  '\x00', 6);
    memset(opt.dip,   '\x00', 4);
    memset(opt.sip,   '\x00', 4);
    memset(opt.fctrl, '\x00', 2);

    opt.prga     = NULL;
    opt.cap_out  = NULL;
    opt.raw_file = NULL;

    opt.mode    = -1;
    opt.pktlen  = -1;
    opt.prgalen = -1;
    opt.ttl     = -1;

    opt.sport   = -1;
    opt.dport   = -1;

    opt.tods    =  1;
    opt.fromds  =  0;
    opt.encrypt =  1;

    opt.size    = 30;

    opt.ivs2    = NULL;
    memset(opt.prev_bssid, '\x00', 6);

    opt.first_packet    = 1;
    opt.num_packets      = 1;

    srand(time(NULL));

    while( 1 )
    {
        static struct option long_options[] = {
            {"arp",      0, 0, '0'},
            {"udp",      0, 0, '1'},
            {"icmp",     0, 0, '2'},
            {"null",     0, 0, '3'},
            {"custom",   0, 0, '9'},
            {"help",     0, 0, 'H'},
            {0,          0, 0,  0 }
        };

        int option;
	option_index = 0;
	option = getopt_long( argc, argv,
                        "p:a:c:h:jok:l:j:r:y:01239w:et:s:Hn:",
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

            case 'p' :

                ret = sscanf( optarg, "%x", &arg );
                if( arg < 0 || arg > 65535 || ret != 1)
                {
                    printf( "Invalid frame control word. [0-65535]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.fctrl[0]=((arg>>8)&0xFF);
                opt.fctrl[1]=(arg&0xFF);
                break;

            case 't' :

                ret = sscanf( optarg, "%i", &arg );
                if( arg < 0 || arg > 255 || ret != 1)
                {
                    printf( "Invalid time to live. [0-255]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.ttl = arg;
                break;

            case 'n' :

                ret = sscanf( optarg, "%i", &arg );
                if( arg <= 0 || ret != 1)
                {
                    printf( "Invalid number of packets. [>=1]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.num_packets = arg;
                break;

            case 'a' :

                if( getmac( optarg, 1, opt.bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'c' :

                if( getmac( optarg, 1, opt.dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'h' :

                if( getmac( optarg, 1, opt.smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'j' :

                opt.fromds = 1;
                break;

            case 'o' :

                opt.tods = 0;
                break;

            case 'e' :

                opt.encrypt = 0;
                break;

            case 'r' :

                if( opt.raw_file != NULL )
                {
                    printf( "Packet source already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.raw_file = optarg;
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
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'w' :

                if( opt.cap_out != NULL )
                {
                    printf( "Output file already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.cap_out = optarg;

                break;

            case 'k' :

                if( getip(optarg, opt.dip, &(opt.dport)) != 0 )
                {
                    printf( "Invalid destination IP address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return 1;
                }
                break;

            case 'l' :

                if( getip(optarg, opt.sip, &(opt.sport)) != 0 )
                {
                    printf( "Invalid source IP address.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return 1;
                }
                break;

            case 's' :

                ret = sscanf( optarg, "%i", &arg );
                if( arg < 26 || arg > 1520 || ret != 1)
                {
                    printf( "Invalid packet size. [26-1520]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.size = arg;
                break;

            case '0' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.mode = 0;

                break;

            case '1' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.mode = 1;
                break;

            case '2' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.mode = 2;
                break;

            case '3' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.mode = 3;
                break;

            case '9' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                opt.mode = 9;
                break;

            case 'H' :

                print_usage();
                return( 1 );

            default : break;

        }
    }

    if(argc == 1)
    {
        print_usage();
        printf("Please specify a mode.\n");
        return( 1 );
    }

    if( opt.raw_file != NULL )
    {
        if( ! ( dev.f_cap_in = fopen( opt.raw_file, "rb" ) ) )
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
                             "TCPDUMP_MAGIC).\n", opt.raw_file );
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

    for(n=0; n<opt.num_packets; n++)
    {
        switch (opt.mode)
        {
            case 0:
                if( forge_arp() != 0 )
                {
                    printf("Error building an ARP packet.\n");
                    return 1;
                }
                break;
            case 1:
                if( forge_udp() != 0 )
                {
                    printf("Error building an UDP packet.\n");
                    return 1;
                }
                break;
            case 2:
                if( forge_icmp() != 0 )
                {
                    printf("Error building an ICMP packet.\n");
                    return 1;
                }
                break;

            case 3:
                if( forge_null() != 0 )
                {
                    printf("Error building a NULL packet.\n");
                    return 1;
                }
                break;

            case 9:
                if( forge_custom() != 0 )
                {
                    printf("Error building a custom packet.\n");
                    return 1;
                }
                break;
            default:
                    print_usage();
                    printf("Please specify a mode.\n");
                    return 1;
        }

        if(opt.encrypt)
        {
            if( create_wep_packet(h80211, &(opt.pktlen)) != 0 )
                    return 1;
        }
        else
        {
            /* set WEP bit = 0 */
            h80211[1] = h80211[1] & 0xBF;
        }

        if( write_cap_packet(h80211, opt.pktlen) != 0 )
        {
            printf("Error writing pcap file %s.\n", opt.cap_out);
            return 1;
        }
    }
    printf( "Wrote packet%s to: %s\n", (opt.num_packets > 1?"s":""), opt.cap_out );

    if(opt.ivs2)
        fclose(opt.ivs2);

    return 0;
}
