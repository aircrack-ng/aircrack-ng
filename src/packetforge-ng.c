/*
 *  802.11 ARP-request WEP packet forgery
 *
 *  Copyright (C) 2006 Thomas d'Otreppe
 *  Copyright (C) 2004,2005  Christophe Devine (arpforge)
 *
 *  UDP, ICMP and custom packet forging developped by Martin Beck
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <getopt.h>
#include "version.h"
#include "pcap.h"

#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#define BROADCAST       "\xFF\xFF\xFF\xFF\xFF\xFF"

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


extern char * getVersion(char * progname, int maj, int min, int submin, int betavers);
extern int getmac(char * macAddress, int strict, unsigned char * mac);
extern int add_crc32(unsigned char* data, int length);


char usage[] =
"\n"
"  %s - (C) 2006 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine and Martin Beck\n"
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
"      -k <ip[:port]> : set Source      IP [Port]\n"
"      -l <ip[:port]> : set Destination IP [Port]\n"
"      -t ttl         : set Time To Live\n"
"      -w <file>      : write packet to this pcap file\n"
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
"      --custom       : build a custom packet  (-9)\n"
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

    unsigned short sport;
    unsigned short dport;

    char tods;
    char fromds;
    char encrypt;
} opt;

unsigned char h80211[2048];

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
        default: mi_b =  4; break;
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
	
    return 0;
}

int read_prga(unsigned char **dest, char *file)
{
    FILE *f;
    int size;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (unsigned char*) malloc(1501);

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

    opt.prgalen = size;

    fclose( f );
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

    /* generate + set ip checksum */
    chksum = ip_chksum((unsigned short*)(h80211+32), 20);
    memcpy(h80211+42, &chksum, 2);

    return 0;
}

int forge_custom()
{
    if(read_raw_packet(h80211, opt.raw_file, opt.pktlen) != 0) return 1;

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
    printf(usage, getVersion("Packetforge-ng", _MAJ, _MIN, _SUB_MIN, _BETA) );
}

int main(int argc, char* argv[])
{
    int arg;
    int option_index;

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

    while( 1 )
    {
        option_index = 0;

        static struct option long_options[] = {
            {"arp",      0, 0, '0'},
            {"udp",      0, 0, '1'},
            {"icmp",     0, 0, '2'},
            {"custom",   1, 0, '9'},
            {0,          0, 0,  0 }
        };

        int option = getopt_long( argc, argv,
                        "p:a:c:h:jok:l:j:r:y:0129:w:et:",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :
                break;

            case 'p' :

                sscanf( optarg, "%x", &arg );
                if( arg < 0 || arg > 65355 )
                {
                    printf( "Invalid frame control word.\n" );
                    return( 1 );
                }
                opt.fctrl[0]=((arg>>8)&0xFF);
                opt.fctrl[1]=(arg&0xFF);
                break;

            case 't' :

                sscanf( optarg, "%i", &arg );
                if( arg < 0 || arg > 255 )
                {
                    printf( "Invalid time to live.\n" );
                    return( 1 );
                }
                opt.ttl = arg;
                break;

            case 'a' :

                if( getmac( optarg, 1, opt.bssid ) != 0 )
                {
                    printf( "Invalid AP MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'c' :

                if( getmac( optarg, 1, opt.dmac ) != 0 )
                {
                    printf( "Invalid destination MAC address.\n" );
                    return( 1 );
                }
                break;

            case 'h' :

                if( getmac( optarg, 1, opt.smac ) != 0 )
                {
                    printf( "Invalid source MAC address.\n" );
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
                    return( 1 );
                }
                opt.raw_file = optarg;
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

            case 'w' :

                if( opt.cap_out != NULL )
                {
                    printf( "Output file already specified.\n" );
                    return( 1 );
                }
                opt.cap_out = optarg;

                break;

            case 'k' :

                if( getip(optarg, opt.dip, &(opt.dport)) != 0 )
                {
                    printf( "Invalid destination IP address.\n" );
                    return 1;
                }
                break;

            case 'l' :

                if( getip(optarg, opt.sip, &(opt.sport)) != 0 )
                {
                    printf( "Invalid source IP address.\n" );
                    return 1;
                }
                break;

            case '0' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    return( 1 );
                }
                opt.mode = 0;

                break;

            case '1' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    return( 1 );
                }
                opt.mode = 1;
                break;

            case '2' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    return( 1 );
                }
                opt.mode = 2;
                break;

            case '9' :

                if( opt.mode != -1 )
                {
                    printf( "Mode already specified.\n" );
                    return( 1 );
                }

                opt.pktlen = atoi(optarg);
                if(opt.pktlen < 24 || opt.pktlen > 2048)
                {
                    printf( "Invalid packet length.\n" );
                    return 1;
                }
                opt.mode = 9;
                break;

            default :

                if(opt.mode != -1)break;
                print_usage();
                return 1;
        }
    }

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
		case 9:
		        if( forge_custom() != 0 )
		        {
		            printf("Error building a custom packet.\n");
		            return 1;
        		}
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

    return 0;
}
