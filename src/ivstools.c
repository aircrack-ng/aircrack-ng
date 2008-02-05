/*
 *  IVS Tools - Convert or merge ivs
 *
 *  Copyright (C) 2006,2007,2008 Thomas d'Otreppe
 *  Copyright (C) 2004,2005  Christophe Devine (pcap2ivs and mergeivs)
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

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "version.h"
#ifdef WIN32
#include <Windows.h>
#include <airpcap.h>
#endif
#include "pcap.h"

#define SPANTREE_ADDR  "\x01\x80\xC2\x00\x00\x00"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);

void usage(int what)
{
       printf("\n  %s - (C) 2006,2007,2008 Thomas d\'Otreppe\n"
              "  Original work: Christophe Devine\n"
              "  http://www.aircrack-ng.org\n"
              "\n   usage: ", getVersion("ivsTools", _MAJ, _MIN, _SUB_MIN, _REVISION));
       if (what == 0 || what == 1)
          printf( "ivstools --convert <pcap file> <ivs output file>\n"
                  "        Extract ivs from a pcap file\n");
       if (what == 0)
          printf("       ");
       if (what == 0 || what == 2)
          printf("ivstools --merge <ivs file 1> <ivs file 2> .. <output file>\n"
                 "        Merge ivs files\n");
}

int merge( int argc, char *argv[] )
{
    int i, n, unused;
    unsigned long nbw;
    unsigned char buffer[1024];
    FILE *f_in, *f_out;

    if( argc < 5 )
    {
    	usage(2);
        return( 1 );
    }

    printf( "Creating %s\n", argv[argc - 1] );

    if( ( f_out = fopen( argv[argc - 1], "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    nbw = 0;

    for( i = 2; i < argc - 1; ++i )
    {
        printf( "Opening %s\n", argv[i] );

        if( ( f_in = fopen( argv[i], "rb" ) ) == NULL )
        {
            perror( "fopen failed" );
            return( 1 );
        }

        if( fread( buffer, 1, 4, f_in ) != 4 )
        {
            perror( "fread file header failed" );
            return( 1 );
        }

        if( memcmp( buffer, IVSONLY_MAGIC, 4 ) != 0 )
        {
            printf( "%s is not an .ivs file\n", argv[i] );
            return( 1 );
        }

        if( i == 2 )
            unused = fwrite( buffer, 1, 4, f_out );

        while( ( n = fread( buffer, 1, 1024, f_in ) ) > 0 )
        {
            nbw += n;
            unused = fwrite( buffer, 1, n, f_out );
            printf( "%ld bytes written\r", nbw );
        }

        fclose( f_in );

        printf( "\n" );
    }

    fclose( f_out );

    return( 0 );
}


int main( int argc, char *argv[] )
{
    time_t tt;
    int n, z, unused;
    FILE *f_in, *f_out;
    unsigned long nbr;
    unsigned long nbivs;
    unsigned char *h80211;
    unsigned char bssid_cur[6];
    unsigned char bssid_prv[6];
    unsigned char buffer[65536];
    struct pcap_file_header pfh;
    struct pcap_pkthdr pkh;

    if( argc < 4 )
    {
		usage(0);
        return( 1 );
    }

	if (strcmp(argv[1],"--merge")==0) {
		return merge(argc,argv);
	}
	if (strcmp(argv[1],"--convert")) {
		usage(1);
        return( 1 );
	}

    memset( bssid_cur, 0, 6 );
    memset( bssid_prv, 0, 6 );

    /* check the input pcap file */

    printf( "Opening %s\n", argv[2] );

    if( ( f_in = fopen( argv[2], "rb" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    n = sizeof( pfh );

    if( fread( &pfh, 1, n, f_in ) != (size_t) n )
    {
        perror( "fread(pcap file header) failed" );
        return( 1 );
    }

    if( pfh.magic != TCPDUMP_MAGIC &&
        pfh.magic != TCPDUMP_CIGAM )
    {
        printf( "\"%s\" isn't a pcap file (expected "
                "TCPDUMP_MAGIC).\n", argv[2] );
        return( 1 );
    }

    if( pfh.magic == TCPDUMP_CIGAM )
        SWAP32( pfh.linktype );

    if( pfh.linktype != LINKTYPE_IEEE802_11 &&
        pfh.linktype != LINKTYPE_PRISM_HEADER &&
        pfh.linktype != LINKTYPE_RADIOTAP_HDR )
    {
        printf( "\"%s\" isn't a regular 802.11 "
                "(wireless) capture.\n", argv[2] );
        return( 1 );
    }

    /* create the output ivs file */

    printf( "Creating %s\n", argv[3] );

    if( ( f_out = fopen( argv[3], "wb+" ) ) == NULL )
    {
        perror( "fopen failed" );
        return( 1 );
    }

    unused = fwrite( IVSONLY_MAGIC, 1, 4, f_out );

    nbr = 0;
    tt = time( NULL ) - 1;

	nbivs = 0;

    while( 1 )
    {
        if( time( NULL ) - tt > 0 )
        {
            printf( "\33[KRead %ld packets...\r", nbr );
            fflush( stdout );
            tt = time( NULL );
        }

        /* read one packet */

        n = sizeof( pkh );

        if( fread( &pkh, 1, n, f_in ) != (size_t) n )
            break;

        if( pfh.magic == TCPDUMP_CIGAM )
            SWAP32( pkh.caplen );

        n = pkh.caplen;

        if( n <= 0 || n > 65535 )
        {
            printf( "Corrupted file? Invalid packet length: %d.\n", n );
            return( 1 );
        }

        if( fread( buffer, 1, n, f_in ) != (size_t) n )
            break;

        ++nbr;

        h80211 = buffer;

        /* remove any prism/radiotap header */

        if( pfh.linktype == LINKTYPE_PRISM_HEADER )
        {
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
            n = *(unsigned short *)( h80211 + 2 );

            if( n <= 0 || n >= (int) pkh.caplen )
                continue;

            h80211 += n; pkh.caplen -= n;
        }

        /* check if WEP data, min. length & bssid */

        if( ( h80211[0] & 0x0C ) != 0x08 ||
            ( h80211[1] & 0x40 ) != 0x40 )
            continue;

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        if( z + 16 > (int) pkh.caplen )
            continue;

        switch( h80211[1] & 3 )
        {
            case  0: memcpy( bssid_cur, h80211 + 16, 6 ); break;
            case  1: memcpy( bssid_cur, h80211 +  4, 6 ); break;
            case  2: memcpy( bssid_cur, h80211 + 10, 6 ); break;
            default: memcpy( bssid_cur, h80211 +  4, 6 ); break;
        }

        if( memcmp( bssid_cur, bssid_prv, 6 ) != 0 )
        {
            unused = fwrite( bssid_cur, 1, 6, f_out );
            memcpy( bssid_prv, bssid_cur, 6 );
        }
        else
        {
            unused = fwrite( "\xFF", 1, 1, f_out );
        }

        /* Special handling for spanning-tree packets */
        if( memcmp( h80211 +  4, SPANTREE_ADDR, 6 ) == 0 ||
            memcmp( h80211 + 16, SPANTREE_ADDR, 6 ) == 0 )
        {
            h80211[z + 4] = (h80211[z + 4] ^ 0x42) ^ 0xAA;
            h80211[z + 5] = (h80211[z + 5] ^ 0x42) ^ 0xAA;
        }

        unused = fwrite( h80211 + z    , 1, 3, f_out );
        unused = fwrite( h80211 + z + 4, 1, 2, f_out );
        ++nbivs;
    }
    fclose( f_in );
    fclose( f_out );

    printf( "\33[2KRead %ld packets.\n", nbr );

	if ( nbivs > 0 )
		printf( "Written %ld IVs.\n", nbivs);
	else
	{
		remove ( argv[3] );
		puts("No IVs written");
	}

    return( 0 );
}
