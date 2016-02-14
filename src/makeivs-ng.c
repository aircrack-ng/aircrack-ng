 /*
  * Server for osdep network driver.  Uses osdep itself!  [ph33r teh recursion]
  *
  *  Copyright (C) 2006-2016 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
  *  Copyright (C) 2004, 2005 Christophe Devine
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
#include <getopt.h>
#include <time.h>

#include "version.h"
#include "pcap.h"
#include "uniqueiv.h"
#include "common.h"

#define NULL_MAC "\x00\x00\x00\x00\x00\x00"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);

char usage[] =

"\n"
"  %s - (C) 2006-2015 Thomas d\'Otreppe\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: makeivs-ng [options]\n"
"\n"
"  Common options:\n"
"      -b <bssid> : Set access point MAC address\n"
"      -f <num>   : Number of first IV\n"
"      -k <key>   : Target network WEP key in hex\n"
"      -s <num>   : Seed used to setup random generator\n"
"      -w <file>  : Filename to write IVs into\n"
"      -c <num>   : Number of IVs to generate\n"
"      -d <num>   : Percentage of dupe IVs\n"
"      -e <num>   : Percentage of erroneous keystreams\n"
"      -l <num>   : Length of keystreams\n"
"      -n         : Ignores ignores weak IVs\n"
"      -p         : Uses prng algorithm to generate IVs\n"
"\n"
"      --help     : Displays this usage screen\n"
"\n";

int main( int argc, char *argv[] )
{
    int i, j, k, pre_n, n, count=100000, length=16;
    int paramUsed = 0, keylen=0, zero=0, startiv=0, iv=0;
    FILE *f_ivs_out;
    unsigned char K[32];
    unsigned char S[256];
//     unsigned char buffer[64];
    char *s, *filename=NULL;
    struct ivs2_pkthdr ivs2;
    struct ivs2_filehdr fivs2;
    unsigned long long size;
    int option_index, option, crypt=0;
    char buf[2048];
    int weplen=0, nofms=0, prng=0;
    float errorrate=0, dupe=0;
    unsigned char bssid[6];
    int seed=time(NULL), z;
    int maxivs=0x1000000;
    unsigned char byte;
    unsigned char **uiv_root;

    static struct option long_options[] = {
        {"key",      1, 0, 'k'},
        {"write",    1, 0, 'w'},
        {"count",    1, 0, 'c'},
        {"seed",     1, 0, 's'},
        {"length",   1, 0, 'l'},
        {"first",    1, 0, 'f'},
        {"bssid",    1, 0, 'b'},
        {"dupe",     1, 0, 'd'},
        {"error",    1, 0, 'e'},
        {"nofms",    0, 0, 'n'},
        {"prng",     0, 0, 'p'},
        {"help",     0, 0, 'H'},
        {0,          0, 0,  0 }
    };

    i = 0;
    memset(K, 0, 32);
    memset(bssid, 0, 6);
    uiv_root = uniqueiv_init();

    /* check the arguments */

    do
    {
        option_index = 0;

        option = getopt_long( argc, argv,
                        "k:w:c:s:l:f:b:d:e:npHh",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':':

                goto usage;
                break;

            case '?':

                goto usage;
                break;

            case 'n':

				paramUsed = 1;
                nofms = 1;
                break;

            case 'p':

				paramUsed = 1;
                prng = 1;
                break;

            case 'l':

				paramUsed = 1;
                if (atoi(optarg) < 2 || atoi(optarg) > 2300) {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                    printf( "Specified keystream length is invalid. [2-2300]" );
                    return( 1 );
                }

                length = atoi(optarg);
                break;

            case 'c':

				paramUsed = 1;
                if (atoi(optarg) < 1 || atoi(optarg) > 0x1000000) {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                    printf( "Specified number of IVs is invalid. [1-16777216]" );
                    return( 1 );
                }

                count = atoi(optarg);
                break;

            case 's':

				paramUsed = 1;
                if (atoi(optarg) < 1) {
                    printf( "Specified seed is invalid. [>=1]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                seed = atoi(optarg);
                break;

            case 'e':

				paramUsed = 1;
                sscanf(optarg, "%f", &errorrate);
#if defined(__x86_64__) && defined(__CYGWIN__)
                if (errorrate < 0.0f || errorrate > (0.0f + 100)) {
#else
                if (errorrate < 0.0f || errorrate > 100.0f) {
#endif
			printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                    printf( "Specified errorrate is invalid. [0-100]" );
                    return( 1 );
                }

                break;

            case 'd':

				paramUsed = 1;
                if (sscanf(optarg, "%f", &dupe) != 1 || dupe < 0.0f || dupe >
#if defined(__x86_64__) && defined(__CYGWIN__)
			(0.0f + 100)) {
#else
			100.0f) {
#endif
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                    printf( "Specified dupe is invalid. [0-100]" );
                    return( 1 );
                }

                break;

            case 'f':

				paramUsed = 1;
                if (atoi(optarg) < 0 || atoi(optarg) > 0xFFFFFF) {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                    printf( "Specified start IV is invalid. [0-16777215]" );
                    return( 1 );
                }

				paramUsed = 1;
                startiv = atoi(optarg);
                break;

            case 'w':

				paramUsed = 1;
                filename = optarg;
                break;

            case 'b':

				paramUsed = 1;
                if ( memcmp(bssid, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: bssid already given\n");
                    break;
                }
                if(getmac(optarg, 1, bssid) != 0)
                {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                    printf("Notice: invalid bssid\n");
                    return( 1 );
                }
                break;

            case 'k' :

				paramUsed = 1;
                if( crypt != 0 )
                {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                    printf( "Encryption key already specified.\n" );
                    return( 1 );
                }

                crypt = 1;

                i = 0;
                s = optarg;

                buf[0] = s[0];
                buf[1] = s[1];
                buf[2] = '\0';

                while( sscanf( buf, "%x", &n ) == 1 )
                {
                    if( n < 0 || n > 255 )
                    {
						printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                        printf( "Invalid WEP key.\n" );
                        return( 1 );
                    }

                    K[3+i++] = n;

                    if( i >= 32 ) break;

                    s += 2;

                    if( s[0] == ':' || s[0] == '-' )
                        s++;

                    if( s[0] == '\0' || s[1] == '\0' )
                        break;

                    buf[0] = s[0];
                    buf[1] = s[1];
                }

                if( i != 5 && i != 13 && i != 29)
                {
					printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

                    printf( "Invalid WEP key length. [5,13,29]\n" );
                    return( 1 );
                }

                weplen = i;
                keylen = i+3;

                break;

			case 'h' :
            case 'H' :
            	goto usage;
            	break;


            default : goto usage;
        }
    } while ( 1 );

    if(nofms)
        maxivs -= 256*weplen;

    srand(seed);

	if (paramUsed == 0)
	{
usage:
		printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
		return( 0 );
	}

    if(count > maxivs)
    {
		printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

        printf( "Specified too many IVs (%d), but there are only %d possible.\n", count, maxivs);
        return( 1 );
    }

    if(length == 0)
        length = 16; //default 16 keystreambytes

    if(crypt < 1)
    {
		printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

        printf("You need to specify the WEP key (-k).\n");
        return( 1 );
    }

    if(filename == NULL)
    {
		printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

        printf("You need to specify the output filename (-w).\n");
        return( 1 );
    }

    size = (long long)strlen(IVS2_MAGIC) + (long long)sizeof(struct ivs2_filehdr) + (long long)count *
           (long long)sizeof(struct ivs2_pkthdr) + (long long)count * (long long)(length+4);

    printf("Creating %d IVs with %d bytes of keystream each.\n", count, length);
    printf("Estimated filesize: ");
    if(size > 1024*1024*1024)   //over 1 GB
        printf("%.2f GB\n", ((double)size/(1024.0*1024.0*1024.0)));
    else if (size > 1024*1024)  //over 1 MB
        printf("%.2f MB\n", ((double)size/(1024.0*1024.0)));
    else if (size > 1024)       //over 1 KB
        printf("%.2f KB\n", ((double)size/1024.0));
    else                        //under 1 KB
        printf("%.2f Byte\n", (double)size);

    if( ( f_ivs_out = fopen( filename, "wb+" ) ) == NULL )
    {
        perror( "fopen" );
        return( 1 );
    }

    if( fwrite( IVS2_MAGIC, 1, 4, f_ivs_out ) != (size_t) 4 )
    {
        perror( "fwrite(IVs file MAGIC) failed" );
        return( 1 );
    }

    memset(&fivs2, '\x00', sizeof(struct ivs2_filehdr));
    fivs2.version = IVS2_VERSION;

    /* write file header */
    if( fwrite( &fivs2, sizeof(struct ivs2_filehdr), 1, f_ivs_out )
        != (size_t) 1 )
    {
        perror( "fwrite(IV file header) failed" );
        return( 1 );
    }

    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
    ivs2.flags |= IVS2_BSSID;
    ivs2.len += 6;

    /* write header */
    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs_out )
        != (size_t) sizeof(struct ivs2_pkthdr) )
    {
        perror( "fwrite(IV header) failed" );
        return( 1 );
    }

    if( memcmp(NULL_MAC, bssid, 6) == 0)
    {
        memcpy(bssid, "\x01\x02\x03\x04\x05\x06", 6);
    }

    /* write BSSID */
    if( fwrite( bssid, 1, 6, f_ivs_out )
        != (size_t) 6 )
    {
        perror( "fwrite(IV bssid) failed" );
        return( 1 );
    }
    printf("Using fake BSSID %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5] );
    z=0;
    pre_n=0;
    for( n = 0; n < count; n++ )
    {
        if( (dupe==0) || (pre_n == n) || ((float)rand()/(float)RAND_MAX > (float)((float)dupe/
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 100))) )
#else
		100.0f)) )
#endif
        {
            if(prng)
            {
                iv = rand() & 0xFFFFFF;
            }
            else
            {
                iv = (z + startiv) & 0xFFFFFF;
                z++;
            }

            if(nofms)
            {
                if ((iv & 0xff00) == 0xff00) {
                    byte = (iv >> 16) & 0xff;
                    if (byte >= 3 && byte < keylen)
                    {
                        if(!prng && (iv&0xFF)==0)
                            z+=0xff;
                        n--;
                        continue;
                    }
                }
            }

            if( uniqueiv_check( uiv_root, (unsigned char*)&iv ) != 0 )
            {
                n--;
                continue;
            }

            uniqueiv_mark( uiv_root, (unsigned char*)&iv );

        }

        pre_n=n;

        K[2] = ( iv >> 16 ) & 0xFF;
        K[1] = ( iv >>  8 ) & 0xFF;
        K[0] = ( iv       ) & 0xFF;

        for( i = 0; i < 256; i++ )
            S[i] = i;

        for( i = j = 0; i < 256; i++ )
        {
            j = ( j + S[i] + K[i % keylen] ) & 0xFF;
            SWAP( S[i], S[j] );
        }

        if(errorrate > 0 && ((float)((float)rand()/(float)RAND_MAX) <= (float)(errorrate/
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 100))) )
#else
		100.0f)) )
#endif
        {
            SWAP( S[1], S[11] );
        }

        memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
        ivs2.flags = 0;
        ivs2.len = 0;

        ivs2.flags |= IVS2_XOR;
        ivs2.len += length+4;

        if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs_out )
            != (size_t) sizeof(struct ivs2_pkthdr) )
        {
            perror( "fwrite(IV header) failed" );
            return( 1 );
        }

        if( fwrite( K, 1, 3, f_ivs_out ) != (size_t) 3 )
        {
            perror( "fwrite(IV iv) failed" );
            return( 1 );
        }
        if( fwrite( &zero, 1, 1, f_ivs_out ) != (size_t) 1 )
        {
            perror( "fwrite(IV idx) failed" );
            return( 1 );
        }
        ivs2.len -= 4;

        i = j = 0;
        for( k=0; k < length; k++ )
        {
            i = (i+1) & 0xFF; j = ( j + S[i] ) & 0xFF; SWAP(S[i], S[j]);
            fprintf( f_ivs_out, "%c", S[(S[i] + S[j]) & 0xFF] );
        }
        if((n%10000) == 0)
            printf("%2.1f%%\r", ((float)n/(float)count)*
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 100));
#else
		100.0f);
#endif
        fflush(stdout);
    }

    fclose( f_ivs_out );
    printf( "Done.\n" );
    return( 0 );
}

