#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "version.h"
#include "pcap.h"
#include "uniqueiv.h"

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

#define NULL_MAC "\x00\x00\x00\x00\x00\x00"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);

char usage[] =

"\n"
"  %s - (C) 2006,2007 Thomas d\'Otreppe\n"
"  Original work: Christophe Devine\n"
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
"      -p         : Uses prng algorith to generate IVs\n"
"\n"
"      --help     : Displays this usage screen\n"
"\n";

int main( int argc, char *argv[] )
{
    int i, j, k, pre_n, n, count=100000, length=16, keylen=0, zero=0, startiv=0, iv=0;
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
    int maxivs=0xFFFFFF;
    unsigned char byte;
    unsigned char **uiv_root;

    i = 0;
    memset(K, 0, 32);
    memset(bssid, 0, 6);
    uiv_root = uniqueiv_init();

    /* check the arguments */
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

    do
    {
        option_index = 0;

        option = getopt_long( argc, argv,
                        "k:w:c:s:l:f:b:d:e:npH",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':':

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?':

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'n':

                nofms = 1;
                break;

            case 'p':

                prng = 1;
                break;

            case 'l':

                if (atoi(optarg) < 2 || atoi(optarg) > 2300) {
                    printf( "Specified keystream length is invalid. [2-2300]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                length = atoi(optarg);
                break;

            case 'c':

                if (atoi(optarg) < 1 || atoi(optarg) > 0xFFFFFF) {
                    printf( "Specified number of IVs is invalid. [1-65535]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                count = atoi(optarg);
                break;

            case 's':

                if (atoi(optarg) < 1) {
                    printf( "Specified seed is invalid. [>=1]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                seed = atoi(optarg);
                break;

            case 'e':

                sscanf(optarg, "%f", &errorrate);
                if (errorrate < 0.0f || errorrate > 100.0f) {
                    printf( "Specified errorrate is invalid. [0-100]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'd':

                sscanf(optarg, "%f", &dupe);
                if (dupe < 0.0f || dupe > 100.0f) {
                    printf( "Specified dupe is invalid. [0-100]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                break;

            case 'f':

                if (atoi(optarg) < 0 || atoi(optarg) > 0xFFFFFF) {
                    printf( "Specified startiv is invalid. [0-16777215]" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                startiv = atoi(optarg);
                break;

            case 'w':

                filename = optarg;
                break;

            case 'b':

                if ( memcmp(bssid, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: bssid already given\n");
                    break;
                }
                if(getmac(optarg, 1, bssid) != 0)
                {
                    printf("Notice: invalid bssid\n");
                    printf("\"%s --help\" for help.\n", argv[0]);

                    return( 1 );
                }
                break;

            case 'k' :

                if( crypt != 0 )
                {
                    printf( "Encryption key already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
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
                        printf( "Invalid WEP key.\n" );
                        printf("\"%s --help\" for help.\n", argv[0]);
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
                    printf( "Invalid WEP key length. [5,13,29]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }

                weplen = i;
                keylen = i+3;

                break;

            case 'H' :
usage:
                printf( usage, getVersion("makeivs-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
                return( 1 );

            default : goto usage;
        }
    } while ( 1 );

    if(nofms)
        maxivs -= 256*weplen;

    srand(seed);

    if(count > maxivs)
    {
        printf( "Specified too many IVs (%d), but there are only %d possible.\n", count, maxivs);
        return( 1 );
    }

    if(length == 0)
        length = 16; //default 16 keystreambytes

    if(crypt < 1)
    {
        printf("You need to specify the WEP key (-k).\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if(filename == NULL)
    {
        printf("You need to specify the output filename (-w).\n");
        printf("\"%s --help\" for help.\n", argv[0]);
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

    fprintf( f_ivs_out, IVS2_MAGIC );

    memset(&fivs2, '\x00', sizeof(struct ivs2_filehdr));
    fivs2.version = IVS2_VERSION;

    /* write file header */
    if( fwrite( &fivs2, 1, sizeof(struct ivs2_filehdr), f_ivs_out )
        != (size_t) sizeof(struct ivs2_filehdr) )
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
        if( (dupe==0) || (pre_n == n) || ((float)rand()/(float)RAND_MAX > (float)((float)dupe/100.0f)) )
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

        if(errorrate > 0 && ((float)((float)rand()/(float)RAND_MAX) <= (float)(errorrate/100.0f)) )
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
            printf("%2.1f%%\r", ((float)n/(float)count)*100.0f);
        fflush(stdout);
    }

    fclose( f_ivs_out );
    printf( "Done.\n" );
    return( 0 );
}

