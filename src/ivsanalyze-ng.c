#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

#include "version.h"
#include "pcap.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);

char usage[] =

"\n"
"  %s - (C) 2007 Martin Beck\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  usage: ivsanalyze-ng [options]\n"
"\n"
"  Common options:\n"
"      -f <file>  : Read this file\n"
"\n"
"  Action options:\n"
"      -i         : Displays all IVs\n"
"\n"
"      --help     : Displays this usage screen\n"
"\n";

int main( int argc, char *argv[] )
{
    int f_in;

    int show_ivs=0;

    int is_ivs2=0, is_ivs=0;

    unsigned char cur_bssid[6];
    unsigned char *pbyte;
    int option, option_index;
    char *filename=NULL;
    unsigned char buf[2048];
    int action=0;

    struct ivs2_filehdr fivs2;
    struct ivs2_pkthdr  ivs2;

    /* check the arguments */
    static struct option long_options[] = {
        {"showivs",  1, 0, 'i'},
        {"file",     1, 0, 'f'},
        {"help",     0, 0, 'H'},
        {0,          0, 0,  0 }
    };

    do
    {
        option_index = 0;

        option = getopt_long( argc, argv,
                        "if:H",
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

            case 'i':

                show_ivs = 1;
                break;

            case 'f':

                filename = optarg;
                break;

            case 'H' :
usage:
                printf( usage, getVersion("ivsanalyze-ng", _MAJ, _MIN, _SUB_MIN, _REVISION)  );
                return( 1 );

            default : goto usage;
        }
    } while ( 1 );

    if(filename == NULL)
    {
        printf("You need to specify the input filename (-f).\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if( ( f_in = open( (char *) filename, O_RDONLY | O_BINARY ) ) == 0 )
    {
        perror( "open" );
        return( 1 );
    }

    if( read( f_in, buf, sizeof(IVS2_MAGIC) ) != sizeof(IVS2_MAGIC)) return 1;

    if( memcmp(buf, IVS2_MAGIC, 4) == 0 )
    {
        is_ivs2=1;
        if( read( f_in, &fivs2, sizeof(struct ivs2_filehdr)) != sizeof(struct ivs2_filehdr)) return 1;

        if(fivs2.version > IVS2_VERSION)
        {
            printf( "Error, wrong %s version: %d. Supported up to version %d.\n", IVS2_EXTENSION, fivs2.version, IVS2_VERSION );
            return 1;
        }
    }

    if( memcmp(buf, IVSONLY_MAGIC, 4) == 0 )
    {
        is_ivs=1;
    }

    if( is_ivs == 0 && is_ivs2 == 0)
    {
        printf("No supported file specified\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        exit(1);
    }

    action = show_ivs+0;

    if( action == 0 )
    {
        printf("No action specified\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        exit(1);
    }

    while(1)
    {
        //get the "packet"
        if(is_ivs)
        {
            if(read(f_in, buf, 1) != 1) break;
            if(buf[0] == 0xff)
            {
                if(read(f_in, buf+1, 5) != 5) break;
            }
            else
            {
                if(read(f_in, buf+1, 10) != 10) break;
            }
        }

        if(is_ivs2)
        {
            if(read(f_in, &ivs2, sizeof(struct ivs2_pkthdr)) != sizeof(struct ivs2_pkthdr)) break;
            if(read(f_in, buf, ivs2.len) != ivs2.len) break;
        }

        //make use of it
        if(is_ivs)
        {
            pbyte=buf+1;
            if(buf[0] != 0xFF)
                pbyte = buf+6;

            if(show_ivs)
            {
                printf("%02X:%02X:%02X\n", pbyte[0], pbyte[1], pbyte[2]);
            }
        }

        if(is_ivs2)
        {
            if(ivs2.flags & IVS2_BSSID)
            {
                memcpy(cur_bssid, buf, 6);
                ivs2.len -= 6;
                ivs2.flags &= ~IVS2_BSSID;
            }

            pbyte = buf;

            if(show_ivs)
            {
                if(ivs2.flags & IVS2_XOR)
                {
                    printf("%02X:%02X:%02X\n", pbyte[0], pbyte[1], pbyte[2]);
                }
            }
        }
    }

    printf("done.\n");
    close( f_in );
    return( 0 );
}

