#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "version.h"
#include "pcap.h"

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
    FILE *f_in;

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

    if( ( f_in = fopen( filename, "r" ) ) == NULL )
    {
        perror( "fopen" );
        return( 1 );
    }

    if( fread( buf, sizeof(IVS2_MAGIC), 1, f_in ) != 1) return 1;

    if( memcmp(buf, IVS2_MAGIC, 4) == 0 )
    {
        is_ivs2=1;
        if( fread(&fivs2, sizeof(struct ivs2_filehdr), 1, f_in) != 1) return 1;

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
            if(fread(buf, 1, 1, f_in) != 1) break;
            if(buf[0] == 0xff)
            {
                if(fread(buf+1, 5, 1, f_in) != 1) break;
            }
            else
            {
                if(fread(buf+1, 10, 1, f_in) != 1) break;
            }
        }

        if(is_ivs2)
        {
            if(fread(&ivs2, sizeof(struct ivs2_pkthdr), 1, f_in) != 1) break;
            if(fread(buf, 1, ivs2.len, f_in) != 1) break;
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
    fclose( f_in );
    return( 0 );
}

