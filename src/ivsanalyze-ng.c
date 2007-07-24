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
"  Action options:\n"
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
    int show_ivs=0, ret=0;
    int is_ivs2=0, is_ivs=0;
//     unsigned char cur_bssid[6];
//     unsigned char packet[4096];
    unsigned char *pbyte;
    int option, option_index;
    char *filename=NULL;
    unsigned char buf[2048];

    /* check the arguments */
    static struct option long_options[] = {
        {"ivs",      1, 0, 'i'},
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

    ret = fread( buf, 1, sizeof(IVS2_MAGIC), f_in );

    if( memcmp(buf, IVS2_MAGIC, sizeof(IVS2_MAGIC)) == 0 )
    {
        is_ivs2=1;
    }

    if( memcmp(buf, IVSONLY_MAGIC, sizeof(IVSONLY_MAGIC)) == 0 )
    {
        is_ivs=1;
    }

    if( is_ivs == 0)
    {
        printf("No supported file specified\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        exit(1);
    }

    if( show_ivs == 0 )
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
            fread(buf, 1, 1, f_in);
            if(buf[0] == 0xff)
            {
                fread(buf+1, 1, 5, f_in);
            }
            else
            {
                fread(buf+1, 1, 10, f_in);
            }
        }

        //make use of it
        if(is_ivs)
        {
            pbyte=buf+1;
            if(buf[0] != 0xFF)
                pbyte += 5;

            if(show_ivs)
            {
                printf("%02X:%02X:%02X\n", pbyte[0], pbyte[1], pbyte[2]);
            }
        }
    }

    fclose( f_in );
    return( 0 );
}

