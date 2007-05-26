#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }
#define IVS2_MAGIC "\xAE\x78\xD1\xFF"
#define IVS2_BSSID	0x01
#define IVS2_ESSID	0x02
#define IVS2_WPA	0x04
#define IVS2_XOR	0x08

struct ivs2_pkthdr
{
    unsigned short flags;
    unsigned short len;
};

int main( int argc, char *argv[] )
{
    int i, j, k, n, count, length, keylen, zero=0;
    FILE *f_ivs_out;
    unsigned char K[16];
    unsigned char S[256];
    unsigned char buffer[64], *s;
    struct ivs2_pkthdr ivs2;

    if( argc != 5 )
    {
        printf( "usage: %s <ivs file> <wep key> <count> <length>\n", argv[0]);
        printf( "example: %s test.ivs ABCDEF01234567890123456789 50000 16\n", argv[0] );
        return( 1 );
    }

    i = 0;
    count = atoi(argv[3]);
    length = atoi(argv[4]);

    if(count < 0 || count > 0xFFFFFF)
    {
        fprintf(stderr, "Invalid number of IVs. (%d)\n", count);
        return( 1 );
    }
    if(count == 0)
        count = 0x0FFFFF; //default 1mio ivs

    if(length < 0 || length > 0xFFFF)
    {
        fprintf(stderr, "Invalid number of keystreambytes. (%d)\n", length);
        return( 1 );
    }
    if(length == 0)
        length = 16; //default 16 keystreambytes

    s = (unsigned char *) argv[2];

    buffer[0] = s[0];
    buffer[1] = s[1];
    buffer[2] = '\0';

    while( sscanf( (char*) buffer, "%x", &n ) == 1 )
    {
        if( n < 0 || n > 255 )
        {
            fprintf( stderr, "Invalid wep key.\n" );
            return( 1 );
        }

        K[3 + i++] = n;

        if( i >= 32 ) break;

        s += 2;

        if( s[0] == ':' || s[0] == '-' )
            s++;

        if( s[0] == '\0' || s[1] == '\0' )
            break;

        buffer[0] = s[0];
        buffer[1] = s[1];
    }

    if( i != 5 && i != 13 && i != 29 )
    {
        fprintf( stderr, "Invalid wep key.\n" );
        return( 1 );
    }

    keylen = i+3;

    if( ( f_ivs_out = fopen( argv[1], "wb+" ) ) == NULL )
    {
        perror( "fopen" );
        return( 1 );
    }

    fprintf( f_ivs_out, IVS2_MAGIC );

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

    /* write BSSID */
    if( fwrite( "\x01\x02\03\x04\x05\x06", 1, 6, f_ivs_out )
        != (size_t) 6 )
    {
        perror( "fwrite(IV bssid) failed" );
        return( 1 );
    }

    for( n = 0x000000; n < count; n++ )
    {
        K[2] = ( n >> 16 ) & 0xFF;
        K[1] = ( n >>  8 ) & 0xFF;
        K[0] = ( n       ) & 0xFF;

        for( i = 0; i < 256; i++ )
            S[i] = i;

        for( i = j = 0; i < 256; i++ )
        {
            j = ( j + S[i] + K[i % keylen] ) & 0xFF;
            SWAP( S[i], S[j] );
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
    }

    fclose( f_ivs_out );
    printf( "Done.\n" );
    return( 0 );
}

