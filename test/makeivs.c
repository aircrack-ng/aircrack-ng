#include <stdio.h>

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

int main( int argc, char *argv[] )
{
    int i, j, n;
    FILE *f_ivs_out;
    unsigned char K[16];
    unsigned char S[256];
    unsigned char buffer[64], *s;

    if( argc != 3 )
    {
        printf( "usage: makeivs <ivs file> <104-bit key>\n" );
        return( 1 );
    }

    i = 0;
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

        if( i >= 16 ) break;

        s += 2;

        if( s[0] == ':' || s[0] == '-' )
            s++;

        if( s[0] == '\0' || s[1] == '\0' )
            break;

        buffer[0] = s[0];
        buffer[1] = s[1];
    }

    if( i != 13 )
    {
        fprintf( stderr, "Invalid wep key.\n" );
        return( 1 );
    }


    if( ( f_ivs_out = fopen( argv[1], "wb+" ) ) == NULL )
    {
        perror( "fopen" );
        return( 1 );
    }

    fprintf( f_ivs_out, "\xBF\xCA\x84\xD4\x01\x01\x01\x01\x01\x01" );

    for( n = 0x000000; n <= 0x0FFFFF; n++ )
    {
        K[2] = ( n >> 16 ) & 0xFF;
        K[1] = ( n >>  8 ) & 0xFF;
        K[0] = ( n       ) & 0xFF;

        fprintf( f_ivs_out, "%c%c%c", K[0], K[1], K[2] );

        for( i = 0; i < 256; i++ )
            S[i] = i;

        for( i = j = 0; i < 256; i++ )
        {
            j = ( j + S[i] + K[i & 15] ) & 0xFF;
            SWAP( S[i], S[j] );
        }

        i = 1; j = ( 0 + S[i] ) & 0xFF; SWAP(S[i], S[j]);
        fprintf( f_ivs_out, "%c", 0xAA ^ S[(S[i] + S[j]) & 0xFF] );

        i = 2; j = ( j + S[i] ) & 0xFF; SWAP(S[i], S[j]);
        fprintf( f_ivs_out, "%c\xFF", 0xAA ^ S[(S[i] + S[j]) & 0xFF] );
    }

    fclose( f_ivs_out );
    printf( "Done.\n" );
    return( 0 );
}

