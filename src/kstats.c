/*
 *  Kstat: displays the votes of the korek attack for each keybyte
 *
 *  Copyright (C) 2006-2016 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005  Christophe Devine
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
#include <stdlib.h>
#include <stdio.h>

#include "common.h"

#define N_ATTACKS 17

enum KoreK_attacks
{
    A_u15,                      /* semi-stable  15%             */
    A_s13,                      /* stable       13%             */
    A_u13_1,                    /* unstable     13%             */
    A_u13_2,                    /* unstable ?   13%             */
    A_u13_3,                    /* unstable ?   13%             */
    A_s5_1,                     /* standard      5% (~FMS)      */
    A_s5_2,                     /* other stable  5%             */
    A_s5_3,                     /* other stable  5%             */
    A_u5_1,                     /* unstable      5% no good ?   */
    A_u5_2,                     /* unstable      5%             */
    A_u5_3,                     /* unstable      5% no good     */
    A_u5_4,                     /* unstable      5%             */
    A_s3,                       /* stable        3%             */
    A_4_s13,                    /* stable       13% on q = 4    */
    A_4_u5_1,                   /* unstable      5% on q = 4    */
    A_4_u5_2,                   /* unstable      5% on q = 4    */
    A_neg                       /* helps reject false positives */
};

int K_COEFF[N_ATTACKS] =
{
        15, 13, 12, 12, 12, 5, 5, 5, 3, 4, 3, 4, 3, 13, 4, 4, -20
};

void calc_votes( unsigned char *ivbuf, long nb_ivs,
                 unsigned char *key, int B,
                 int votes[N_ATTACKS][256] )
{
    int i, j;
    long xv;
    unsigned char R[256], jj[256];
    unsigned char S[256], Si[256];
    unsigned char K[64];

    unsigned char io1, o1, io2, o2;
    unsigned char Sq, dq, Kq, jq, q;
    unsigned char S1, S2, J2, t2;

    for( i = 0; i < 256; i++ )
        R[i] = i;

    q = 3 + B;

    memcpy( K + 3, key, B );
    memset( votes, 0, sizeof( int ) * N_ATTACKS * 256 );

    for( xv = 0; xv < nb_ivs; xv += 5 )
    {
        memcpy( K, &ivbuf[xv], 3 );
        memcpy( S,  R, 256 );
        memcpy( Si, R, 256 );

        for( i = j = 0; i < q; i++ )
        {
            jj[i] = j = ( j + S[i] + K[i & 15] ) & 0xFF;
            SWAP( S[i], S[j] );
        }

        i = q; do { i--; SWAP(Si[i],Si[jj[i]]); } while( i != 0 );

        o1 = ivbuf[xv + 3] ^ 0xAA; io1 = Si[o1]; S1 = S[1];
        o2 = ivbuf[xv + 4] ^ 0xAA; io2 = Si[o2]; S2 = S[2];
        Sq = S[q]; dq = Sq + jj[q - 1];

        if( S2 == 0 )
        {
            if( ( S1 == 2 ) && ( o1 == 2 ) )
            {
                Kq = 1 - dq; votes[A_neg][Kq]++;
                Kq = 2 - dq; votes[A_neg][Kq]++;
            }
            else if( o2 == 0 )
            {
                Kq = 2 - dq; votes[A_neg][Kq]++;
            }
        }
        else
        {
            if( ( o2 == 0 ) && ( Sq == 0 ) )
            {
                Kq = 2 - dq; votes[A_u15][Kq]++;
            }
        }

        if( ( S1 == 1 ) && ( o1 == S2 ) )
        {
            Kq = 1 - dq; votes[A_neg][Kq]++;
            Kq = 2 - dq; votes[A_neg][Kq]++;
        }

        if( ( S1 == 0 ) && ( S[0] == 1 ) && ( o1 == 1 ) )
        {
            Kq = 0 - dq; votes[A_neg][Kq]++;
            Kq = 1 - dq; votes[A_neg][Kq]++;
        }

        if( S1 == q )
        {
            if( o1 == q )
            {
                Kq = Si[0] - dq; votes[A_s13][Kq]++;
            }
            else if( ( ( 1 - q - o1 ) & 0xFF ) == 0 )
            {
                Kq = io1 - dq; votes[A_u13_1][Kq]++;
            }
            else if( io1 < q )
            {
                jq = Si[( io1 - q ) & 0xFF];

                if( jq != 1 )
                {
                    Kq = jq - dq; votes[A_u5_1][Kq]++;
                }
            }
        }

        if( ( io1 == 2 ) && ( S[q] == 1 ) )
        {
            Kq = 1 - dq; votes[A_u5_2][Kq]++;
        }

        if( S[q] == q )
        {
            if( ( S1 == 0 ) && ( o1 == q ) )
            {
                Kq = 1 - dq; votes[A_u13_2][Kq]++;
            }
            else if( ( ( ( 1 - q - S1 ) & 0xFF ) == 0 ) && ( o1 == S1 ) )
            {
                Kq = 1 - dq; votes[A_u13_3][Kq]++;
            }
            else if( ( S1 >= ( ( -q ) & 0xFF ) )
                     && ( ( ( q + S1 - io1 ) & 0xFF ) == 0 ) )
            {
                Kq = 1 - dq; votes[A_u5_3][Kq]++;
            }
        }

        if( ( S1 < q ) && ( ( ( S1 + S[S1] - q ) & 0xFF ) == 0 )  &&
            ( io1 != 1 ) && ( io1 != S[S1] ) )
        {
            Kq = io1 - dq; votes[A_s5_1][Kq]++;
        }

        if( ( S1 > q ) && ( ( ( S2 + S1 - q ) & 0xFF ) == 0 ) )
        {
            if( o2 == S1 )
            {
                jq = Si[(S1 - S2) & 0xFF];

                if( ( jq != 1 ) && ( jq != 2 ) )
                {
                    Kq = jq - dq; votes[A_s5_2][Kq]++;
                }
            }
            else if( o2 == ( ( 2 - S2 ) & 0xFF ) )
            {
                jq = io2;

                if( ( jq != 1 ) && ( jq != 2 ) )
                {
                    Kq = jq - dq; votes[A_s5_3][Kq]++;
                }
            }
        }

        if( ( S[1] != 2 ) && ( S[2] != 0 ) )
        {
            J2 = S[1] + S[2];

            if( J2 < q )
            {
                t2 = S[J2] + S[2];

                if( ( t2 == q ) && ( io2 != 1 ) && ( io2 != 2 )
                    && ( io2 != J2 ) )
                {
                    Kq = io2 - dq; votes[A_s3][Kq]++;
                }
            }
        }

        if( S1 == 2 )
        {
            if( q == 4 )
            {
                if( o2 == 0 )
                {
                    Kq = Si[0] - dq; votes[A_4_s13][Kq]++;
                }
                else
                {
                    if( ( jj[1] == 2 ) && ( io2 == 0 ) )
                    {
                        Kq = Si[254] - dq; votes[A_4_u5_1][Kq]++;
                    }
                    if( ( jj[1] == 2 ) && ( io2 == 2 ) )
                    {
                        Kq = Si[255] - dq; votes[A_4_u5_2][Kq]++;
                    }
                }
            }
            else if( ( q > 4 ) && ( ( S[4] + 2 ) == q ) &&
                     ( io2 != 1 ) && ( io2 != 4 ) )
            {
                Kq = io2 - dq; votes[A_u5_4][Kq]++;
            }
        }
    }
}

typedef struct { int idx, val; } vote;

int cmp_votes( const void *bs1, const void *bs2 )
{
    if( ((vote *) bs1)->val < ((vote *) bs2)->val )
        return(  1 );

    if( ((vote *) bs1)->val > ((vote *) bs2)->val )
        return( -1 );

    return( 0 );
}

int main( int argc, char *argv[] )
{
    FILE *f;
    long nb_ivs;
    int i, n, B, *vi;
    int votes[N_ATTACKS][256];

    unsigned char *ivbuf, *s;
    unsigned char buffer[4096];
    unsigned char wepkey[16];

    vote poll[64][256];

    if( argc != 3 )
    {
        printf( "usage: kstats <ivs file> <104-bit key>\n" );
        return( 1 );
    }

    i = 0;
    s = (unsigned char * ) argv[2];

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

        wepkey[i++] = n;

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

    if( ( ivbuf = (unsigned char *) malloc( 5 * 0xFFFFFF ) ) == NULL )
    {
        perror( "malloc" );
        return( 1 );
    }

    if( ( f = fopen( argv[1], "rb" ) ) == NULL )
    {
    	free(ivbuf);
        perror( "fopen" );
        return( 1 );
    }

    if( fread( buffer, 1, 4, f ) != 4 )
    {
    	free(ivbuf);
    	fclose(f);
        perror( "fread header" );
        return( 1 );
    }

    if( memcmp( buffer, "\xBF\xCA\x84\xD4", 4 ) != 0 )
    {
    	free(ivbuf);
    	fclose(f);
        fprintf( stderr, "Not an .IVS file\n" );
        return( 1 );
    }

    nb_ivs = 0;

    while( 1 )
    {
        if( fread( buffer, 1, 1, f ) != 1 )
            break;

        if( buffer[0] != 0xFF )
            if( fread( buffer + 1, 1, 5, f ) != 5 )
                break;

        if( fread( buffer, 1, 5, f ) != 5 )
            break;

        memcpy( ivbuf + nb_ivs * 5, buffer, 5 );

        nb_ivs++;
    }

    for( B = 0; B < 13; B++ )
    {
        for( i = 0; i < 256; i++ )
        {
            poll[B][i].idx = i;
            poll[B][i].val = 0;
        }

        calc_votes( ivbuf, nb_ivs, wepkey, B, votes );

        for( n = 0, vi = (int *) votes; n < N_ATTACKS; n++ )
            for( i = 0; i < 256; i++, vi++ )
                poll[B][i].val += *vi * K_COEFF[n];

        qsort( poll[B], 256, sizeof( vote ), cmp_votes );

        printf( "KB %02d VALID  %02X",
                B, wepkey[B] );

        for( i = 0; i < 256; i++ )
            if( poll[B][i].idx == wepkey[B] )
                printf( "(%4d) ", poll[B][i].val );

        for( i = 0; i < N_ATTACKS; i++ )
            printf( "%3d  ", votes[i][wepkey[B]] );

        printf( "\n" );

        printf( "KB %02d FIRST  %02X(%4d) ",
                B, poll[B][0].idx, poll[B][0].val );

        for( i = 0; i < N_ATTACKS; i++ )
            printf( "%3d  ", votes[i][poll[B][0].idx] );

        printf( "\n" );

        printf( "KB %02d SECOND %02X(%4d) ",
                B, poll[B][1].idx, poll[B][1].val );

        for( i = 0; i < N_ATTACKS; i++ )
            printf( "%3d  ", votes[i][poll[B][1].idx] );

        printf( "\n" );

        printf( "KB %02d THIRD  %02X(%4d) ",
                B, poll[B][2].idx, poll[B][2].val );

        for( i = 0; i < N_ATTACKS; i++ )
            printf( "%3d  ", votes[i][poll[B][2].idx] );

        printf( "\n\n" );
    }

    free(ivbuf);
    fclose(f);

    return( 0 );
}
