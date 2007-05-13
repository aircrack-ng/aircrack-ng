/*
 *  IV uniqueness detection method, as designed by Stanislaw Pusep:
 *
 *  Each IV byte is stored in corresponding "level". We have 3 levels with
 *  IV[2] as root index (level 0), IV[1] and IV[2] as level 2 and level 1
 *  indices respectively. Space required to allocate all data is at maximum
 *  2^24/8 (2 MB) and space required by filled index structures is 257 KB.
 */

#include <stdlib.h>

#define IV_NOTHERE  0
#define IV_PRESENT  1

/* select byte within which desired bit is located */

#define BITWISE_OFFT(x)         (x >> 3)

/* mask to extract desired bit */

#define BITWISE_MASK(x)         (1 << (x & 7))

/* allocate root structure */

unsigned char **uniqueiv_init( void )
{
    int i;

    /* allocate root bucket (level 0) as vector of pointers */
    
    unsigned char **uiv_root = (unsigned char **)
        malloc( 256 * sizeof( unsigned char * ) );
    
    if( uiv_root == NULL )
        return( NULL );

    /* setup initial state as empty */

    for( i = 0; i < 256; ++i )
        uiv_root[i] = NULL;

    return( uiv_root );
}

/* update records with new IV */

int uniqueiv_mark( unsigned char **uiv_root, unsigned char IV[3] )
{
    unsigned char **uiv_lvl1;
    unsigned char  *uiv_lvl2;
    short i;

    if( uiv_root == NULL )
        return( 0 );

    /* select bucket from level 1 */

    uiv_lvl1 = (unsigned char **) uiv_root[IV[2]];

    /* create if it doesn't exists */

    if( uiv_lvl1 == NULL )
    {
        /* allocate level 2 bucket being a vector of bits */

        uiv_lvl1 = (unsigned char **) malloc( 256 * sizeof( unsigned char * ) );

        if( uiv_lvl1 == NULL )
            return( 1 );

        /* setup initial state as empty */

        for( i = 0; i < 256; i++ )
            uiv_lvl1[i] = NULL;

        /* link to parent bucket */

        uiv_root[IV[2]] = (unsigned char *) uiv_lvl1;
    }

    /* select bucket from level 2 */

    uiv_lvl2 = (unsigned char *) uiv_lvl1[IV[1]];

    /* create if it doesn't exists */

    if( uiv_lvl2 == NULL )
    {
        /* allocate level 2 bucket as a vector of pointers */

        uiv_lvl2 = (unsigned char *) malloc( 32 * sizeof( unsigned char ) );

        if( uiv_lvl1 == NULL )
            return( 1 );

        /* setup initial state as empty */

        for( i = 0; i < 32; i++ )
            uiv_lvl2[i] = 0;

        /* link to parent bucket */

        uiv_lvl1[IV[1]] = uiv_lvl2;
    }

    /* place single bit into level 2 bucket */

    uiv_lvl2[BITWISE_OFFT( IV[0] )] |= BITWISE_MASK( IV[0] );
        
    return( 0 );
}

/* check if already seen IV */

int uniqueiv_check( unsigned char **uiv_root, unsigned char IV[3] )
{
    unsigned char **uiv_lvl1;
    unsigned char  *uiv_lvl2;
        
    if( uiv_root == NULL )
        return( IV_NOTHERE );

    /* select bucket from level 1 */

    uiv_lvl1 = (unsigned char **) uiv_root[IV[2]];

    /* stop here if not even allocated */

    if( uiv_lvl1 == NULL )
        return( IV_NOTHERE );

    /* select bucket from level 2 */

    uiv_lvl2 = (unsigned char *) uiv_lvl1[IV[1]];

    /* stop here if not even allocated */

    if( uiv_lvl2 == NULL )
        return( IV_NOTHERE );

    /* check single bit from level 2 bucket */

    if( ( uiv_lvl2[ BITWISE_OFFT( IV[0] ) ]
                  & BITWISE_MASK( IV[0] ) ) == 0 )
        return( IV_NOTHERE );
    else
        return( IV_PRESENT );
}

/* unallocate everything */

void uniqueiv_wipe( unsigned char **uiv_root )
{
    int i, j;
    unsigned char **uiv_lvl1;
    unsigned char  *uiv_lvl2;
        
    if( uiv_root == NULL )
        return;

    /* recursively wipe out allocated buckets */

    for( i = 0; i < 256; ++i )
    {
        uiv_lvl1 = (unsigned char **) uiv_root[i];

        if( uiv_lvl1 != NULL )
        {
            for( j = 0; j < 256; ++j )
            {
                uiv_lvl2 = (unsigned char *) uiv_lvl1[j];

                if( uiv_lvl2 != NULL )
                    free( uiv_lvl2 );
            }

            free( uiv_lvl1 );
        }
    }

    free( uiv_root );

    return;
}
