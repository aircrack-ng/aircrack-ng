#ifndef _UNIQUEIV_H
#define _UNIQUEIV_H

#define IV_NOTHERE  0
#define IV_PRESENT  1

/* select byte within which desired bit is located */

#define BITWISE_OFFT(x)         (x >> 3)

/* mask to extract desired bit */

#define BITWISE_MASK(x)         (1 << (x & 7))

unsigned char **uniqueiv_init( void );
int uniqueiv_mark( unsigned char **uiv_root, unsigned char IV[3] );
int uniqueiv_check( unsigned char **uiv_root, unsigned char IV[3] );
void uniqueiv_wipe( unsigned char **uiv_root );

#define NO_CLOAKING 0
#define CLOAKING    1

unsigned char *data_init( void );
int data_check(unsigned char *data_root, unsigned char IV[3], unsigned char data[2]);
void data_wipe(unsigned char * data);

#endif
