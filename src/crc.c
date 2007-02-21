#include "crctable.h"

/* CRC checksum calculation routine */

unsigned long calc_crc( unsigned char * buf, int len)
{
    unsigned long crc = 0xFFFFFFFF;

    for( ; len > 0; len--, buf++ )
        crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ ( crc >> 8 );

    return( ~crc );
}

/* CRC checksum verification routine */

int check_crc_buf( unsigned char *buf, int len )
{
    unsigned long crc;

    crc = calc_crc(buf, len);
    buf+=len;
    return( ( ( crc       ) & 0xFF ) == buf[0] &&
            ( ( crc >>  8 ) & 0xFF ) == buf[1] &&
            ( ( crc >> 16 ) & 0xFF ) == buf[2] &&
            ( ( crc >> 24 ) & 0xFF ) == buf[3] );
}

/* Add CRC32 */

int add_crc32(unsigned char* data, int length)
{
    unsigned long crc;

    crc = calc_crc(data, length);

    data[length]   = (crc      ) & 0xFF;
    data[length+1] = (crc >>  8) & 0xFF;
    data[length+2] = (crc >> 16) & 0xFF;
    data[length+3] = (crc >> 24) & 0xFF;

    return 0;
}

int calc_crc_buf( unsigned char *buf, int len )
{
    return (calc_crc(buf, len));
}
