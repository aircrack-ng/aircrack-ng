/*
 *
 * test-encrypt-ccmp.c
 *
 * Copyright (C) 2015 Jorn van Engelen <spamme@quzart.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"
#include "tests.h"

#define BUFFER_SIZE 65536

int main(int argc, char **argv)
{
    int error = 0;
    int caplen = 44;

    // CCMP test vector as described in IEEE 802.11(TM)-2012, Section M.6.4.

    unsigned char tk1[16] =
    "\xc9\x7c\x1f\x67\xce\x37\x11\x85\x51\x4a\x8a\x19\xf2\xbd\xd5\x2f";

    unsigned char pn[6] =
    "\xb5\x03\x97\x76\xe7\x0c";

    unsigned char h80211[44] =
    "\x08\x48\xc3\x2c\x0f\xd2\xe1\x28\xa5\x7c\x50\x30\xf1\x84\x44\x08"
    "\xab\xae\xa5\xb8\xfc\xba\x80\x33\xf8\xba\x1a\x55\xd0\x2f\x85\xae"
    "\x96\x7b\xb6\x2f\xb6\xcd\xa8\xeb\x7e\x78\xa0\x50";

    unsigned char expected[60] =
    "\x08\x48\xc3\x2c\x0f\xd2\xe1\x28\xa5\x7c\x50\x30\xf1\x84\x44\x08"
    "\xab\xae\xa5\xb8\xfc\xba\x80\x33\x0c\xe7\x00\x20\x76\x97\x03\xb5"
    "\xf3\xd0\xa2\xfe\x9a\x3d\xbf\x23\x42\xa6\x43\xe4\x32\x46\xe8\x0c"
    "\x3c\x04\xd0\x19\x78\x45\xce\x0b\x16\xf9\x76\x23";

    unsigned char expected_output[BUFFER_SIZE];
    unsigned char input[BUFFER_SIZE];

    if (argc < 1)
	return 1;

    bzero( expected_output, BUFFER_SIZE );
    bzero( input, BUFFER_SIZE );
    memcpy( expected_output, expected, sizeof(expected) );
    memcpy( input, h80211, sizeof(h80211) );

    caplen = encrypt_ccmp( input, caplen, tk1, pn );
    if ( caplen != sizeof(expected) )
        error++;
    error += test( input, expected_output, sizeof(expected), argv[0] );

    return error;
}

