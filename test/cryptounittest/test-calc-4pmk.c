/*
 *
 * test-calc-4pmk.c
 *
 * Copyright (C) 2012 Carlos Alberto Lopez Perez <clopez@igalia.com>
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
#include "sha1-sse2.h"
#include "tests.h"

#define KLEN 32

int main(int argc, char **argv)
{
    argc = argc; // remove warning not-used argc

    int error=0, j;
    char  key[4][128];
    unsigned char pmk[4][128];
    unsigned char epmk[4][128];
    bzero(&pmk,sizeof(pmk));
    bzero(&epmk,sizeof(epmk));
    bzero(&key,sizeof(key));
    strcpy(key[0],"biscotte");
    strcpy(key[1],"password");
    strcpy(key[2],"aircrack");
    strcpy(key[3],"keyboard");
    memcpy(epmk[0],
    "\xcd\xd7\x9a\x5a\xcf\xb0\x70\xc7\xe9\xd1\x02\x3b\x87\x02\x85\xd6"
    "\x39\xe4\x30\xb3\x2f\x31\xaa\x37\xac\x82\x5a\x55\xb5\x55\x24\xee", KLEN);
    memcpy(epmk[1],
    "\x9a\x15\xed\x29\xa9\xb8\x0e\x5d\x52\x32\xa0\x64\x4c\xfd\x40\x4b"
    "\x83\x97\x9b\x57\xaf\x83\x05\x80\x6d\xd4\xd4\x86\x50\x06\xed\x7d", KLEN);
    memcpy(epmk[2],
    "\x12\x8c\x41\xed\xf5\x32\x1c\x51\x1f\xd6\xaf\x07\x96\x95\xdf\x71"
    "\x5c\xb1\xb7\x68\x6f\x1a\xed\xe9\x70\x1e\x87\x07\xb8\xc9\xb4\x3b", KLEN);
    memcpy(epmk[3],
    "\xbb\x84\x66\x33\xef\x41\x5a\xb6\xcd\x83\x93\xc6\x00\x18\x26\x42"
    "\x76\x62\x7c\x4e\xbc\x6b\x8f\x20\x9b\xbe\x59\xb4\x86\x71\x69\xdd", KLEN);

    static char essid[] = "test";


#if defined(__i386__) || defined(__x86_64__)
    // Check for SSE2, with SSE2 the algorithm works with 4 keys
    if (shasse2_cpuid()>=2) {
        calc_4pmk( key[0], key[1], key[2], key[3], essid, pmk[0], pmk[1], pmk[2], pmk[3] );
        for (j=0;j<4;j++)
            error += test(pmk[j],epmk[j],32, argv[0]);
    }
#endif
    // do non-sse calc_pmk
    for(j=0; j<4; ++j)
        calc_pmk( key[j], essid, pmk[j] );
    for (j=0;j<4;j++)
        error += test(pmk[j],epmk[j],32, argv[0]);

    return error;
}

