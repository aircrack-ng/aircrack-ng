/*
 *
 * test-calc-pmk.c
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
#include "tests.h"

#define PLEN 40
#define KLEN 14


int main(int argc, char **argv)
{
    if (argc < 1) return 1;

    int error=0;

    static unsigned char input[PLEN] =
             "\x72\xea\x7c\xf3\x62\xd0\x63\xb6\xf6\x3b\xd6\xfc\x1c\x6c\xc0\x18"
             "\xd0\x10\x23\xd6\x86\x4e\x04\xf0\x0e\xc7\x34\xca\x66\x34\x01\xac"
             "\x46\xd4\x7d\x15\x24\xa7\xaa\xb0";
    static unsigned char expected[PLEN] =
             "\x1d\x4d\xf5\x5d\xd8\xd9\x13\xf5\x54\x0d\x05\x3c\xdb\x57\x83\x53"
             "\xd0\x6c\x0f\xb3\x50\x71\x10\xee\x48\xda\xce\x2b\x60\xf6\xd0\xd4"
             "\xc2\x24\x39\x9f\xe8\x1d\x1e\x80";
    static char key[KLEN] =
             "\x6E\x9C\x7A\x91\x9F\xB8\xAE\x93\xC1\xAB\x80\x3C\x09\x00";
    static char essid[8] = "T3st1ng";


    unsigned char pmk[PLEN]; memcpy(&pmk, &input, PLEN);



    calc_pmk( key, essid, pmk );
    error += test(pmk,expected,PLEN, argv[0]);

    calc_pmk( key, essid, pmk );
    error += test(pmk,expected,PLEN, argv[0]);

    return error;
}

