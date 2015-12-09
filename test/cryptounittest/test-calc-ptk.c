/*
 *
 * test-calc-ptk.c
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
#include <strings.h>
#include <stdlib.h>
#include "crypto.h"
#include "tests.h"
#include <string.h>


int main(int argc, char **argv)
{
    if (argc < 1) return 1;

    int error=0;
    static unsigned char opmk[32] =     "\xee\x51\x88\x37\x93\xa6\xf6\x8e\x96\x15\xfe\x73\xc8\x0a\x3a\xa6"
                                        "\xf2\xdd\x0e\xa5\x37\xbc\xe6\x27\xb9\x29\x18\x3c\xc6\xe5\x79\x25";




    static unsigned char ostmac[6] =    "\x00\x13\x46\xfe\x32\x0c";
    static unsigned char obssid[6] =    "\x00\x14\x6c\x7e\x40\x80";
    static unsigned char osnonce[32] =  "\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08\x8d"
                                        "\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85\x70";
    static unsigned char oanonce[32] =  "\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0"
                                        "\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55";
    static unsigned char okeymic[20] =  "\xd5\x35\x53\x82\xb8\xa9\xb8\x06\xdc\xaf\x99\xcd\xaf\x56\x4e\xb6"
                                        "\x00\x00\x00\x00";

    static unsigned char optk[80] =    "\x0d\xde\xae\x80\x83\xf9\x2c\xa9\xaf\xdb\x25\x0d\xde\xe5\x25\x1b"
                                        "\xc0\xee\xb4\x7e\xf2\x2a\xf7\x9e\x25\x34\x6e\x8b\x73\xe2\xca\x7d"
                                        "\x94\xb0\x60\x5f\x2e\xed\x66\xd8\x60\x76\xb3\x38\xa6\x65\xfe\xe3"
                                        "\x9f\xde\x22\x1e\xb1\x38\x6b\x3d\xa7\xac\x6a\xbe\x7e\xe0\x00\x1f"
                                        "\xbd\x92\xab\xec\xc8\xba\x49\xf0\x5d\xff\x8f\x50\x1e\xfa\xaa\xcc";

    static unsigned char eptk[80] =     "\xea\x0e\x40\x46\x33\xc8\x02\x45\x03\x02\x86\x8c\xca\xa7\x49\xde"
                                        "\x5c\xba\x5a\xbc\xb2\x67\xe2\xde\x1d\x5e\x21\xe5\x7a\xcc\xd5\x07"
                                        "\x9b\x31\xe9\xff\x22\x0e\x13\x2a\xe4\xf6\xed\x9e\xf1\xac\xc8\x85"
                                        "\x45\x82\x5f\xc3\x2e\xe5\x59\x61\x39\x5a\xe4\x37\x34\xd6\xc1\x07"
                                        "\x98\xef\x5a\xfe\x42\xc0\x74\x26\x47\x18\x68\xa5\x77\xd4\xd1\x7e";

    static unsigned char oeapol[256]=   "\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00"
                                        "\x01\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08"
                                        "\x8d\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85"
                                        "\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac"
                                        "\x04\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";



    unsigned char pmk[32]; memcpy(&pmk, &opmk, 32);

    struct WPA_ST_info *wpa;
    wpa=(struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info));
    // default to zero
    bzero(wpa,sizeof(struct WPA_ST_info));

    memcpy(wpa->stmac,&ostmac,6);
    memcpy(wpa->bssid,&obssid,6);
    memcpy(wpa->ptk,&optk,80);
    memcpy(wpa->anonce,&oanonce,32);




    // not valid_ptk
    if ((1==1) == (calc_ptk (wpa, pmk))) error++;
    error += test(pmk,opmk,32, argv[0]);
    error += test(wpa->ptk,optk,80, argv[0]);


    // calc another one
    wpa->eapol_size=121;
    memcpy(wpa->eapol,&oeapol,256);
    memcpy(wpa->keymic,&okeymic,20);
    memcpy(wpa->snonce,&osnonce,32);

    // valid ptk
    if ((1==1) != (calc_ptk (wpa, pmk))) error++;
    error += test(pmk,opmk,32, argv[0]);
    error += test(wpa->ptk,eptk,80, argv[0]);

    free(wpa);

    return error;
}

