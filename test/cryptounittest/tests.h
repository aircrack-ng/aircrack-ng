/*
 *
 * tests.h
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

int ntest=1;

void hexdump (unsigned char *buffer, int length)
 {
  int i,x;
  x=1;
  for (i=0; i<length; i++)
        {
        printf("%02x ",buffer[i]);
        if (x>15) { x=0; printf("\n"); }
        x++;
        }
  printf("\n");
 }

int test (unsigned char *computed, unsigned char *expected, int length, char* name)
{
        int z;
        int error=0;

        for (z=0; z< length; z++)
                if  ( computed[z] != expected[z] )
                        error = 1;

        if (error == 1)
                {
                printf ("[%s][Test %d] ERROR: The output don't match. I got:\n",name,ntest++);
                hexdump (computed,length);
                printf ("And i was expecting:\n");
                hexdump (expected,length);
                }
        else
                {
                printf("[%s][Test %d] OK: Output matchs :)\n",name,ntest++);
                }
        return error;
}
