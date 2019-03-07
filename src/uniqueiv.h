/*
 *  802.11 WEP / WPA-PSK Key Cracker
 *
 *  Copyright (C) 2007-2012 Martin Beck <martin.beck2@gmx.de>
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _UNIQUEIV_H
#define _UNIQUEIV_H

#define IV_NOTHERE 0
#define IV_PRESENT 1

/* select byte within which desired bit is located */

#define BITWISE_OFFT(x) ((x) >> 3)

/* mask to extract desired bit */

#define BITWISE_MASK(x) (1 << ((x) &7))

unsigned char ** uniqueiv_init(void);
int uniqueiv_mark(unsigned char ** uiv_root, unsigned char IV[3]);
int uniqueiv_check(unsigned char ** uiv_root, unsigned char IV[3]);
void uniqueiv_wipe(unsigned char ** uiv_root);

#define NO_CLOAKING 0
#define CLOAKING 1

unsigned char * data_init(void);
int data_check(unsigned char * data_root,
			   unsigned char IV[3],
			   unsigned char data[2]);
void data_wipe(unsigned char * data);

#endif
