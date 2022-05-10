/*
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2006-2009 Martin Beck <martin.beck2@gmx.de>
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

#ifndef AIRCRACK_NG_FRAGMENTS_H
#define AIRCRACK_NG_FRAGMENTS_H

#include <aircrack-ng/crypto/crypto.h>

// if not all fragments are available 60 seconds after the last fragment was
// received, they will be removed
#define FRAG_TIMEOUT (1000000 * 60)

typedef struct Fragment_list * pFrag_t;
struct Fragment_list
{
	unsigned char source[6];
	unsigned short sequence;
	unsigned char * fragment[16];
	short fragmentlen[16];
	char fragnum;
	unsigned char * header;
	short headerlen;
	struct timeval access;
	char wep;
	pFrag_t next;
};

int addFrag(unsigned char * packet,
			unsigned char * smac,
			int len,
			int crypt,
			unsigned char * wepkey,
			int weplen);

int timeoutFrag(void);

int delFrag(unsigned char * smac, int sequence);

unsigned char * getCompleteFrag(unsigned char * smac,
								int sequence,
								size_t * packetlen,
								int crypt,
								unsigned char * wepkey,
								int weplen);

#endif //AIRCRACK_NG_FRAGMENTS_H
