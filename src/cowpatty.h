/*
 *  coWPAtty hash DB file format structures and helper functions
 *
 *  Copyright (C) 2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#ifndef _COWPATTY_H_
#define _COWPATTY_H_

#include <stdint.h>

#define MAX_PASSPHRASE_LENGTH 63

#define GENPMKMAGIC 0x43575041
struct hashdb_head {
	uint32_t magic;
	uint8_t reserved1[3];
	uint8_t ssidlen;
	uint8_t ssid[32];
};

struct hashdb_rec {
	uint8_t rec_size;
	char *word;
	uint8_t pmk[32];
} __attribute__ ((packed));

struct cowpatty_file {
	char ssid[33];
	FILE * fp;
	char error[256 - sizeof(FILE *) - 33];
};

void close_free_cowpatty_hashdb(struct cowpatty_file * cf);
struct cowpatty_file * open_cowpatty_hashdb(const char * filename, const char * mode);
struct hashdb_rec * read_next_cowpatty_record(struct cowpatty_file * cf);

#endif // _COWPATTY_H_