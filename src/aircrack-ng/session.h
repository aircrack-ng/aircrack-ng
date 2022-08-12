/*
 *  Aircrack-ng session (load/restore).
 *
 *  Copyright (C) 2018-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#ifndef _AIRCRACK_NG_SESSION_H
#define _AIRCRACK_NG_SESSION_H

#include <inttypes.h>
#include <pthread.h>

struct session
{
	char * filename; // Session filename

	// Session file content
	char * working_dir; // Line 1: Current working directory
	unsigned char bssid[6]; // Line 2: BSSID
	unsigned char wordlist_id; // Line 3: Wordlist # (there can be multiple
	// wordlist loaded using -w
	int64_t pos; // Line 3: Position in the wordlist ID.
	long long int
		nb_keys_tried; // Line 3: Amount of keys already tried, purely for stats
	int argc; // Line 4: amount of arguments
	char ** argv; // Line 5 and further: Arguments (1 per line)
	pthread_mutex_t
		mutex; // Locking for when updating wordlist settings and saving file
	unsigned char is_loaded;
	// Set to 1 when session is loaded
};

struct session * ac_session_new(void);
int ac_session_destroy(struct session * s);
void ac_session_free(struct session ** s);
int ac_session_init(struct session * s);

// Validate and set the different values in the session structure
int ac_session_set_working_directory(struct session * session,
									 const char * str);
int ac_session_set_bssid(struct session * session, const char * str);
int ac_session_set_wordlist_settings(struct session * session,
									 const char * str);
int ac_session_set_amount_arguments(struct session * session, const char * str);

// Load from file
struct session * ac_session_load(const char * filename);

// Save to file
int ac_session_save(struct session * s,
					uint64_t pos,
					long long int nb_keys_tried);

struct session *
ac_session_from_argv(const int argc, char ** argv, const char * filename);

#endif // _AIRCRACK_NG_SESSION_H
