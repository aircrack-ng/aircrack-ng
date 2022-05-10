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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include "session.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/support/common.h"

int ac_session_destroy(struct session * s)
{
	if (s == NULL || s->filename == NULL)
	{
		return (0);
	}

	ALLEGE(pthread_mutex_lock(&(s->mutex)) == 0);
	FILE * f = fopen(s->filename, "r");
	if (!f)
	{
		ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
		return (0);
	}

	fclose(f);
	int ret = remove(s->filename);
	ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);

	return (ret == 0);
}

void ac_session_free(struct session ** s)
{
	if (s == NULL || *s == NULL)
	{
		return;
	}

	if ((*s)->filename)
	{
		// Delete 0 byte file
		struct stat scs;
		memset(&scs, 0, sizeof(struct stat));
		ALLEGE(pthread_mutex_lock(&((*s)->mutex)) == 0);
		if (stat((*s)->filename, &scs) == 0 && scs.st_size == 0)
		{
			ALLEGE(pthread_mutex_unlock(&((*s)->mutex)) == 0);
			ac_session_destroy(*s);
		}

		free((*s)->filename);
	}
	if ((*s)->argv)
	{
		for (int i = 0; i < (*s)->argc; ++i)
		{
			free((*s)->argv[i]);
		}
		free((*s)->argv);
	}
	if ((*s)->working_dir) free((*s)->working_dir);

	free(*s);
	*s = NULL;
}

struct session * ac_session_new(void)
{
	return (struct session *) calloc(1, sizeof(struct session));
}

int ac_session_init(struct session * s)
{
	if (s == NULL)
	{
		return (EXIT_FAILURE);
	}

	memset(s, 0, sizeof(struct session));
	ALLEGE(pthread_mutex_init(&(s->mutex), NULL) == 0);

	return (EXIT_SUCCESS);
}

int ac_session_set_working_directory(struct session * session, const char * str)
{
	if (session == NULL || str == NULL || str[0] == 0 || chdir(str) == -1)
	{
		return (EXIT_FAILURE);
	}

	session->working_dir = strdup(str);

	return ((session->working_dir) ? EXIT_SUCCESS : EXIT_FAILURE);
}

int ac_session_set_bssid(struct session * session, const char * str)
{
	if (session == NULL || str == NULL || strlen(str) != 17)
	{
		return (EXIT_FAILURE);
	}

	// Parse BSSID
	unsigned int bssid[6] = {0};
	int count = sscanf(str,
					   "%02X:%02X:%02X:%02X:%02X:%02X",
					   &bssid[0],
					   &bssid[1],
					   &bssid[2],
					   &bssid[3],
					   &bssid[4],
					   &bssid[5]);

	// Verify all parsed correctly
	if (count < 6)
	{
		return (EXIT_FAILURE);
	}

	// Copy it back to the structure
	for (int i = 0; i < 6; ++i)
	{
		session->bssid[i] = (uint8_t) bssid[i];
	}

	return (EXIT_SUCCESS);
}

int ac_session_set_wordlist_settings(struct session * session, const char * str)
{
	if (session == NULL || str == NULL)
	{
		return (EXIT_FAILURE);
	}

	int nb_input_scanned = sscanf(str,
								  "%hhu %" PRId64 " %lld",
								  &(session->wordlist_id),
								  &(session->pos),
								  &(session->nb_keys_tried));

	if (nb_input_scanned != 3 || session->pos < 0 || session->nb_keys_tried < 0)
	{
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

#define SESSION_MIN_NBARG 4
int ac_session_set_amount_arguments(struct session * session, const char * str)
{
	if (session == NULL || str == NULL)
	{
		return (EXIT_FAILURE);
	}

	// Parse amount of arguments
	int nb_input_scanned = sscanf(str, "%d", &(session->argc));
	if (nb_input_scanned != 1 || session->argc < SESSION_MIN_NBARG)
	{
		// There should be at least 4 arguments:
		// - Executable path (argv[0])
		// - -w
		// - Wordlist
		// - capture file
		return (EXIT_FAILURE);
	}

	// Allocate memory for all the arguments
	session->argv = (char **) calloc(session->argc, sizeof(char *));
	ALLEGE(session->argv != NULL);

	return (EXIT_SUCCESS);
}

static char * ac_session_getline(FILE * f)
{
	if (f == NULL)
	{
		return (NULL);
	}

	char * ret = NULL;
	size_t n = 0;
	ssize_t line_len = getline(&ret, &n, f);

	if (line_len == -1)
	{
		return (NULL);
	}

	return (ret);
}

/*
 * MT-Unsafe: Caller must not permit multiple threads to call
 * the function with the same filename.
 *
 * File format:
 * Line 1: Working directory
 * Line 2: BSSID
 * Line 3: Wordlist ID followed by a space then
 *          position in file followed by a space then
 *          amount of keys tried
 * Line 4: Amount of arguments (indicates how many lines will follow this one)
 *
 * Notes:
 * - Any line starting with # is ignored
 * - First 4 lines CANNOT be empty
 * - Lines are trimmed of any possible \r and \n at the end
 */

#define SESSION_ARGUMENTS_LINE 4
#define AC_SESSION_CWD_LINE 0
#define AC_SESSION_BSSID_LINE 1
#define AC_SESSION_WL_SETTINGS_LINE 2
#define AC_SESSION_ARGC_LINE 3
struct session * ac_session_load(const char * filename)
{
	int temp;

	// Check if file exists
	if (filename == NULL || filename[0] == 0)
	{
		return (NULL);
	}
	FILE * f = fopen(filename, "r");
	if (f == NULL)
	{
		return (NULL);
	}

	// Check size isn't 0
	if (fseeko(f, 0, SEEK_END))
	{
		fclose(f);
		return (NULL);
	}
	uint64_t fsize = ftello(f);
	if (fsize == 0)
	{
		fclose(f);
		return (NULL);
	}
	rewind(f);

	// Prepare structure
	struct session * ret = ac_session_new();
	if (ret == NULL)
	{
		fclose(f);
		return (NULL);
	}

	// Initialize
	ac_session_init(ret);
	ret->is_loaded = 1;
	ret->filename = strdup(filename);
	ALLEGE(ret->filename != NULL);

	char * line;
	int line_nr = 0;
	while (1)
	{
		line = ac_session_getline(f);

		// Basic checks and trimming
		if (line == NULL) break;
		if (line[0] == '#') continue;
		rtrim(line);

		// Check the parameters
		switch (line_nr)
		{
			case AC_SESSION_CWD_LINE: // Working directory
			{
				temp = ac_session_set_working_directory(ret, line);
				break;
			}
			case AC_SESSION_BSSID_LINE: // BSSID
			{
				temp = ac_session_set_bssid(ret, line);
				break;
			}
			case AC_SESSION_WL_SETTINGS_LINE: // Wordlist ID, position in
				// wordlist and amount of keys
				// tried
				{
					temp = ac_session_set_wordlist_settings(ret, line);
					break;
				}
			case AC_SESSION_ARGC_LINE: // Number of arguments
			{
				temp = ac_session_set_amount_arguments(ret, line);
				break;
			}
			default: // All the arguments
			{
				ret->argv[line_nr - SESSION_ARGUMENTS_LINE] = line;
				temp = EXIT_SUCCESS;
				break;
			}
		}

		// Cleanup
		if (line_nr < SESSION_ARGUMENTS_LINE)
		{
			free(line);
		}

		// Check for success/failure
		if (temp == EXIT_FAILURE)
		{
			fclose(f);
			ac_session_free(&ret);
			return (NULL);
		}

		++line_nr;
	}

	fclose(f);
	if (line_nr < SESSION_ARGUMENTS_LINE + 1)
	{
		ac_session_free(&ret);
		return (NULL);
	}

	return (ret);
}

// Two arguments will be ignored: Session creation parameter and its argument
#define AMOUNT_ARGUMENTS_IGNORE 2
struct session *
ac_session_from_argv(const int argc, char ** argv, const char * filename)
{
	if (filename == NULL || filename[0] == 0 || argc <= 3 || argv == NULL)
	{
		// If it only has this parameter, then there is something wrong
		return (NULL);
	}

	// Check if the file exists and create it if it doesn't
	int fd = -1;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666)) >= 0)
	{
		// Just create an empty file for now
		close(fd);
	}
	else
	{
		// Not overwriting
		fprintf(stderr, "Session file already exists: %s\n", filename);
		return (NULL);
	}

	// Initialize structure
	struct session * ret = ac_session_new();
	if (ret == NULL)
	{
		return (NULL);
	}
	ac_session_init(ret);

	// Get working directory and copy filename
	ret->working_dir = get_current_working_directory();

	// Copy filename
	ret->filename = strdup(filename);
	ALLEGE(ret->filename != NULL);

	// Copy argc and argv, except the 2 specifying session filename location
	ret->argv
		= (char **) calloc(argc - AMOUNT_ARGUMENTS_IGNORE, sizeof(char *));
	ALLEGE(ret->argv != NULL);

	// Check values are properly set
	if (ret->working_dir == NULL)
	{
		ac_session_free(&ret);
		return (NULL);
	}

	// Copy all the arguments
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], filename) == 0)
		{
			// Found the session filename, now remove the previously copied
			// argument
			ret->argc--;
			free(ret->argv[ret->argc]);
			ret->argv[ret->argc] = NULL;
			continue;
		}

		// Copy argument
		ret->argv[ret->argc] = strdup(argv[i]);
		if (ret->argv[ret->argc] == NULL)
		{
			ac_session_free(&ret);
			return (NULL);
		}

		// Increment count
		ret->argc++;
	}

	return (ret);
}

int ac_session_save(struct session * s,
					uint64_t pos,
					long long int nb_keys_tried)
{
	if (s == NULL || s->filename == NULL || s->working_dir == NULL
		|| s->argc == 0
		|| s->argv == NULL)
	{
		return (-1);
	}

	// Update amount of keys tried in structure
	s->nb_keys_tried = nb_keys_tried;

	// Open file for writing
	ALLEGE(pthread_mutex_lock(&(s->mutex)) == 0);
	FILE * f = fopen(s->filename, "w");
	if (f == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);
		return (-1);
	}

	// Update position in wordlist
	s->pos = pos;

	// Write it
	fprintf(f, "%s\n", s->working_dir);
	fprintf(f,
			"%02X:%02X:%02X:%02X:%02X:%02X\n",
			s->bssid[0],
			s->bssid[1],
			s->bssid[2],
			s->bssid[3],
			s->bssid[4],
			s->bssid[5]);
	fprintf(
		f, "%d %" PRId64 " %lld\n", s->wordlist_id, s->pos, s->nb_keys_tried);
	fprintf(f, "%d\n", s->argc);
	for (int i = 0; i < s->argc; ++i)
	{
		fprintf(f, "%s\n", s->argv[i]);
	}
	fclose(f);
	ALLEGE(pthread_mutex_unlock(&(s->mutex)) == 0);

	return (0);
}
