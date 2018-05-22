/*
 *  Aircrack-ng session (load/restore).
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

#include "session.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>

int ac_session_destroy(struct session * s)
{
    if (s == NULL || s->filename == NULL) {
        return 0;
    }

    FILE * f = fopen(s->filename, "r");
    if (!f) {
        return 0;
    }
    
    fclose(f);
    return remove(s->filename) == 0;
}

void ac_session_free(struct session ** s)
{
    if (s == NULL || *s == NULL) {
        return;
    }
    
    
    if ((*s)->filename) {
        
        // Delete 0 byte file
        struct stat scs;
        memset(&scs, 0, sizeof(struct stat));
        if (stat((*s)->filename, &scs) == 0 && scs.st_size == 0) {
            ac_session_destroy(*s);
        }
        
        free((*s)->filename);
    }
    if ((*s)->argv) {
        for (int i = 0; i < (*s)->argc; ++i) {
            free((*s)->argv[i]);
        }
        free((*s)->argv);
    }
    if ((*s)->working_dir) free((*s)->working_dir);
    
    free(*s);
    *s = NULL;
}


struct session * ac_session_new()
{
    return (struct session *)calloc(1, sizeof(struct session));
}

/*
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
struct session * ac_session_load(const char * filename)
{
    // Check if file exists
    if (filename == NULL || filename[0] == 0) {
        return NULL;
    }
    FILE * f = fopen(filename, "r");
    if (f == NULL) {
        return NULL;
    }
    
    // Check size isn't 0
    uint64_t fsize = fseeko(f, 0, SEEK_END);
    if (fsize == 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    // Prepare structure
    struct session * ret = ac_session_new();
    if (ret == NULL) {
        fclose(f);
        return NULL;
    }

    ret->filename = strdup(filename);
    
    char * line;
    int line_nr = 0;
    size_t n;
    while (1) {
        line = NULL;
        n = 0;
        ssize_t line_len = getline(&line, &n, f);
        
        // Basic checks and trimming
        if (line_len == -1) break;
        if (line[0] == '#') continue;
        if (strlen(line) > 0) {
            if (line[strlen(line) - 1] == '\n') line[strlen(line) - 1] = 0;
            if (line[strlen(line) - 1] == '\r') line[strlen(line) - 1] = 0;
        }

        // The first 4 parameters cannot be empty
        if (line_nr < SESSION_ARGUMENTS_LINE && strlen(line) == 0) {
            free(line);
            fclose(f);
            ac_session_free(&ret);
            return NULL;
        }
        
        // Check the parameters
        switch (line_nr) {
            case 0: // Working directory
            {
                if (chdir(line) == -1) {
                    free(line);
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }
                ret->working_dir = line;
                
                break;
            }
            case 1: // BSSID
            {
                // Check length
                if (strlen(line) != 17) {
                    free(line);
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }

                // Parse BSSID
                unsigned int bssid[6];
                int count = sscanf(line, "%02X:%02X:%02X:%02X:%02X:%02X", &bssid[0], &bssid[1],
                                            &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
                free(line);

                // Verify all parsed correctly
                if (count < 6) {
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }
                
                // Copy it back to the structure
                for (int i = 0; i < 6; ++i) {
                    ret->bssid[i] = (uint8_t)bssid[i];
                }
                break;
            }
            case 2: // Wordlist ID, position in wordlist and amount of keys tried
            {
                if (sscanf(line, "%hhu %" PRId64 " %lld", &(ret->wordlist_id), &(ret->pos), &(ret->nb_keys_tried)) != 3 
                    || ret->pos < 0 || ret->nb_keys_tried < 0) {
                    free(line);
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }
                break;
            }
            case 3: // Number of arguments
            {
                int sscanf_ret = sscanf(line, "%d", &(ret->argc));
                free(line);
                if (sscanf_ret != 1 || ret->argc < 2) {
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }

                // Allocate memory for all the arguments
                ret->argv = (char **)calloc(ret->argc, sizeof(char *));
                if (ret->argv == NULL) {
                    fclose(f);
                    ac_session_free(&ret);
                    return NULL;
                }

                break;
            }
            default: // All the arguments
            {
                ret->argv[line_nr - SESSION_ARGUMENTS_LINE] = line;
                break;
            }
        }
        ++line_nr;
    }
    
    fclose(f);
    if (line_nr < SESSION_ARGUMENTS_LINE + 1) {
        ac_session_free(&ret);
        return NULL;
    }
    
    return ret;
}

struct session * ac_session_from_argv(const int argc, char ** argv, const char * filename)
{
    if (filename == NULL || filename[0] == 0 || argc <= 3 || argv == NULL) {
        // If it only has this parameter, then there is something wrong
        return NULL;
    }

    // Check if the file exists and create it if it doesn't
    int fd = -1;
    if ((fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666)) >= 0) {
        // Just create an empty file for now
        close(fd);
    } else {
        // Not overwriting
        fprintf(stderr, "Session file already exists: %s\n", filename);
        return NULL;
    }
        
    // Prepare structure
    struct session * ret = ac_session_new();
    if (ret == NULL) {
        return NULL;
    }

    // Get working directory and copy filename
    size_t wd_size = 0;
    char * wd_ret;
    do {
        wd_size += PATH_MAX;
        char * wd_realloc = (char *)realloc(ret->working_dir, wd_size);
        if (wd_realloc == NULL) {
            ac_session_free(&ret);
            return NULL;
        }
        ret->working_dir = wd_realloc;
        wd_ret = getcwd(ret->working_dir, wd_size);
        if (wd_ret == NULL && errno != ERANGE) {
            ac_session_free(&ret);
            return NULL;
        }
    } while (wd_ret == NULL && errno == ERANGE);

    // Copy filename
    ret->filename = strdup(filename);
    if (ret->filename == NULL) {
        ac_session_free(&ret);
        return NULL;
    }

    // Copy argc and argv, except the 2 specifying session filename location
    ret->argv = (char **)calloc(argc - 2, sizeof(char *));
    if (ret->argv == NULL) {
        ac_session_free(&ret);
        return NULL;
    }
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], filename) == 0) {
            // Found the filename, now remove the previously copied argument
            ret->argc--;
            free(ret->argv[ret->argc]);
            ret->argv[ret->argc] = NULL;
            continue;
        }

        // Copy argument
        ret->argv[ret->argc] = strdup(argv[i]);
        if (ret->argv[ret->argc] == NULL) {
            ac_session_free(&ret);
            return NULL;
        }

        // Increment count
        ret->argc++;
    }
    
    return ret;
}

int ac_session_save(struct session * s, long long int nb_keys_tried)
{
    if (s == NULL || s->filename == NULL || s->working_dir == NULL
        || s->argc == 0 || s->argv == NULL) {
        return -1;
    }

    FILE * f = fopen(s->filename, "w");
    if (f == NULL) {
        return -1;
    }

    // Update amount of keys tried in structure
    s->nb_keys_tried = nb_keys_tried;

    // Write it
    fprintf(f, "%s\n", s->working_dir);
    fprintf(f, "%02X:%02X:%02X:%02X:%02X:%02X\n", s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5]);
    fprintf(f, "%d %" PRId64 " %lld\n", s->wordlist_id, s->pos, s->nb_keys_tried);
    fprintf(f, "%d\n", s->argc);
    for (int i = 0; i < s->argc; ++i) {
        fprintf(f, "%s\n", s->argv[i]);
    }
    fclose(f);
    
    return 0;
}