/*
 *  coWPAtty hash DB file helper functions
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cowpatty.h"

void close_free_cowpatty_hashdb(struct cowpatty_file * cf)
{
	if (cf != NULL) {
		if (cf->fp) {
			fclose(cf->fp);
		}
		free(cf);
	}
}

struct cowpatty_file * open_cowpatty_hashdb(const char * filename, const char * mode)
{
	struct hashdb_head filehead;

	// Initialize structure
	struct cowpatty_file * ret =
			(struct cowpatty_file *)malloc(sizeof(struct cowpatty_file));
	memset(ret->ssid, 0, sizeof(ret->ssid));
	memset(ret->error, 0, sizeof(ret->error));
	ret->fp = NULL;

	if (filename == NULL || filename[0] == 0) {
		strcpy(ret->error, "No filename specified");
		return ret;
	}

	if (mode == NULL || strncmp(mode, "r", 1) == 0) {
		if (strcmp(filename,"-") == 0) {
			ret->fp = stdin;
		} else {
			ret->fp = fopen(filename, "r");
			if (ret->fp == NULL) {
				snprintf(ret->error, sizeof(ret->error), "File <%s> cannot be opened", filename);
				return ret;
			}
		}
		
		// Check headers
		if (fread(&filehead, sizeof(struct hashdb_head), 1, ret->fp) != 1) {
			strcpy(ret->error, "Failed reading hash DB header");
			fclose(ret->fp);
			ret->fp = NULL;
			return ret;
		}
		
		if (filehead.magic != GENPMKMAGIC) { // Verify header magic
			strcpy(ret->error, "Header magic doesn't match");
			fclose(ret->fp);
			ret->fp = NULL;
			return ret;
		}
		if (filehead.ssid[0] == 0) {
			strcpy(ret->error, "SSID is NULL");
			fclose(ret->fp);
			ret->fp = NULL;
			return ret;
		}

		// Copy SSID
		memcpy(ret->ssid, filehead.ssid, sizeof(filehead.ssid));
		if (filehead.ssidlen > 32 || filehead.ssidlen == 0) {
			snprintf(ret->error, sizeof(ret->error), "Advertised SSID length is %u (Max length: 32)", filehead.ssidlen);
			fclose(ret->fp);
			ret->fp = NULL;
		}
	} else {
		// Write not supported yet
		strcpy(ret->error, "Write and other modes not supported yet");
	}

	return ret;
}

struct hashdb_rec * read_next_cowpatty_record(struct cowpatty_file * cf)
{
	int rc, wordlength;
	struct hashdb_rec * ret = NULL;
	
	if (cf == NULL || cf->error[0]) {
		return NULL;
	}

	if (cf->fp == NULL) {
		strcpy(cf->error, "File pointer is NULL");
		return NULL;
	}

	// Allocate memory
	ret = (struct hashdb_rec *)malloc(sizeof(struct hashdb_rec));
	if (ret == NULL) {
		strcpy(cf->error, "Failed allocating memory for coWPAtty record");
		return NULL;
	}

	// Read record size
	rc = fread(&(ret->rec_size), sizeof(ret->rec_size), 1, cf->fp);

	// Close and exit if failed
	if (rc != 1 && feof(cf->fp)) {
		free(ret);
		fclose(cf->fp);
		cf->fp = NULL;
		return NULL;
	}

	// Get passphrase length
	ret->word = NULL;
	wordlength = ret->rec_size - (sizeof(ret->pmk) + sizeof(ret->rec_size));

	if (wordlength > 0 && wordlength <= MAX_PASSPHRASE_LENGTH) {
		ret->word = (char *)calloc(wordlength + 1, sizeof(char));

		// Read passphrase
		rc += fread(ret->word, wordlength, 1, cf->fp);
		if (rc == 2) {
			// And the PMK
			rc += fread(&ret->pmk, sizeof(ret->pmk), 1, cf->fp);
		}
	}

	// Check if everything went well
	if (rc != 3 || ret->word == NULL || ret->word[0] == 0) {
		if (rc == 1) {
			snprintf(cf->error, sizeof(cf->error), "Error while reading record, failed to read passphrase invalid word length: %i", wordlength);
		} else if (rc == 2) {
			strcpy(cf->error, "Error while reading record, failed reading PMK");
		} else {
			strcpy(cf->error, "NULL or empty passphrase");
		}
		
		// Cleanup and close file
		fclose(cf->fp);
		free(ret->word);
		free(ret);
		ret = NULL;
		cf->fp = NULL;
	}

	return ret;
}