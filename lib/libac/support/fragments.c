/*
 *  Copyright (C) 2006-2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/support/fragments.h"
#include "aircrack-ng/crypto/crypto.h"

extern pFrag_t rFragment;

int addFrag(unsigned char * packet,
			unsigned char * smac,
			int len,
			int crypt,
			unsigned char * wepkey,
			int weplen)
{
	pFrag_t cur = rFragment;
	int seq, frag, wep, z, i;
	unsigned char frame[4096];
	unsigned char K[128];

	if (packet == NULL) return (-1);
	if (smac == NULL) return (-1);
	if (len <= 32 || len > 2000) return (-1);
	if (rFragment == NULL) return (-1);

	memset(frame, 0, sizeof(frame));
	memcpy(frame, packet, (size_t) len);

	z = ((frame[1] & 3) != 3) ? 24 : 30;
	frag = frame[22] & 0x0F;
	seq = (frame[22] >> 4) | (frame[23] << 4);
	wep = (frame[1] & 0x40) >> 6;

	ALLEGE(frag >= 0 && frag <= 15); //-V560

	if (wep && crypt != CRYPT_WEP) return (-1);

	if (wep)
	{
		// decrypt it
		memcpy(K, frame + z, 3);
		memcpy(K + 3, wepkey, (size_t) weplen);

		if (decrypt_wep(frame + z + 4, len - z - 4, K, 3 + weplen) == 0
			&& (len - z - 4 > 8))
		{
			printf("error decrypting... len: %d\n", len - z - 4);
			return (-1);
		}

		/* WEP data packet was successfully decrypted, *
		* remove the WEP IV & ICV and write the data  */

		len -= 8;

		memcpy(frame + z, frame + z + 4, (size_t) len - z);

		frame[1] &= 0xBF;
	}

	while (cur->next != NULL)
	{
		cur = cur->next;
		if ((memcmp(smac, cur->source, 6) == 0) && (seq == cur->sequence)
			&& (wep == cur->wep))
		{
			// entry already exists, update
			if (cur->fragment[frag] != NULL) return (0);

			if ((frame[1] & 0x04) == 0)
			{
				cur->fragnum = (char) frag; // no higher frag number possible
			}
			cur->fragment[frag] = (unsigned char *) malloc((size_t) len - z);
			ALLEGE(cur->fragment[frag] != NULL);
			memcpy(cur->fragment[frag], frame + z, (size_t) len - z);
			cur->fragmentlen[frag] = (short) (len - z);
			gettimeofday(&cur->access, NULL);

			return (0);
		}
	}

	// new entry, first fragment received
	// alloc mem
	cur->next = (pFrag_t) malloc(sizeof(struct Fragment_list));
	ALLEGE(cur->next != NULL);
	cur = cur->next;

	for (i = 0; i < 16; i++)
	{
		cur->fragment[i] = NULL;
		cur->fragmentlen[i] = 0;
	}

	if ((frame[1] & 0x04) == 0)
	{
		cur->fragnum = (char) frag; // no higher frag number possible
	}
	else
	{
		cur->fragnum = 0;
	}

	// remove retry & more fragments flag
	frame[1] &= 0xF3;
	// set frag number to 0
	frame[22] &= 0xF0;
	memcpy(cur->source, smac, 6);
	cur->sequence = (uint16_t) seq;
	cur->header = (unsigned char *) malloc((size_t) z);
	ALLEGE(cur->header != NULL);
	memcpy(cur->header, frame, (size_t) z);
	cur->headerlen = (int16_t) z;
	cur->fragment[frag] = (unsigned char *) malloc((size_t) len - z);
	ALLEGE(cur->fragment[frag] != NULL);
	memcpy(cur->fragment[frag], frame + z, len - z);
	cur->fragmentlen[frag] = (int16_t)(len - z);
	cur->wep = (int8_t) wep;
	gettimeofday(&cur->access, NULL);

	cur->next = NULL;

	return (0);
}

int timeoutFrag(void)
{
	pFrag_t old, cur = rFragment;
	struct timeval tv;
	int64_t timediff;
	int i;

	if (rFragment == NULL) return (-1);

	gettimeofday(&tv, NULL);

	while (cur->next != NULL)
	{
		old = cur->next;
		timediff = (tv.tv_sec - old->access.tv_sec) * 1000000UL
				   + (tv.tv_usec - old->access.tv_usec);
		if (timediff > FRAG_TIMEOUT)
		{
			// remove captured fragments
			if (old->header != NULL) free(old->header);
			for (i = 0; i < 16; i++)
				if (old->fragment[i] != NULL) free(old->fragment[i]);

			cur->next = old->next;
			free(old);
		}
		cur = cur->next;
	}

	return (0);
}

int delFrag(unsigned char * smac, int sequence)
{
	pFrag_t old, cur = rFragment;
	int i;

	if (rFragment == NULL) return (-1);
	if (smac == NULL) return (-1);
	if (sequence < 0) return (-1);

	while (cur->next != NULL)
	{
		old = cur->next;
		if (memcmp(smac, old->source, 6) == 0 && old->sequence == sequence)
		{
			// remove captured fragments
			if (old->header != NULL) free(old->header);
			for (i = 0; i < 16; i++)
				if (old->fragment[i] != NULL) free(old->fragment[i]);

			cur->next = old->next;
			free(old);

			return (0);
		}
		cur = cur->next;
	}

	return (0);
}

unsigned char * getCompleteFrag(unsigned char * smac,
								int sequence,
								size_t * packetlen,
								int crypt,
								unsigned char * wepkey,
								int weplen)
{
	pFrag_t old, cur = rFragment;
	int i, len = 0;
	unsigned char * packet = NULL;
	unsigned char K[128];

	if (rFragment == NULL) return (NULL);
	if (smac == NULL) return (NULL);

	while (cur->next != NULL)
	{
		old = cur->next;
		if (memcmp(smac, old->source, 6) == 0 && old->sequence == sequence)
		{
			// check if all frags available
			if (old->fragnum == 0) return (NULL);

			for (i = 0; i <= old->fragnum; i++)
			{
				if (old->fragment[i] == NULL) return (NULL);
				len += old->fragmentlen[i];
			}

			if (len > 2000) return (NULL);

			if (old->wep)
			{
				if (crypt == CRYPT_WEP)
				{
					packet = (unsigned char *) malloc(
						(size_t) len + old->headerlen + 8);
					ALLEGE(packet != NULL);
					K[0] = rand_u8();
					K[1] = rand_u8();
					K[2] = rand_u8();
					K[3] = (uint8_t)(0x00);

					memcpy(packet, old->header, (size_t) old->headerlen);
					len = old->headerlen;
					memcpy(packet + len, K, 4); //-V512
					len += 4;

					for (i = 0; i <= old->fragnum; i++)
					{
						memcpy(packet + len,
							   old->fragment[i],
							   (size_t) old->fragmentlen[i]);
						len += old->fragmentlen[i];
					}

					/* write crc32 value behind data */
					if (add_crc32(packet + old->headerlen + 4,
								  len - old->headerlen - 4)
						!= 0)
						return (NULL);

					len += 4; // icv

					memcpy(K + 3, wepkey, (size_t) weplen);

					encrypt_wep(packet + old->headerlen + 4,
								len - old->headerlen - 4,
								K,
								weplen + 3);

					packet[1] = (uint8_t)(packet[1] | 0x40);

					// delete captured fragments
					delFrag(smac, sequence);
					*packetlen = (size_t) len;
					return (packet);
				}
				else
					return (NULL);
			}
			else
			{
				packet
					= (unsigned char *) malloc((size_t) len + old->headerlen);
				ALLEGE(packet != NULL);
				memcpy(packet, old->header, (size_t) old->headerlen);
				len = old->headerlen;
				for (i = 0; i <= old->fragnum; i++)
				{
					memcpy(packet + len,
						   old->fragment[i],
						   (size_t) old->fragmentlen[i]);
					len += old->fragmentlen[i];
				}

				// delete captured fragments
				delFrag(smac, sequence);
				*packetlen = (size_t) len;
				return (packet);
			}
		}

		cur = cur->next;
	}

	return (packet);
}
