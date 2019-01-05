/*
 *  Copyright (C) 2006-2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2006-2009 Martin Beck <martin.beck2@gmx.de>
 *  Copyright (C) 2018-2019 Joseph Benden <joe@benden.us>
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

#include <errno.h>
#include <sys/time.h>

#include "defs.h"
#include "communications.h"
#include "crypto.h"
#include "aircrack-util/verifyssid.h"

int read_packet(struct wif * wi,
				void * buf,
				uint32_t count,
				struct rx_info * ri)
{
	REQUIRE(buf != NULL && count > 0);
	REQUIRE(ri != NULL);

	int rc;

	rc = wi_read(wi, buf, count, ri);
	if (rc == -1)
	{
		switch (errno)
		{
			case EAGAIN:
				return (0);

			default:
				perror("wi_read()");
				return (-1);
		}
	}

	return (rc);
}

int wait_for_beacon(struct wif * wi,
					uint8_t * bssid,
					uint8_t * capa,
					char * essid)
{
	int len = 0, chan = 0, taglen = 0, tagtype = 0, pos = 0;
	uint8_t pkt_sniff[4096];
	struct timeval tv, tv2;
	char essid2[33];

	gettimeofday(&tv, NULL);
	while (1)
	{
		len = 0;
		while (len < 22)
		{
			len = read_packet(wi, pkt_sniff, sizeof(pkt_sniff), NULL);

			gettimeofday(&tv2, NULL);
			if (((tv2.tv_sec - tv.tv_sec) * 1000000)
					+ (tv2.tv_usec - tv.tv_usec)
				> 10000 * 1000) // wait 10sec for beacon frame
			{
				return (-1);
			}
			if (len <= 0) usleep(1);
		}

		if (!memcmp(pkt_sniff, "\x80", 1))
		{
			pos = 0;
			taglen = 22; // initial value to get the fixed tags parsing started
			taglen += 12; // skip fixed tags in frames
			do
			{
				pos += taglen + 2;
				tagtype = pkt_sniff[pos];
				taglen = pkt_sniff[pos + 1];
			} while (tagtype != 3 && pos < len - 2);

			if (tagtype != 3) continue;
			if (taglen != 1) continue;
			if (pos + 2 + taglen > len) continue;

			chan = pkt_sniff[pos + 2];

			if (essid)
			{
				pos = 0;
				taglen
					= 22; // initial value to get the fixed tags parsing started
				taglen += 12; // skip fixed tags in frames
				do
				{
					pos += taglen + 2;
					tagtype = pkt_sniff[pos];
					taglen = pkt_sniff[pos + 1];
				} while (tagtype != 0 && pos < len - 2);

				if (tagtype != 0) continue;
				if (taglen <= 1)
				{
					if (bssid != NULL && memcmp(bssid, pkt_sniff + 10, 6) == 0)
						break;
					else
						continue;
				}
				if (pos + 2 + taglen > len) continue;

				if (taglen > 32) taglen = 32;

				if ((pkt_sniff + pos + 2)[0] < 32 && bssid != NULL
					&& memcmp(bssid, pkt_sniff + 10, 6) == 0)
				{
					break;
				}

				/* if bssid is given, copy essid */
				if (bssid != NULL && memcmp(bssid, pkt_sniff + 10, 6) == 0
					&& strlen(essid) == 0)
				{
					memset(essid, 0, 33);
					memcpy(essid, pkt_sniff + pos + 2, taglen);
					break;
				}

				/* if essid is given, copy bssid AND essid, so we can handle
				 * case insensitive arguments */
				if (bssid != NULL && memcmp(bssid, NULL_MAC, 6) == 0
					&& strncasecmp(essid, (char *) pkt_sniff + pos + 2, taglen)
						   == 0
					&& strlen(essid) == (unsigned) taglen)
				{
					memset(essid, 0, 33);
					memcpy(essid, pkt_sniff + pos + 2, taglen);
					memcpy(bssid, pkt_sniff + 10, 6);
					printf("Found BSSID \"%02X:%02X:%02X:%02X:%02X:%02X\" to "
						   "given ESSID \"%s\".\n",
						   bssid[0],
						   bssid[1],
						   bssid[2],
						   bssid[3],
						   bssid[4],
						   bssid[5],
						   essid);
					break;
				}

				/* if essid and bssid are given, check both */
				if (bssid != NULL && memcmp(bssid, pkt_sniff + 10, 6) == 0
					&& strlen(essid) > 0)
				{
					memset(essid2, 0, 33);
					memcpy(essid2, pkt_sniff + pos + 2, taglen);
					if (strncasecmp(essid, essid2, taglen) == 0
						&& strlen(essid) == (unsigned) taglen)
						break;
					else
					{
						printf("For the given BSSID "
							   "\"%02X:%02X:%02X:%02X:%02X:%02X\", there is an "
							   "ESSID mismatch!\n",
							   bssid[0],
							   bssid[1],
							   bssid[2],
							   bssid[3],
							   bssid[4],
							   bssid[5]);
						printf(
							"Found ESSID \"%s\" vs. specified ESSID \"%s\"\n",
							essid2,
							essid);
						printf("Using the given one, double check it to be "
							   "sure its correct!\n");
						break;
					}
				}
			}
		}
	}

	if (capa) memcpy(capa, pkt_sniff + 34, 2);

	return (chan);
}

/**
	if bssid != NULL its looking for a beacon frame
*/
int attack_check(uint8_t * bssid,
				 char * essid,
				 uint8_t * capa,
				 struct wif * wi,
				 int ignore_negative_one)
{
	int ap_chan = 0, iface_chan = 0;

	iface_chan = wi_get_channel(wi);

	if (iface_chan == -1 && !ignore_negative_one)
	{
		PCT;
		printf("Couldn't determine current channel for %s, you should either "
			   "force the operation with --ignore-negative-one or apply a "
			   "kernel patch\n",
			   wi_get_ifname(wi));
		return (-1);
	}

	if (bssid != NULL)
	{
		ap_chan = wait_for_beacon(wi, bssid, capa, essid);
		if (ap_chan < 0)
		{
			PCT;
			printf("No such BSSID available.\n");
			return (-1);
		}
		if ((ap_chan != iface_chan)
			&& (iface_chan != -1 || !ignore_negative_one))
		{
			PCT;
			printf("%s is on channel %d, but the AP uses channel %d\n",
				   wi_get_ifname(wi),
				   iface_chan,
				   ap_chan);
			return (-1);
		}
	}

	return (0);
}

int getnet(struct wif * wi,
		   uint8_t * capa,
		   int filter,
		   int force,
		   uint8_t * f_bssid,
		   uint8_t * r_bssid,
		   uint8_t * r_essid,
		   int ignore_negative_one,
		   int nodetect)
{
	uint8_t * bssid;

	if (nodetect) return (0);

	if (filter)
		bssid = f_bssid;
	else
		bssid = r_bssid;

	if (memcmp(bssid, NULL_MAC, 6) != 0)
	{
		PCT;
		printf("Waiting for beacon frame (BSSID: "
			   "%02X:%02X:%02X:%02X:%02X:%02X) on channel %d\n",
			   bssid[0],
			   bssid[1],
			   bssid[2],
			   bssid[3],
			   bssid[4],
			   bssid[5],
			   wi_get_channel(wi));
	}
	else if (strlen((const char *) r_essid) > 0)
	{
		PCT;
		printf("Waiting for beacon frame (ESSID: %s) on channel %d\n",
			   r_essid,
			   wi_get_channel(wi));
	}
	else if (force)
	{
		PCT;
		if (filter)
		{
			printf("Please specify at least a BSSID (-b) or an ESSID (-e)\n");
		}
		else
		{
			printf("Please specify at least a BSSID (-a) or an ESSID (-e)\n");
		}

		return (1);
	}
	else
		return (0);

	if (attack_check(bssid, (char *) r_essid, capa, wi, ignore_negative_one)
		!= 0)
	{
		if (memcmp(bssid, NULL_MAC, 6) != 0)
		{
			if (verifyssid(r_essid) == 0)
			{
				printf("Please specify an ESSID (-e).\n");
			}
		}
		else
		{
			if (strlen((const char *) r_essid) > 0)
			{
				printf("Please specify a BSSID (-a).\n");
			}
		}

		return (1);
	}

	return (0);
}