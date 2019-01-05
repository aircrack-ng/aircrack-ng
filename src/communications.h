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

#ifndef AIRCRACK_NG_COMMUNICATIONS_H
#define AIRCRACK_NG_COMMUNICATIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "defs.h"
#include "aircrack-osdep/osdep.h"
#include "aircrack-util/common.h"
#include "include/ieee80211.h"

/* Expects host-endian arguments, but returns little-endian seq. */
static inline uint16_t fnseq(uint16_t fn, uint16_t seq)
{
	uint16_t r = 0;

	if (fn > 15)
	{
		fprintf(stderr, "too many fragments (%d)\n", fn);
		exit(EXIT_FAILURE);
	}

	r = fn;

	r |= ((seq % 4096) << IEEE80211_SEQ_SEQ_SHIFT);

	return (htole16(r));
}

static inline int get_ip_port(char * iface, char * ip, const int ip_size)
{
	REQUIRE(iface != NULL);
	REQUIRE(ip != NULL);
	REQUIRE(ip_size > 0);

	char * host;
	char * ptr;
	int port = -1;
	struct in_addr addr;

	host = strdup(iface);
	if (!host) return (-1);

	ptr = strchr(host, ':');
	if (!ptr) goto out;

	*ptr++ = 0;

	if (!inet_aton(host, (struct in_addr *) &addr))
		goto out; /* XXX resolve hostname */

	if (strlen(host) > 15)
	{
		port = -1;
		goto out;
	}

	strncpy(ip, host, (size_t) ip_size);
	port = (int) strtol(ptr, NULL, 10);
	if (port <= 0) port = -1;

out:
	free(host);
	return (port);
}

int read_packet(struct wif * wi,
				void * buf,
				uint32_t count,
				struct rx_info * ri);

int wait_for_beacon(struct wif * wi,
					uint8_t * bssid,
					uint8_t * capa,
					char * essid);

int attack_check(uint8_t * bssid,
				 char * essid,
				 uint8_t * capa,
				 struct wif * wi,
				 int ignore_negative_one);

typedef void (*read_sleep_cb)(void);

static inline void read_sleep(int fd_in, unsigned long usec, read_sleep_cb cb)
{
	struct timeval tv, tv2, tv3;
	fd_set rfds;

	gettimeofday(&tv, NULL);
	gettimeofday(&tv2, NULL);

	tv3.tv_sec = 0;
	tv3.tv_usec = 10000;

	while (((tv2.tv_sec * 1000000UL - tv.tv_sec * 1000000UL)
			+ (tv2.tv_usec - tv.tv_usec))
		   < (usec))
	{
		FD_ZERO(&rfds);
		FD_SET(fd_in, &rfds);

		if (select(fd_in + 1, &rfds, NULL, NULL, &tv3) < 0)
		{
			continue;
		}

		if (FD_ISSET(fd_in, &rfds)) cb();

		gettimeofday(&tv2, NULL);
	}
}

extern unsigned long nb_pkt_sent;

static inline int send_packet(struct wif * wi,
							  void * buf,
							  size_t count,
							  bool rewriteSequenceNumber)
{
	REQUIRE(buf != NULL);
	REQUIRE(count >= 0);

	uint8_t * pkt = (uint8_t *) buf;

	if (rewriteSequenceNumber && (count > 24) && (pkt[1] & 0x04) == 0
		&& (pkt[22] & 0x0F) == 0)
	{
		pkt[22] = (uint8_t)((nb_pkt_sent & 0x0000000F) << 4);
		pkt[23] = (uint8_t)((nb_pkt_sent & 0x00000FF0) >> 4);
	}
	else if (rewriteSequenceNumber && count > 24)
	{
		// Set the duration...
		pkt[2] = 0x3A;
		pkt[3] = 0x01;

		// Reset Retry Flag
		pkt[1] = (uint8_t)(pkt[1] & ~0x4);
	}

	if (wi_write(wi, buf, (int) count, NULL) == -1)
	{
		switch (errno)
		{
			case EAGAIN:
			case ENOBUFS:
				usleep(10000);
				return (0); /* XXX not sure I like this... -sorbo */

			default:
				perror("wi_write()");
				return (-1);
		}
	}

	++nb_pkt_sent;

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
		   int nodetect);

#endif //AIRCRACK_NG_COMMUNICATIONS_H
