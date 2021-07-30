/*
  *  Copyright (c) 2010 Andrea Bittau <bittau@cs.stanford.edu>
  *
  *  OS dependent API for using card via a pcap file.
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
  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>

#include "osdep.h"
#include "aircrack-ng/support/pcap_local.h"
#include "radiotap/radiotap_iter.h"
#include "common.h"

struct priv_file
{
	int pf_fd;
	int pf_chan;
	int pf_rate;
	int pf_dtl;
	uint32_t pf_magic;
	unsigned char pf_mac[6];
};

static int file_read(struct wif * wi,
					 struct timespec * ts,
					 int * dlt,
					 unsigned char * h80211,
					 int len,
					 struct rx_info * ri)
{
	struct priv_file * pf = wi_priv(wi);
	struct pcap_pkthdr pkh;
	int rc;
	int got_signal = 0;
	int got_noise = 0;
	unsigned char buf[4096] __attribute__((aligned(8)));
	int off = 0;
	struct ieee80211_radiotap_header * rh;
	struct ieee80211_radiotap_iterator iterator;

	memset(&iterator, 0, sizeof(iterator));

	rc = read(pf->pf_fd, &pkh, sizeof(pkh));
	if (rc != sizeof(pkh)) return -1;

	if (pf->pf_magic == TCPDUMP_CIGAM)
	{
		pkh.caplen = ___my_swab32(pkh.caplen);
		pkh.len = ___my_swab32(pkh.len);
	}

	if (pkh.caplen > sizeof(buf))
	{
		printf("Bad caplen %lu\n", (unsigned long) pkh.caplen);
		return 0;
	}

	assert(pkh.caplen <= sizeof(buf)); //-V547

	rc = read(pf->pf_fd, buf, pkh.caplen);
	if (rc != (int) pkh.caplen) return -1;

	if (ri) memset(ri, 0, sizeof(*ri));

	switch (pf->pf_dtl)
	{
		case LINKTYPE_IEEE802_11:
			off = 0;
			break;

		case LINKTYPE_RADIOTAP_HDR:
			rh = (struct ieee80211_radiotap_header *) buf;
			off = le16_to_cpu(rh->it_len);

			if (ieee80211_radiotap_iterator_init(&iterator, rh, rc, NULL) < 0)
				return -1;

			while (ieee80211_radiotap_iterator_next(&iterator) >= 0)
			{
				switch (iterator.this_arg_index)
				{
					case IEEE80211_RADIOTAP_TSFT:
						if (ri)
							ri->ri_mactime = le64_to_cpu(
								*((uint64_t *) iterator.this_arg));
						break;

					case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
					case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
						if (ri && !got_signal)
						{
							if (*iterator.this_arg < 127)
								ri->ri_power = *iterator.this_arg;
							else
								ri->ri_power = *iterator.this_arg - 255;

							got_signal = 1;
						}
						break;

					case IEEE80211_RADIOTAP_DB_ANTNOISE:
					case IEEE80211_RADIOTAP_DBM_ANTNOISE:
						if (ri && !got_noise)
						{
							if (*iterator.this_arg < 127)
								ri->ri_noise = *iterator.this_arg;
							else
								ri->ri_noise = *iterator.this_arg - 255;

							got_noise = 1;
						}
						break;

					case IEEE80211_RADIOTAP_ANTENNA:
						if (ri) ri->ri_antenna = *iterator.this_arg;
						break;

					case IEEE80211_RADIOTAP_CHANNEL:
						if (ri)
							ri->ri_channel = getChannelFromFrequency(
								le16toh(*(uint16_t *) iterator.this_arg));
						break;

					case IEEE80211_RADIOTAP_RATE:
						if (ri) ri->ri_rate = (*iterator.this_arg) * 500000;
						break;

					case IEEE80211_RADIOTAP_FLAGS:
						if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS)
							rc -= 4;
						break;
				}
			}
			break;

		case LINKTYPE_PRISM_HEADER:
			if (buf[7] == 0x40)
			{
				off = 0x40;

				if (ri)
				{
					ri->ri_power = -((int32_t) load32_le(buf + 0x33));
					ri->ri_noise = (int32_t) load32_le(buf + 0x33 + 12);
					ri->ri_rate = load32_le(buf + 0x33 + 24) * 500000;

					got_signal = 1;
					got_noise = 1;
				}
			}
			else
			{
				off = load32_le(buf + 4);

				if (ri)
				{
					ri->ri_mactime = load64_le(buf + 0x5C - 48);
					ri->ri_channel = load32_le(buf + 0x5C - 36);
					ri->ri_power = -((int32_t) load32_le(buf + 0x5C));
					ri->ri_noise = (int32_t) load32_le(buf + 0x5C + 12);
					ri->ri_rate = load32_le(buf + 0x5C + 24) * 500000;
				}
			}

			rc -= 4;
			break;

		case LINKTYPE_PPI_HDR:
			off = load16_le(buf + 2);

			/* for a while Kismet logged broken PPI headers */
			if (off == 24 && load16_le(buf + 8) == 2) off = 32;

			break;

		case LINKTYPE_ETHERNET:
			printf("Ethernet packets\n");
			return 0;

		default:
			errx(1, "Unknown DTL %d", pf->pf_dtl);
			break;
	}

	rc -= off;
	assert(rc >= 0);

	if (off < 0 || rc < 0) return -1;

	if (rc > len) rc = len;

	if (dlt)
	{
		*dlt = LINKTYPE_IEEE802_11;
	}

	if (ts)
	{
		ts->tv_sec = pkh.tv_sec;
		ts->tv_nsec = pkh.tv_usec * 1000UL;
	}

	if (off < 0 || off >= len) return -1; //-V560
	memcpy(h80211, &buf[off], rc);

	return rc;
}

static int file_get_mac(struct wif * wi, unsigned char * mac)
{
	struct priv_file * pn = wi_priv(wi);

	memcpy(mac, pn->pf_mac, sizeof(pn->pf_mac));

	return 0;
}

static int file_write(struct wif * wi,
					  struct timespec * ts,
					  int dlt,
					  unsigned char * h80211,
					  int len,
					  struct tx_info * ti)
{
	struct priv_file * pn = wi_priv(wi);

	if (h80211 && ti && pn && ts && dlt)
	{
	}

	return len;
}

static int file_set_channel(struct wif * wi, int chan)
{
	struct priv_file * pf = wi_priv(wi);

	pf->pf_chan = chan;

	return 0;
}

static int file_get_channel(struct wif * wi)
{
	struct priv_file * pf = wi_priv(wi);

	return pf->pf_chan;
}

static int file_set_rate(struct wif * wi, int rate)
{
	struct priv_file * pf = wi_priv(wi);

	pf->pf_rate = rate;

	return 0;
}

static int file_get_rate(struct wif * wi)
{
	struct priv_file * pf = wi_priv(wi);

	return pf->pf_rate;
}

static int file_get_monitor(struct wif * wi)
{
	if (wi)
	{
	}

	return 1;
}

static void file_close(struct wif * wi)
{
	struct priv_file * pn = wi_priv(wi);

	if (pn)
	{
		if (pn->pf_fd)
		{
			close(pn->pf_fd);
		}
		free(pn);
	}

	free(wi);
}

static int file_fd(struct wif * wi)
{
	struct priv_file * pf = wi_priv(wi);

	return pf->pf_fd;
}

struct wif * file_open(char * iface)
{
	struct wif * wi;
	struct priv_file * pf;
	int fd;
	struct pcap_file_header pfh;
	int rc;

	if (iface == NULL || strncmp(iface, "file://", 7) != 0) return NULL;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*pf));
	if (!wi) return NULL;

	wi->wi_read = file_read;
	wi->wi_write = file_write;
	wi->wi_set_channel = file_set_channel;
	wi->wi_get_channel = file_get_channel;
	wi->wi_set_rate = file_set_rate;
	wi->wi_get_rate = file_get_rate;
	wi->wi_close = file_close;
	wi->wi_fd = file_fd;
	wi->wi_get_mac = file_get_mac;
	wi->wi_get_monitor = file_get_monitor;

	pf = wi_priv(wi);

	fd = open(iface + 7, O_RDONLY);
	if (fd == -1) err(1, "open()");

	pf->pf_fd = fd;

	if ((rc = read(fd, &pfh, sizeof(pfh))) != sizeof(pfh)) goto __err;

	if (pfh.magic != TCPDUMP_MAGIC && pfh.magic != TCPDUMP_CIGAM) goto __err;

	if (pfh.magic == TCPDUMP_CIGAM)
	{
		pfh.version_major = ___my_swab16(pfh.version_major);
		pfh.version_minor = ___my_swab16(pfh.version_minor);
		pfh.linktype = ___my_swab32(pfh.linktype);
	}

	if (pfh.version_major != PCAP_VERSION_MAJOR
		|| pfh.version_minor != PCAP_VERSION_MINOR)
		goto __err;

	pf->pf_dtl = pfh.linktype;
	pf->pf_magic = pfh.magic;

	return wi;

__err:
	wi_close(wi);
	return (struct wif *) -1;
}
