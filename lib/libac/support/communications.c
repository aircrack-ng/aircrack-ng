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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/tui/console.h"
#include "aircrack-ng/utf8/verifyssid.h"

#include "aircrack-ng/osdep/byteorder.h"
#include "aircrack-ng/osdep/packed.h"
#include "aircrack-ng/third-party/ethernet.h"
#include "aircrack-ng/third-party/ieee80211.h"

extern struct communication_options opt;
extern struct devices dev;
struct wif *_wi_in = NULL, *_wi_out = NULL;
uint8_t h80211[4096] __attribute__((aligned(16)));
uint8_t tmpbuf[4096] __attribute__((aligned(16)));
static char strbuf[512] __attribute__((aligned(16)));

int read_packet(struct wif * wi,
				void * buf,
				uint32_t count,
				struct rx_info * ri)
{
	REQUIRE(buf != NULL && count > 0);

	int rc;

	rc = wi_read(wi, NULL, NULL, buf, count, ri);
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

/* A beacon-frame contains a lot of data ordered like this:
 * <tag (1 byte)><length(1 byte)><data (length bytes)><tag><length><data>.....
 * This functions tries to find a specific tag
 */
static int get_tagged_data(uint8_t * beacon_pkt,
						   size_t pkt_len,
						   uint8_t tag,
						   uint8_t * tag_len, /* Receives length of the data */
						   uint8_t ** tag_data) /* Receives pointer to data */
{
	size_t pos;
	size_t
		taglen; /* Length of tag-data. Does not include the two-byte tag-header */
	uint8_t tagtype;

	if (beacon_pkt[0] != 0x80) return -1;

	pos = 0;
	taglen = 22; /* First 22 bytes contains standard stuff like SRC+DST */
	taglen += 12; /* The fixed tags are 12 bytes long */
	do
	{
		pos += taglen + 2;
		tagtype = beacon_pkt[pos];
		taglen = beacon_pkt[pos + 1];
	} while (tagtype != tag && pos < pkt_len - 2);

	if (tagtype != tag)
	{
		/* Tag not found */
		return -1;
	}

	if (pos + 2 + taglen > pkt_len)
	{
		/* Malformed packet? */
		return -1;
	}

	if (tag_data != NULL)
	{
		*tag_data = &beacon_pkt[pos + 2];
	}

	if (tag_len != NULL)
	{
		*tag_len = taglen;
	}

	return 0;
}

int get_channel(uint8_t * beacon_pkt, size_t pkt_len)
{
	uint8_t * ch;
	uint8_t * ht_info;
	uint8_t tag_len;

	/* Look for the standard tag */
	if (get_tagged_data(beacon_pkt, pkt_len, MGNT_PAR_CHANNEL, &tag_len, &ch)
		== 0)
	{
		if (tag_len >= 1)
		{
			return *ch;
		}
	}

	/* Tag not found, look for the HT information tag used by 11n devices*/
	if (get_tagged_data(
			beacon_pkt, pkt_len, MGNT_PAR_HT_INFO, &tag_len, &ht_info))
	{
		/* tag not found... */
		return -1;
	}

	if (tag_len < 1)
	{
		/* Malformed packet? */
		return -1;
	}

	/* Main channel is first in HT info */
	return ht_info[0];
}

int wait_for_beacon(struct wif * wi,
					uint8_t * bssid,
					uint8_t * capa,
					char * essid)
{
	int chan = 0;
	size_t len = 0;
	ssize_t read_len = 0;
	uint8_t taglen = 0;
	uint8_t pkt_sniff[4096] __attribute__((aligned(16))) = {0};
	struct timeval tv, tv2;
	char essid2[33];
	uint8_t * data = NULL;

	gettimeofday(&tv, NULL);
	while (1)
	{
		read_len = len = 0;

		while (read_len < 22)
		{
			read_len = read_packet(wi, pkt_sniff, sizeof(pkt_sniff), NULL);

			gettimeofday(&tv2, NULL);
			if (((tv2.tv_sec - tv.tv_sec) * 1000000)
					+ (tv2.tv_usec - tv.tv_usec)
				> 10000 * 1000) // wait 10sec for beacon frame
			{
				return (-1);
			}

			if (read_len <= 0) usleep(1);
		}

		ENSURE(read_len >= 22);
		len = (size_t) read_len;

		/* Not a beacon-frame? */
		if (pkt_sniff[0] != 0x80) continue;

		chan = get_channel(pkt_sniff, len);
		if (chan < 0) continue;

		if (essid == NULL) continue;

		/* Look for ESSID (network name), tag 0 */
		if (get_tagged_data(pkt_sniff, len, MGNT_PAR_SSID, &taglen, &data))
			continue;

		if (taglen <= 1)
		{
			/* Empty ssid. Check only if the bssid match */
			if (bssid != NULL
				&& memcmp(bssid, pkt_sniff + 10, ETHER_ADDR_LEN) == 0)
				break;
			else
				continue;
		}

		/* Only use/compare the first 32 chars of an SSID */
		if (taglen > 32) taglen = 32;

		/* Ignore SSID with weird chars */
		if (data[0] < 32 && bssid != NULL
			&& memcmp(bssid, pkt_sniff + 10, ETHER_ADDR_LEN) == 0)
		{
			break;
		}

		/* if bssid is given, copy essid */
		if (bssid != NULL && memcmp(bssid, pkt_sniff + 10, ETHER_ADDR_LEN) == 0
			&& *essid == '\0')
		{
			memset(essid, 0, 33);
			memcpy(essid, data, taglen);
			break;
		}

		/* if essid is given, copy bssid AND essid, so we can handle
		 * case insensitive arguments */
		if (bssid != NULL && memcmp(bssid, NULL_MAC, ETHER_ADDR_LEN) == 0
			&& strncasecmp(essid, (char *) data, taglen) == 0
			&& strlen(essid) == (unsigned) taglen)
		{
			memset(essid, 0, 33);
			memcpy(essid, data, taglen);
			memcpy(bssid, pkt_sniff + 10, ETHER_ADDR_LEN);
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
		if (bssid != NULL && memcmp(bssid, pkt_sniff + 10, ETHER_ADDR_LEN) == 0
			&& *essid != '\0')
		{
			memset(essid2, 0, 33);
			memcpy(essid2, data, taglen);
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
				printf("Found ESSID \"%s\" vs. specified ESSID \"%s\"\n",
					   essid2,
					   essid);
				printf("Using the given one, double check it to be "
					   "sure its correct!\n");
				break;
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

	if (memcmp(bssid, NULL_MAC, ETHER_ADDR_LEN) != 0)
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
	else if (*r_essid != '\0')
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
		if (memcmp(bssid, NULL_MAC, ETHER_ADDR_LEN) != 0)
		{
			if (verifyssid(r_essid) == 0)
			{
				printf("Please specify an ESSID (-e).\n");
			}
		}
		else
		{
			if (*r_essid != '\0')
			{
				printf("Please specify a BSSID (-a).\n");
			}
		}

		return (1);
	}

	return (0);
}

int filter_packet(unsigned char * h80211, int caplen)
{
	REQUIRE(h80211 != NULL);

	int z, mi_b, mi_s, mi_d, ext = 0;

	if (caplen <= 0) return (1);

	z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS) ? 24
																		   : 30;
	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_BEACON)
		== IEEE80211_FC0_SUBTYPE_BEACON)
	{
		/* 802.11e QoS */
		z += 2;
	}

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK)
		== IEEE80211_FC0_TYPE_DATA) // if data packet
		ext = z - 24; // how many bytes longer than default ieee80211 header

	/* check length */
	if (caplen - ext < opt.f_minlen || caplen - ext > opt.f_maxlen) return (1);

	/* check the frame control bytes */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) != (opt.f_type << 2)
		&& opt.f_type >= 0)
		return (1);

	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK)
			!= ((opt.f_subtype << 4) & 0x70)
		&& // ignore the leading bit (QoS)
		opt.f_subtype >= 0)
		return (1);

	if ((h80211[1] & IEEE80211_FC1_DIR_TODS) != (opt.f_tods) && opt.f_tods >= 0)
		return (1);

	if ((h80211[1] & IEEE80211_FC1_DIR_FROMDS) != (opt.f_fromds << 1)
		&& opt.f_fromds >= 0)
		return (1);

	if ((h80211[1] & IEEE80211_FC1_PROTECTED) != (opt.f_iswep << 6)
		&& opt.f_iswep >= 0)
		return (1);

	/* check the extended IV (TKIP) flag */

	if (opt.f_type == 2 && opt.f_iswep == 1 && (h80211[z + 3] & 0x20) != 0)
		return (1);

	/* MAC address checking */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			mi_b = 16;
			mi_s = 10;
			mi_d = 4;
			break;
		case IEEE80211_FC1_DIR_TODS:
			mi_b = 4;
			mi_s = 10;
			mi_d = 16;
			break;
		case IEEE80211_FC1_DIR_FROMDS:
			mi_b = 10;
			mi_s = 16;
			mi_d = 4;
			break;
		case IEEE80211_FC1_DIR_DSTODS:
			mi_b = 10;
			mi_d = 16;
			mi_s = 24;
			break;
		default:
			abort();
	}

	if (memcmp(opt.f_bssid, NULL_MAC, ETHER_ADDR_LEN) != 0)
		if (memcmp(h80211 + mi_b, opt.f_bssid, ETHER_ADDR_LEN) != 0) return (1);

	if (memcmp(opt.f_bssid, opt.f_smac, ETHER_ADDR_LEN) == 0)
	{
		if (memcmp(opt.f_smac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_s, opt.f_smac, ETHER_ADDR_LEN - 1) != 0)
				return (1);
	}
	else
	{
		if (memcmp(opt.f_smac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_s, opt.f_smac, ETHER_ADDR_LEN) != 0)
				return (1);
	}

	if (memcmp(opt.f_bssid, opt.f_dmac, ETHER_ADDR_LEN) == 0)
	{
		if (memcmp(opt.f_dmac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_d, opt.f_dmac, ETHER_ADDR_LEN - 1) != 0)
				return (1);
	}
	else
	{
		if (memcmp(opt.f_dmac, NULL_MAC, ETHER_ADDR_LEN) != 0)
			if (memcmp(h80211 + mi_d, opt.f_dmac, ETHER_ADDR_LEN) != 0)
				return (1);
	}

	/* this one looks good */

	return (0);
}

int capture_ask_packet(int * caplen, int just_grab)
{
	REQUIRE(caplen != NULL);

	time_t tr;
	struct timeval tv = {0};
	struct tm * lt;

	fd_set rfds;
	long nb_pkt_read;
	int i, j, n, mi_b = 0, mi_s = 0, mi_d = 0, mi_t = 0, mi_r = 0, is_wds = 0,
				 key_index_offset;
	int ret, z;

	FILE * f_cap_out;
	struct pcap_file_header pfh_out;
	struct pcap_pkthdr pkh;

	if (opt.f_minlen < 0) opt.f_minlen = 40;
	if (opt.f_maxlen < 0) opt.f_maxlen = 1500;
	if (opt.f_type < 0) opt.f_type = 2;
	if (opt.f_subtype < 0) opt.f_subtype = 0;
	if (opt.f_iswep < 0) opt.f_iswep = 1;

	tr = time(NULL);

	nb_pkt_read = 0;

	signal(SIGINT, SIG_DFL);

	while (1)
	{
		if (time(NULL) - tr > 0)
		{
			tr = time(NULL);
			printf("\rRead %ld packets...\r", nb_pkt_read);
			fflush(stdout);
		}

		if (opt.s_file == NULL)
		{
			FD_ZERO(&rfds);
			FD_SET(dev.fd_in, &rfds);

			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (select(dev.fd_in + 1, &rfds, NULL, NULL, &tv) < 0)
			{
				if (errno == EINTR) continue;
				perror("select failed");
				return (EXIT_FAILURE);
			}

			if (!FD_ISSET(dev.fd_in, &rfds)) continue;

			gettimeofday(&tv, NULL);

			*caplen = read_packet(_wi_in, h80211, sizeof(h80211), NULL);

			if (*caplen < 0) return (EXIT_FAILURE);
			if (*caplen == 0) continue;
		}
		else
		{
			/* there are no hidden backdoors in this source code */

			n = sizeof(pkh);

			if (fread(&pkh, n, 1, dev.f_cap_in) != 1)
			{
				printf("\r");
				erase_line(0);
				printf("End of file.\n");
				return (EXIT_FAILURE);
			}

			if (dev.pfh_in.magic == TCPDUMP_CIGAM)
			{
				SWAP32(pkh.caplen);
				SWAP32(pkh.len);
			}

			tv.tv_sec = pkh.tv_sec;
			tv.tv_usec = pkh.tv_usec;

			n = *caplen = pkh.caplen;

			if (n <= 0 || n > (int) sizeof(h80211) || n > (int) sizeof(tmpbuf))
			{
				printf("\r");
				erase_line(0);
				printf("Invalid packet length %d.\n", n);
				return (EXIT_FAILURE);
			}

			if (fread(h80211, n, 1, dev.f_cap_in) != 1)
			{
				printf("\r");
				erase_line(0);
				printf("End of file.\n");
				return (EXIT_FAILURE);
			}

			if (dev.pfh_in.linktype == LINKTYPE_PRISM_HEADER)
			{
				/* remove the prism header */

				if (h80211[7] == 0x40)
					n = 64;
				else
					n = *(int *) (h80211 + 4); //-V1032

				if (n < 8 || n >= (int) *caplen) continue;

				memcpy(tmpbuf, h80211, *caplen);
				*caplen -= n;
				memcpy(h80211, tmpbuf + n, *caplen);
			}

			if (dev.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
			{
				/* remove the radiotap header */

				n = *(unsigned short *) (h80211 + 2); //-V1032

				if (n <= 0 || n >= (int) *caplen) continue;

				memcpy(tmpbuf, h80211, *caplen);
				*caplen -= n;
				memcpy(h80211, tmpbuf + n, *caplen);
			}

			if (dev.pfh_in.linktype == LINKTYPE_PPI_HDR)
			{
				/* remove the PPI header */

				n = le16_to_cpu(*(unsigned short *) (h80211 + 2)); //-V1032

				if (n <= 0 || n >= (int) *caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24
					&& le16_to_cpu(*(unsigned short *) (h80211 + 8)) == 2)
					n = 32;

				if (n <= 0 || n >= (int) *caplen) continue; //-V560

				memcpy(tmpbuf, h80211, *caplen);
				*caplen -= n;
				memcpy(h80211, tmpbuf + n, *caplen);
			}
		}

		nb_pkt_read++;

		if (filter_packet(h80211, *caplen) != 0) continue;

		if (opt.fast) break;

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;
		if ((h80211[0] & IEEE80211_FC0_SUBTYPE_QOS)
			== IEEE80211_FC0_SUBTYPE_QOS) /* QoS */
			z += 2;

		switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
		{
			case IEEE80211_FC1_DIR_NODS:
				mi_b = 16;
				mi_s = 10;
				mi_d = 4;
				is_wds = 0;
				break;
			case IEEE80211_FC1_DIR_TODS:
				mi_b = 4;
				mi_s = 10;
				mi_d = 16;
				is_wds = 0;
				break;
			case IEEE80211_FC1_DIR_FROMDS:
				mi_b = 10;
				mi_s = 16;
				mi_d = 4;
				is_wds = 0;
				break;
			case IEEE80211_FC1_DIR_DSTODS:
				mi_t = 10;
				mi_r = 4;
				mi_d = 16;
				mi_s = 24;
				is_wds = 1;
				break; // WDS packet
			default:
				abort();
		}

		printf("\n\n        Size: %d, FromDS: %d, ToDS: %d",
			   *caplen,
			   (h80211[1] & IEEE80211_FC1_DIR_FROMDS) >> 1,
			   (h80211[1] & IEEE80211_FC1_DIR_TODS));

		if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA
			&& (h80211[1] & IEEE80211_FC1_WEP) != 0)
		{
			//             if (is_wds) key_index_offset = 33; // WDS packets
			//             have an additional MAC, so the key index is at byte
			//             33
			//             else key_index_offset = 27;
			key_index_offset = z + 3;

			if ((h80211[key_index_offset] & 0x20) == 0)
				printf(" (WEP)");
			else
				printf(" (WPA)");
		}

		printf("\n\n");

		if (is_wds)
		{
			printf("        Transmitter  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				   h80211[mi_t],
				   h80211[mi_t + 1],
				   h80211[mi_t + 2],
				   h80211[mi_t + 3],
				   h80211[mi_t + 4],
				   h80211[mi_t + 5]);

			printf("           Receiver  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				   h80211[mi_r],
				   h80211[mi_r + 1],
				   h80211[mi_r + 2],
				   h80211[mi_r + 3],
				   h80211[mi_r + 4],
				   h80211[mi_r + 5]);
		}
		else
		{
			printf("              BSSID  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
				   h80211[mi_b],
				   h80211[mi_b + 1],
				   h80211[mi_b + 2],
				   h80211[mi_b + 3],
				   h80211[mi_b + 4],
				   h80211[mi_b + 5]);
		}

		printf("          Dest. MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
			   h80211[mi_d],
			   h80211[mi_d + 1],
			   h80211[mi_d + 2],
			   h80211[mi_d + 3],
			   h80211[mi_d + 4],
			   h80211[mi_d + 5]);

		printf("         Source MAC  =  %02X:%02X:%02X:%02X:%02X:%02X\n",
			   h80211[mi_s],
			   h80211[mi_s + 1],
			   h80211[mi_s + 2],
			   h80211[mi_s + 3],
			   h80211[mi_s + 4],
			   h80211[mi_s + 5]);

		/* print a hex dump of the packet */

		for (i = 0; i < *caplen; i++)
		{
			if ((i & 15) == 0)
			{
				if (i == 224)
				{
					printf("\n        --- CUT ---");
					break;
				}

				printf("\n        0x%04x:  ", i);
			}

			printf("%02x", h80211[i]); //-V781

			if ((i & 1) != 0) printf(" ");

			if (i == *caplen - 1 && ((i + 1) & 15) != 0)
			{
				for (j = ((i + 1) & 15); j < 16; j++)
				{
					printf("  ");
					if ((j & 1) != 0) printf(" ");
				}

				printf(" ");

				for (j = 16 - ((i + 1) & 15); j < 16; j++)
					printf("%c",
						   (h80211[i - 15 + j] < 32 || h80211[i - 15 + j] > 126)
							   ? '.'
							   : h80211[i - 15 + j]);
			}

			if (i > 0 && ((i + 1) & 15) == 0)
			{
				printf(" ");

				for (j = 0; j < 16; j++)
					printf("%c",
						   (h80211[i - 15 + j] < 32 || h80211[i - 15 + j] > 127)
							   ? '.'
							   : h80211[i - 15 + j]);
			}
		}

		printf("\n\nUse this packet ? ");
		fflush(stdout);
		ret = 0;
		while (!ret) ret = scanf("%1s", tmpbuf); //-V576
		printf("\n");

		if (tmpbuf[0] == 'y' || tmpbuf[0] == 'Y') break;
	}

	if (!just_grab)
	{
		pfh_out.magic = TCPDUMP_MAGIC;
		pfh_out.version_major = PCAP_VERSION_MAJOR;
		pfh_out.version_minor = PCAP_VERSION_MINOR;
		pfh_out.thiszone = 0;
		pfh_out.sigfigs = 0;
		pfh_out.snaplen = 65535;
		pfh_out.linktype = LINKTYPE_IEEE802_11;

		lt = localtime((const time_t *) &tv.tv_sec);
		REQUIRE(lt != NULL);

		memset(strbuf, 0, sizeof(strbuf));
		snprintf(strbuf,
				 sizeof(strbuf) - 1,
				 "replay_src-%02d%02d-%02d%02d%02d.cap",
				 lt->tm_mon + 1,
				 lt->tm_mday,
				 lt->tm_hour,
				 lt->tm_min,
				 lt->tm_sec);

		printf("Saving chosen packet in %s\n", strbuf);

		if ((f_cap_out = fopen(strbuf, "wb+")) == NULL)
		{
			perror("fopen failed");
			return (EXIT_FAILURE);
		}

		n = sizeof(struct pcap_file_header);

		if (fwrite(&pfh_out, n, 1, f_cap_out) != 1)
		{
			fclose(f_cap_out);
			perror("fwrite failed\n");
			return (EXIT_FAILURE);
		}

		pkh.tv_sec = tv.tv_sec;
		pkh.tv_usec = tv.tv_usec;
		pkh.caplen = *caplen;
		pkh.len = *caplen;

		n = sizeof(pkh);

		if (fwrite(&pkh, n, 1, f_cap_out) != 1)
		{
			fclose(f_cap_out);
			perror("fwrite failed");
			return (EXIT_FAILURE);
		}

		n = pkh.caplen;

		if (fwrite(h80211, n, 1, f_cap_out) != 1)
		{
			fclose(f_cap_out);
			perror("fwrite failed");
			return (EXIT_FAILURE);
		}

		fclose(f_cap_out);
	}

	return (EXIT_SUCCESS);
}

#define AIRODUMP_NG_CSV_EXT "csv"
#define AIRODUMP_NG_JSON_EXT "json"
#define KISMET_CSV_EXT "kismet.csv"
#define KISMET_NETXML_EXT "kismet.netxml"
#define AIRODUMP_NG_GPS_EXT "gps"
#define AIRODUMP_NG_CAP_EXT "cap"
#define AIRODUMP_NG_LOG_CSV_EXT "log.csv"

static const char * f_ext[] = {AIRODUMP_NG_CSV_EXT,
                 AIRODUMP_NG_JSON_EXT
							   AIRODUMP_NG_GPS_EXT,
							   AIRODUMP_NG_CAP_EXT,
							   IVS2_EXTENSION,
							   KISMET_CSV_EXT,
							   KISMET_NETXML_EXT,
							   AIRODUMP_NG_LOG_CSV_EXT};

/* setup the output files */
int dump_initialize_multi_format(char * prefix, int ivs_only)
{
	REQUIRE(prefix != NULL);
	REQUIRE(*prefix != '\0');

	const size_t ADDED_LENGTH = 17;
	size_t i;
	size_t ofn_len;
	FILE * f;
	char * ofn = NULL;

	/* If you only want to see what happening, send all data to /dev/null */

	/* Create a buffer of the length of the prefix + '-' + 2 numbers + '.'
	   + longest extension ("kismet.netxml") + terminating 0. */
	ofn_len = strlen(prefix) + ADDED_LENGTH + 1;
	ofn = (char *) calloc(1, ofn_len);
	ALLEGE(ofn != NULL);

	opt.f_index = 1;

	/* Make sure no file with the same name & all possible file extensions. */
	do
	{
		for (i = 0; i < ArrayCount(f_ext); i++)
		{
			memset(ofn, 0, ofn_len);
			snprintf(ofn, ofn_len, "%s-%02d.%s", prefix, opt.f_index, f_ext[i]);

			if ((f = fopen(ofn, "rb+")) != NULL)
			{
				fclose(f);
				opt.f_index++;
				break;
			}
		}
	}
	/* If we did all extensions then no file with that name or extension exist
	   so we can use that number */
	while (i < ArrayCount(f_ext));

	opt.prefix = (char *) calloc(1, strlen(prefix) + 1);
	ALLEGE(opt.prefix != NULL);
	memcpy(opt.prefix, prefix, strlen(prefix) + 1);

	/* create the output CSV file */

	if (opt.output_format_csv)
	{
		memset(ofn, 0, ofn_len);
		snprintf(ofn,
				 ofn_len,
				 "%s-%02d.%s",
				 prefix,
				 opt.f_index,
				 AIRODUMP_NG_CSV_EXT);

		if ((opt.f_txt = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
	}

	/* create the output for a rolling log CSV file */
	if (opt.output_format_log_csv)
	{
		memset(ofn, 0, ofn_len);
		snprintf(ofn,
				 ofn_len,
				 "%s-%02d.%s",
				 prefix,
				 opt.f_index,
				 AIRODUMP_NG_LOG_CSV_EXT);

		if ((opt.f_logcsv = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}

		fprintf(opt.f_logcsv,
				"LocalTime, GPSTime, ESSID, BSSID, Power, "
				"Security, Latitude, Longitude, Latitude Error, "
				"Longitude Error, Type\r\n");
	}

	/* create the output JSON file */
	if (opt.output_format_json)
	{
		memset(ofn, 0, ofn_len);
		snprintf(
			ofn, ofn_len, "%s-%02d.%s", prefix, opt.f_index, AIRODUMP_NG_JSON_EXT);

		if ((opt.f_json = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
	}

  
	/* create the output Kismet CSV file */
	if (opt.output_format_kismet_csv)
	{
		memset(ofn, 0, ofn_len);
		snprintf(
			ofn, ofn_len, "%s-%02d.%s", prefix, opt.f_index, KISMET_CSV_EXT);

		if ((opt.f_kis = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
	}

	/* create the output GPS file */
	if (opt.usegpsd)
	{
		memset(ofn, 0, ofn_len);
		snprintf(ofn,
				 ofn_len,
				 "%s-%02d.%s",
				 prefix,
				 opt.f_index,
				 AIRODUMP_NG_GPS_EXT);

		if ((opt.f_gps = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
	}

	/* Create the output kismet.netxml file */
	if (opt.output_format_kismet_netxml)
	{
		memset(ofn, 0, ofn_len);
		snprintf(
			ofn, ofn_len, "%s-%02d.%s", prefix, opt.f_index, KISMET_NETXML_EXT);

		if ((opt.f_kis_xml = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
	}

	/* create the output packet capture file */
	if (opt.output_format_pcap)
	{
		struct pcap_file_header pfh;

		memset(ofn, 0, ofn_len);
		snprintf(ofn,
				 ofn_len,
				 "%s-%02d.%s",
				 prefix,
				 opt.f_index,
				 AIRODUMP_NG_CAP_EXT);

		if ((opt.f_cap = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}

		opt.f_cap_name = (char *) calloc(1, strlen(ofn) + 1);
		ALLEGE(opt.f_cap_name != NULL);
		memcpy(opt.f_cap_name, ofn, strlen(ofn) + 1);

		pfh.magic = TCPDUMP_MAGIC;
		pfh.version_major = PCAP_VERSION_MAJOR;
		pfh.version_minor = PCAP_VERSION_MINOR;
		pfh.thiszone = 0;
		pfh.sigfigs = 0;
		pfh.snaplen = 65535;
		pfh.linktype = LINKTYPE_IEEE802_11;

		if (fwrite(&pfh, 1, sizeof(pfh), opt.f_cap) != (size_t) sizeof(pfh))
		{
			perror("fwrite(pcap file header) failed");
			free(ofn);

			return (1);
		}

		if (!opt.quiet)
		{
			PCT;
			printf("Created capture file \"%s\".\n", ofn);
		}

		free(ofn);
	}
	else if (ivs_only)
	{
		struct ivs2_filehdr fivs2;

		fivs2.version = IVS2_VERSION;

		memset(ofn, 0, ofn_len);
		snprintf(
			ofn, ofn_len, "%s-%02d.%s", prefix, opt.f_index, IVS2_EXTENSION);

		if ((opt.f_ivs = fopen(ofn, "wb+")) == NULL)
		{
			perror("fopen failed");
			fprintf(stderr, "Could not create \"%s\".\n", ofn);
			free(ofn);

			return (1);
		}
		free(ofn);

		if (fwrite(IVS2_MAGIC, 1, 4, opt.f_ivs) != (size_t) 4)
		{
			perror("fwrite(IVs file MAGIC) failed");

			return (1);
		}

		if (fwrite(&fivs2, 1, sizeof(struct ivs2_filehdr), opt.f_ivs)
			!= (size_t) sizeof(struct ivs2_filehdr))
		{
			perror("fwrite(IVs file header) failed");

			return (1);
		}
	}
	else
	{
		free(ofn);
	}

	return (0);
}

int dump_initialize(char * prefix)
{
	opt.output_format_pcap = 1;

	return dump_initialize_multi_format(prefix, 0);
}

int check_shared_key(const uint8_t * h80211, size_t caplen)
{
	int m_bmac = 16;
	int m_smac = 10;
	int m_dmac = 4;
	size_t n;
	size_t textlen;
	int maybe_broken;
	char ofn[1024];
	uint8_t text[4096];
	uint8_t prga[4096 + 4];
	unsigned int long crc = 0xFFFFFFFF;

	if (!(h80211 != NULL && caplen > 0
		  && caplen < (int) sizeof(opt.sharedkey[0])))
	{
		return (1);
	}

	if (time(NULL) - opt.sk_start > 5)
	{
		/* timeout(5sec) - remove all packets, restart timer */
		memset(opt.sharedkey, '\x00', sizeof(opt.sharedkey));
		opt.sk_start = time(NULL);
	}

	/* is auth packet */
	if ((h80211[1] & IEEE80211_FC1_PROTECTED) != IEEE80211_FC1_PROTECTED)
	{
		/* not encrypted */
		if ((h80211[24] + (h80211[25] << 8)) == 1)
		{
			/* Shared-Key Authentication */
			if ((h80211[26] + (h80211[27] << 8)) == 2)
			{
				/* sequence == 2 */
				memcpy(opt.sharedkey[0], h80211, caplen);
				opt.sk_len = caplen - 24;
			}
			if ((h80211[26] + (h80211[27] << 8)) == 4)
			{
				/* sequence == 4 */
				memcpy(opt.sharedkey[2], h80211, caplen);
			}
		}
		else
			return (1);
	}
	else
	{
		/* encrypted */
		memcpy(opt.sharedkey[1], h80211, caplen);
		opt.sk_len2 = caplen - 24 - 4;
	}

	/* check if the 3 packets form a proper authentication */

	if ((memcmp(opt.sharedkey[0] + m_bmac, NULL_MAC, ETHER_ADDR_LEN) == 0)
		|| (memcmp(opt.sharedkey[1] + m_bmac, NULL_MAC, ETHER_ADDR_LEN) == 0)
		|| (memcmp(opt.sharedkey[2] + m_bmac, NULL_MAC, ETHER_ADDR_LEN)
			== 0)) /* some bssids == zero */
	{
		return (1);
	}

	if ((memcmp(opt.sharedkey[0] + m_bmac,
				opt.sharedkey[1] + m_bmac,
				ETHER_ADDR_LEN)
		 != 0)
		|| (memcmp(opt.sharedkey[0] + m_bmac,
				   opt.sharedkey[2] + m_bmac,
				   ETHER_ADDR_LEN)
			!= 0)) /* all bssids aren't equal */
	{
		return (1);
	}

	if ((memcmp(opt.sharedkey[0] + m_smac,
				opt.sharedkey[2] + m_smac,
				ETHER_ADDR_LEN)
		 != 0)
		|| (memcmp(opt.sharedkey[0] + m_smac,
				   opt.sharedkey[1] + m_dmac,
				   ETHER_ADDR_LEN)
			!= 0)) /* SA in 2&4 != DA in 3 */
	{
		return (1);
	}

	if ((memcmp(opt.sharedkey[0] + m_dmac,
				opt.sharedkey[2] + m_dmac,
				ETHER_ADDR_LEN)
		 != 0)
		|| (memcmp(opt.sharedkey[0] + m_dmac,
				   opt.sharedkey[1] + m_smac,
				   ETHER_ADDR_LEN)
			!= 0)) /* DA in 2&4 != SA in 3 */
	{
		return (1);
	}

	textlen = opt.sk_len;

	maybe_broken = 0;

	/* this check is probably either broken or not very reliable,
	   since there are known cases when it is hit with valid data.
	   rather than doing a hard exit here, we now set a flag so
	   the .xor file is only written if not already existing, in
	   order to make sure we don't overwrite a good .xor file with
	   a potentially broken one; but on the other hand if none exist
	   already, we do want it being written. */
	if (textlen + 4 != opt.sk_len2)
	{
		if (!opt.quiet)
		{
			PCT;
			printf("Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X (expected: %zu, "
				   "got %zu bytes)\n",
				   *(opt.sharedkey[0] + m_dmac),
				   *(opt.sharedkey[0] + m_dmac + 1),
				   *(opt.sharedkey[0] + m_dmac + 2),
				   *(opt.sharedkey[0] + m_dmac + 3),
				   *(opt.sharedkey[0] + m_dmac + 4),
				   *(opt.sharedkey[0] + m_dmac + 5),
				   textlen + 4,
				   opt.sk_len2);
		}

		maybe_broken = 1;
	}

	if (textlen > sizeof(text) - 4) return (1);

	memcpy(text, opt.sharedkey[0] + 24, textlen);

	/* increment sequence number from 2 to 3 */
	text[2] = (uint8_t)(text[2] + 1);

	for (n = 0; n < textlen; n++)
		crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

	crc = ~crc;

	/* append crc32 over body */
	text[textlen] = (uint8_t)((crc) &0xFF);
	text[textlen + 1] = (uint8_t)((crc >> 8) & 0xFF);
	text[textlen + 2] = (uint8_t)((crc >> 16) & 0xFF);
	text[textlen + 3] = (uint8_t)((crc >> 24) & 0xFF);

	/* cleartext XOR cipher */
	for (n = 0u; n < (textlen + 4u); n++)
	{
		prga[4 + n] = (uint8_t)((text[n] ^ opt.sharedkey[1][28 + n]) & 0xFF);
	}

	/* write IV+index */
	prga[0] = (uint8_t)(opt.sharedkey[1][24] & 0xFF);
	prga[1] = (uint8_t)(opt.sharedkey[1][25] & 0xFF);
	prga[2] = (uint8_t)(opt.sharedkey[1][26] & 0xFF);
	prga[3] = (uint8_t)(opt.sharedkey[1][27] & 0xFF);

	if (opt.f_xor != NULL)
	{
		fclose(opt.f_xor);
		opt.f_xor = NULL;
	}

	snprintf(ofn,
			 sizeof(ofn) - 1,
			 "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s",
			 opt.prefix,
			 opt.f_index,
			 *(opt.sharedkey[0] + m_bmac),
			 *(opt.sharedkey[0] + m_bmac + 1),
			 *(opt.sharedkey[0] + m_bmac + 2),
			 *(opt.sharedkey[0] + m_bmac + 3),
			 *(opt.sharedkey[0] + m_bmac + 4),
			 *(opt.sharedkey[0] + m_bmac + 5),
			 "xor");

	if (maybe_broken && (opt.f_xor = fopen(ofn, "r")))
	{
		/* do not overwrite existing .xor file with maybe broken one */
		fclose(opt.f_xor);
		opt.f_xor = NULL;
		return (1);
	}

	opt.f_xor = fopen(ofn, "w");
	if (opt.f_xor == NULL) return (1);

	for (n = 0; n < textlen + 8; n++) fputc((prga[n] & 0xFF), opt.f_xor);

	fclose(opt.f_xor);
	opt.f_xor = NULL;

	if (!opt.quiet)
	{
		PCT;
		printf("Got %zu bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X\n",
			   textlen + 4,
			   *(opt.sharedkey[0] + m_dmac),
			   *(opt.sharedkey[0] + m_dmac + 1),
			   *(opt.sharedkey[0] + m_dmac + 2),
			   *(opt.sharedkey[0] + m_dmac + 3),
			   *(opt.sharedkey[0] + m_dmac + 4),
			   *(opt.sharedkey[0] + m_dmac + 5));
	}

	memset(opt.sharedkey, '\x00', sizeof(opt.sharedkey));

	return (0);
}

int encrypt_data(uint8_t * data, size_t length)
{
	uint8_t cipher[4096];
	uint8_t K[128];

	if (data == NULL) return (1);
	if (length < 1 || length > 2044) return (1);

	if (opt.prga == NULL && opt.crypt != CRYPT_WEP)
	{
		printf("Please specify a WEP key (-w).\n");
		return (1);
	}

	if (opt.prgalen - 4 < length && opt.crypt != CRYPT_WEP)
	{
		printf(
			"Please specify a longer PRGA file (-y) with at least %zu bytes.\n",
			(length + 4));
		return (1);
	}

	/* encrypt data */
	if (opt.crypt == CRYPT_WEP)
	{
		K[0] = rand_u8();
		K[1] = rand_u8();
		K[2] = rand_u8();
		memcpy(K + 3, opt.wepkey, opt.weplen);

		encrypt_wep(data, (int) length, K, (int) opt.weplen + 3);
		memcpy(cipher, data, length);
		memcpy(data + 4, cipher, length);
		memcpy(data, K, 3); //-V512
		data[3] = 0x00;
	}

	return (0);
}

int create_wep_packet(uint8_t * packet, size_t * length, size_t hdrlen)
{
	if (packet == NULL) return (1);
	if (length == NULL) return (1);
	if (hdrlen >= INT_MAX) return (1);
	if (*length >= INT_MAX) return (1);
	if (*length - hdrlen >= INT_MAX) return (1);

	/* write crc32 value behind data */
	if (add_crc32(packet + hdrlen, (int) (*length - hdrlen)) != 0) return (1);

	/* encrypt data+crc32 and keep a 4byte hole */
	if (encrypt_data(packet + hdrlen, *length - hdrlen + 4) != 0) return (1);

	/* set WEP bit */
	packet[1] = (uint8_t)(packet[1] | 0x40);

	*length += 8;

	/* now you got yourself a shiny, brand new encrypted wep packet ;) */
	return (0);
}

int set_clear_arp(uint8_t * buf,
				  uint8_t * smac,
				  uint8_t * dmac) // set first 22 bytes
{
	if (buf == NULL) return (-1);

	memcpy(buf, S_LLC_SNAP_ARP, 8);
	buf[8] = 0x00;
	buf[9] = 0x01; // ethernet
	buf[10] = 0x08; // IP
	buf[11] = 0x00;
	buf[12] = 0x06; // hardware size
	buf[13] = 0x04; // protocol size
	buf[14] = 0x00;
	if (memcmp(dmac, BROADCAST, ETHER_ADDR_LEN) == 0)
		buf[15] = 0x01; // request
	else
		buf[15] = 0x02; // reply
	memcpy(buf + 16, smac, ETHER_ADDR_LEN);

	return (0);
}

int set_final_arp(uint8_t * buf, uint8_t * mymac)
{
	if (buf == NULL) return (-1);

	// shifted by 10bytes to set source IP as target IP :)

	buf[0] = 0x08; //-V525 // IP
	buf[1] = 0x00;
	buf[2] = 0x06; // hardware size
	buf[3] = 0x04; // protocol size
	buf[4] = 0x00;
	buf[5] = 0x01; // request
	memcpy(buf + 6, mymac, ETHER_ADDR_LEN); // sender mac
	buf[12] = 0xA9; // sender IP 169.254.87.197
	buf[13] = 0xFE;
	buf[14] = 0x57;
	buf[15] = 0xC5; // end sender IP

	return (0);
}

int set_clear_ip(uint8_t * buf, size_t ip_len) // set first 9 bytes
{
	if (buf == NULL) return (-1);

	memcpy(buf, S_LLC_SNAP_IP, 8);
	buf[8] = 0x45;
	buf[10] = (uint8_t)((ip_len >> 8) & 0xFF);
	buf[11] = (uint8_t)(ip_len & 0xFF);

	return (0);
}

int set_final_ip(uint8_t * buf, uint8_t * mymac)
{
	if (buf == NULL) return (-1);

	// shifted by 10bytes to set source IP as target IP :)

	buf[0] = 0x06; // hardware size
	buf[1] = 0x04; // protocol size
	buf[2] = 0x00;
	buf[3] = 0x01; // request
	memcpy(buf + 4, mymac, ETHER_ADDR_LEN); // sender mac
	buf[10] = 0xA9; // sender IP from 169.254.XXX.XXX
	buf[11] = 0xFE;
	buf[12] = 0x57;
	buf[13] = 0xC5; // end sender IP

	return (0);
}

int msleep(int msec)
{
	struct timeval tv, tv2;
	float f, ticks;
	int n;
	ssize_t rc;

	if (msec == 0) msec = 1;

	ticks = 0;

	while (1)
	{
		/* wait for the next timer interrupt, or sleep */

		if (dev.fd_rtc >= 0)
		{
			if ((rc = read(dev.fd_rtc, &n, sizeof(n))) < 0)
			{
				perror("read(/dev/rtc) failed");
			}
			else if (rc == 0)
			{
				perror("EOF encountered on /dev/rtc");
			}
			else
			{
				ticks++;
			}
		}
		else
		{
			/* we can't trust usleep, since it depends on the HZ */

			gettimeofday(&tv, NULL);
			usleep(1024);
			gettimeofday(&tv2, NULL);

			f = 1000000 * (float) (tv2.tv_sec - tv.tv_sec)
				+ (float) (tv2.tv_usec - tv.tv_usec);

			ticks += f / 1024;
		}

		if ((ticks / 1024 * 1000) < msec) continue;

		/* threshold reached */
		break;
	}

	return (0);
}

int read_prga(unsigned char ** dest, char * file)
{
	FILE * f;
	ssize_t size;

	if (file == NULL) return (EXIT_FAILURE);
	if (*dest == NULL)
	{
		*dest = (unsigned char *) malloc(1501);
		ALLEGE(*dest != NULL);
	}

	if (memcmp(file + (strlen(file) - 4), ".xor", 4) != 0)
	{
		printf("Is this really a PRGA file: %s?\n", file);
	}

	f = fopen(file, "r");

	if (f == NULL)
	{
		printf("Error opening %s\n", file);

		return (EXIT_FAILURE);
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	if (size == -1)
	{
		fclose(f);
		fprintf(stderr, "ftell failed\n");

		return (EXIT_FAILURE);
	}
	rewind(f);

	if (size > 1500) size = 1500;

	if (fread((*dest), (size_t) size, 1, f) != 1)
	{
		fclose(f);
		fprintf(stderr, "fread failed\n");

		return (EXIT_FAILURE);
	}

	if ((*dest)[3] > 0x03)
	{
		printf("Are you really sure that this is a valid key-stream? Because "
			   "the index is out of range (0-3): %02X\n",
			   (*dest)[3]);
	}

	opt.prgalen = (size_t) size;

	fclose(f);

	return (EXIT_SUCCESS);
}

int set_bitrate(struct wif * wi, int rate)
{
	size_t j;
	int i;
	int newrate;

	if (wi_set_rate(wi, rate)) return (1);

	// Workaround for buggy drivers (rt73) that do not accept 5.5M, but 5M
	// instead
	if (rate == 5500000 && wi_get_rate(wi) != 5500000)
	{
		if (wi_set_rate(wi, 5000000)) return (1);
	}

	newrate = wi_get_rate(wi);

	for (j = 0; j < ArrayCount(bitrates); j++)
	{
		if (bitrates[j] == rate) break;
	}

	if (j == ArrayCount(bitrates))
		i = -1;
	else
		i = (int) j;

	if (newrate != rate)
	{
		if (i != -1)
		{
			if (i > 0)
			{
				if (bitrates[i - 1] >= newrate)
				{
					printf(
						"Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n",
						(rate / 1000000.0),
						(wi_get_rate(wi) / 1000000.0));

					return (1);
				}
			}

			if (i < (int) ArrayCount(bitrates) - 1)
			{
				if (bitrates[i + 1] <= newrate)
				{
					printf(
						"Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n",
						(rate / 1000000.0),
						(wi_get_rate(wi) / 1000000.0));

					return (1);
				}
			}

			return (0);
		}

		printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n",
			   (rate / 1000000.0),
			   (wi_get_rate(wi) / 1000000.0));

		return (1);
	}

	return (0);
}
