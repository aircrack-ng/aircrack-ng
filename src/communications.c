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
#include <sys/signal.h>
#include <sys/time.h>

#include "defs.h"
#include "communications.h"
#include "crypto.h"
#include "pcap.h"
#include "aircrack-util/console.h"
#include "aircrack-util/verifyssid.h"

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

int filter_packet(unsigned char * h80211, int caplen)
{
	REQUIRE(h80211 != NULL);

	int z, mi_b, mi_s, mi_d, ext = 0, qos;

	if (caplen <= 0) return (1);

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if ((h80211[0] & 0x80) == 0x80)
	{
		qos = 1; /* 802.11e QoS */
		z += 2;
	}

	if ((h80211[0] & 0x0C) == 0x08) // if data packet
		ext = z - 24; // how many bytes longer than default ieee80211 header

	/* check length */
	if (caplen - ext < opt.f_minlen || caplen - ext > opt.f_maxlen) return (1);

	/* check the frame control bytes */

	if ((h80211[0] & 0x0C) != (opt.f_type << 2) && opt.f_type >= 0) return (1);

	if ((h80211[0] & 0x70) != ((opt.f_subtype << 4) & 0x70)
		&& // ignore the leading bit (QoS)
		opt.f_subtype >= 0)
		return (1);

	if ((h80211[1] & 0x01) != (opt.f_tods) && opt.f_tods >= 0) return (1);

	if ((h80211[1] & 0x02) != (opt.f_fromds << 1) && opt.f_fromds >= 0)
		return (1);

	if ((h80211[1] & 0x40) != (opt.f_iswep << 6) && opt.f_iswep >= 0)
		return (1);

	/* check the extended IV (TKIP) flag */

	if (opt.f_type == 2 && opt.f_iswep == 1 && (h80211[z + 3] & 0x20) != 0)
		return (1);

	/* MAC address checking */

	switch (h80211[1] & 3)
	{
		case 0:
			mi_b = 16;
			mi_s = 10;
			mi_d = 4;
			break;
		case 1:
			mi_b = 4;
			mi_s = 10;
			mi_d = 16;
			break;
		case 2:
			mi_b = 10;
			mi_s = 16;
			mi_d = 4;
			break;
		default:
			mi_b = 10;
			mi_d = 16;
			mi_s = 24;
			break;
	}

	if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
		if (memcmp(h80211 + mi_b, opt.f_bssid, 6) != 0) return (1);

	if (memcmp(opt.f_bssid, opt.f_smac, 6) == 0)
	{
		if (memcmp(opt.f_smac, NULL_MAC, 6) != 0)
			if (memcmp(h80211 + mi_s, opt.f_smac, 5) != 0) return (1);
	}
	else
	{
		if (memcmp(opt.f_smac, NULL_MAC, 6) != 0)
			if (memcmp(h80211 + mi_s, opt.f_smac, 6) != 0) return (1);
	}

	if (memcmp(opt.f_bssid, opt.f_dmac, 6) == 0)
	{
		if (memcmp(opt.f_dmac, NULL_MAC, 6) != 0)
			if (memcmp(h80211 + mi_d, opt.f_dmac, 5) != 0) return (1);
	}
	else
	{
		if (memcmp(opt.f_dmac, NULL_MAC, 6) != 0)
			if (memcmp(h80211 + mi_d, opt.f_dmac, 6) != 0) return (1);
	}

	/* this one looks good */

	return (0);
}

int capture_ask_packet(int * caplen, int just_grab)
{
	REQUIRE(caplen != NULL);

	time_t tr;
	struct timeval tv;
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

		z = ((h80211[1] & 3) != 3) ? 24 : 30;
		if ((h80211[0] & 0x80) == 0x80) /* QoS */
			z += 2;

		switch (h80211[1] & 3)
		{
			case 0:
				mi_b = 16;
				mi_s = 10;
				mi_d = 4;
				is_wds = 0;
				break;
			case 1:
				mi_b = 4;
				mi_s = 10;
				mi_d = 16;
				is_wds = 0;
				break;
			case 2:
				mi_b = 10;
				mi_s = 16;
				mi_d = 4;
				is_wds = 0;
				break;
			case 3:
				mi_t = 10;
				mi_r = 4;
				mi_d = 16;
				mi_s = 24;
				is_wds = 1;
				break; // WDS packet
		}

		printf("\n\n        Size: %d, FromDS: %d, ToDS: %d",
			   *caplen,
			   (h80211[1] & 2) >> 1,
			   (h80211[1] & 1));

		if ((h80211[0] & 0x0C) == 8 && (h80211[1] & 0x40) != 0)
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
