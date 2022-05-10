/*
 *  802.11 WEP network connection tunneling
 *  based on aireplay-ng
 *
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#ifdef linux
#include <linux/rtc.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include <fcntl.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/support/fragments.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/common.h"

#include "aircrack-ng/osdep/osdep.h"

static const char usage[]
	= "\n"
	  "  %s - (C) 2006-2022 Thomas d'Otreppe\n"
	  "  Original work: Martin Beck\n"
	  "  https://www.aircrack-ng.org\n"
	  "\n"
	  "  usage: airtun-ng <options> <replay interface>\n"
	  "\n"
	  "      -x nbpps         : number of packets per second (default: 100)\n"
	  "      -a bssid         : set Access Point MAC address\n"
	  "                         In WDS Mode this sets the Receiver\n"
	  "      -i iface         : capture packets from this interface\n"
	  "      -y file          : read PRGA from this file\n"
	  "      -w wepkey        : use this WEP-KEY to encrypt packets\n"
	  "      -p pass          : use this WPA passphrase to decrypt packets\n"
	  "                         (use with -a and -e)\n"
	  "      -e essid         : target network SSID (use with -p)\n"
	  "      -t tods          : send frames to AP (1) or to client (0)\n"
	  "                         or tunnel them into a WDS/Bridge (2)\n"
	  "      -r file          : read frames out of pcap file\n"
	  "      -h MAC           : source MAC address\n"
	  "\n"
	  "  WDS/Bridge Mode options:\n"
	  "      -s transmitter   : set Transmitter MAC address for WDS Mode\n"
	  "      -b               : bidirectional mode. This enables "
	  "communication\n"
	  "                         in Transmitter's AND Receiver's networks.\n"
	  "                         Works only if you can see both stations.\n"
	  "\n"
	  "  Repeater options:\n"
	  "      --repeat         : activates repeat mode\n"
	  "      --bssid <mac>    : BSSID to repeat\n"
	  "      --netmask <mask> : netmask for BSSID filter\n"
	  "\n"
	  "      --help           : Displays this usage screen\n"
	  "\n";

struct communication_options opt;
static struct local_options
{
	int tods;
	int bidir;
	char essid[36];
	char passphrase[65];
	unsigned char pmk[40];
	unsigned char wepkey[64];
	int weplen;
	int repeat;
} lopt;

struct devices dev;
extern struct wif *_wi_in, *_wi_out;
extern uint8_t h80211[4096];
extern uint8_t tmpbuf[4096];

struct ARP_req
{
	unsigned char * buf;
	int len;
};

struct net_entry
{
	unsigned char * addr;
	unsigned char net;
	struct net_entry * next;
};

unsigned long nb_pkt_sent;
static struct net_entry * nets = NULL;
static struct WPA_ST_info * st_1st = NULL;

pFrag_t rFragment;

static struct net_entry * find_entry(unsigned char * adress)
{
	struct net_entry * cur = nets;

	if (cur == NULL) return (NULL);

	do
	{
		if (!memcmp(cur->addr, adress, 6))
		{
			return (cur);
		}
		cur = cur->next;
	} while (cur != nets);

	return (NULL);
}

static void set_entry(unsigned char * adress, unsigned char network)
{
	struct net_entry * cur;

	if (nets == NULL)
	{
		nets = malloc(sizeof(struct net_entry));
		ALLEGE(nets != NULL);
		nets->addr = malloc(6 * sizeof(unsigned char));
		ALLEGE(nets->addr != NULL);
		nets->next = nets;
		cur = nets;
	}
	else
	{
		cur = find_entry(adress);
		if (cur == NULL)
		{
			cur = malloc(sizeof(struct net_entry));
			ALLEGE(cur != NULL);
			cur->addr = malloc(6 * sizeof(unsigned char));
			ALLEGE(cur->addr != NULL);
			cur->next = nets->next;
			nets->next = cur;
		}
	}

	memcpy(cur->addr, adress, 6);
	cur->net = network;
}

static int get_entry(unsigned char * adress)
{
	struct net_entry * cur = find_entry(adress);

	if (cur == NULL)
	{
		return (-1);
	}
	else
	{
		return (cur->net);
	}
}

static void swap_ra_ta(unsigned char * h80211)
{
	REQUIRE(h80211 != NULL);

	unsigned char mbuf[6];

	memcpy(mbuf, h80211 + 4, 6);
	memcpy(h80211 + 4, h80211 + 10, 6);
	memcpy(h80211 + 10, mbuf, 6);
}

static int is_filtered_netmask(unsigned char * bssid)
{
	REQUIRE(bssid != NULL);

	unsigned char mac1[6];
	unsigned char mac2[6];
	int i;

	for (i = 0; i < 6; i++)
	{
		mac1[i] = bssid[i] & opt.f_netmask[i];
		mac2[i] = opt.f_bssid[i] & opt.f_netmask[i];
	}

	if (memcmp(mac1, mac2, 6) != 0)
	{
		return (1);
	}

	return (0);
}

#define IEEE80211_LLC_SNAP                                                     \
	"\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"         \
	"\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"

static int set_IVidx(unsigned char * packet, int data_begin)
{
	if (packet == NULL) return (1);

	if (opt.prga == NULL)
	{
		printf("Please specify a PRGA file (-y).\n");
		return (1);
	}

	/* insert IV+index */
	memcpy(packet + data_begin, opt.prga, 4);

	return (0);
}

static int
my_encrypt_data(unsigned char * dest, unsigned char * data, int length)
{
	unsigned char cipher[2048];
	int n;

	if (dest == NULL) return (1);
	if (data == NULL) return (1);
	if (length < 1 || length > 2044) return (1);

	if (opt.prga == NULL)
	{
		printf("Please specify a PRGA file (-y).\n");
		return (1);
	}

	if (opt.prgalen - 4 < (size_t) length)
	{
		printf(
			"Please specify a longer PRGA file (-y) with at least %i bytes.\n",
			(length + 4));
		return (1);
	}

	/* encrypt data */
	for (n = 0; n < length; n++)
	{
		cipher[n] = (data[n] ^ opt.prga[4 + n]) & 0xFF;
	}

	memcpy(dest, cipher, length);

	return (0);
}

static int
my_create_wep_packet(unsigned char * packet, int * length, int data_begin)
{
	if (packet == NULL) return (1);

	/* write crc32 value behind data */
	if (add_crc32(packet + data_begin, *length - data_begin) != 0) return (1);

	/* encrypt data+crc32 and keep a 4byte hole */
	if (my_encrypt_data(packet + data_begin + 4,
						packet + data_begin,
						*length - (data_begin - 4))
		!= 0)
		return (1);

	/* write IV+IDX right in front of the encrypted data */
	if (set_IVidx(packet, data_begin) != 0) return (1);

	/* set WEP bit */
	packet[1] = packet[1] | 0x40;

	*length += 8;
	/* now you got yourself a shiny, brand new encrypted wep packet ;) */

	return (0);
}

static int packet_xmit(unsigned char * packet, int length)
{
	REQUIRE(packet != NULL);

	unsigned char K[64];
	unsigned char buf[4096];
	struct WPA_ST_info * st_cur;
	int data_begin = 24;
	int dest_net;

	if (memcmp(packet, SPANTREE, 6) == 0)
	{
		memcpy(h80211, //-V512
			   IEEE80211_LLC_SNAP,
			   24); // shorter LLC/SNAP - only copy IEEE80211 HEADER
		memcpy(h80211 + 24, packet + 14, length - 14);
		length = length + 24
				 - 14; // 32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE
	}
	else
	{
		memcpy(h80211, IEEE80211_LLC_SNAP, 32);
		memcpy(h80211 + 32, packet + 14, length - 14);
		memcpy(h80211 + 30, packet + 12, 2);
		length = length + 32
				 - 14; // 32=IEEE80211+LLC/SNAP; 14=SRC_MAC+DST_MAC+TYPE
	}

	if (lopt.tods == 1)
	{
		h80211[1] |= 0x01;
		memcpy(h80211 + 4, opt.r_bssid, 6); // BSSID
		memcpy(h80211 + 10, packet + 6, 6); // SRC_MAC
		memcpy(h80211 + 16, packet, 6); // DST_MAC
	}
	else if (lopt.tods == 2)
	{
		h80211[1] |= 0x03;
		length += 6; // additional MAC addr
		data_begin += 6;
		memcpy(buf, h80211 + 24, length - 24);
		memcpy(h80211 + 30, buf, length - 24);

		memcpy(h80211 + 24, packet + 6, 6); // SRC_MAC
		memcpy(h80211 + 10, opt.r_trans, 6); // TRANSMITTER
		memcpy(h80211 + 16, packet, 6); // DST_MAC
		memcpy(h80211 + 4, opt.r_bssid, 6); // RECEIVER
	}
	else
	{
		h80211[1] |= 0x02;
		memcpy(h80211 + 10, opt.r_bssid, 6); // BSSID
		memcpy(h80211 + 16, packet + 6, 6); // SRC_MAC
		memcpy(h80211 + 4, packet, 6); // DST_MAC
	}

	if (opt.crypt == CRYPT_WEP)
	{
		K[0] = rand_u8();
		K[1] = rand_u8();
		K[2] = rand_u8();
		K[3] = 0x00;

		/* write crc32 value behind data */
		if (add_crc32(h80211 + data_begin, length - data_begin) != 0)
			return (1);

		length += 4; // icv
		memcpy(buf, h80211 + data_begin, length - data_begin);
		memcpy(h80211 + data_begin + 4, buf, length - data_begin);

		memcpy(h80211 + data_begin, K, 4); //-V512
		length += 4; // iv

		memcpy(K + 3, lopt.wepkey, lopt.weplen);

		encrypt_wep(h80211 + data_begin + 4,
					length - data_begin - 4,
					K,
					lopt.weplen + 3);

		h80211[1] = h80211[1] | 0x40;
	}
	else if (opt.crypt == CRYPT_WPA)
	{
		/* Find station */
		st_cur = st_1st;
		while (st_cur != NULL)
		{
			// STA -> AP
			if (lopt.tods == 1 && memcmp(st_cur->stmac, packet + 6, 6) == 0)
				break;

			// AP -> STA
			if (lopt.tods == 0 && memcmp(st_cur->stmac, packet, 6) == 0) break;

			st_cur = st_cur->next;
		}
		if (st_cur == NULL)
		{
			printf("Cannot inject: handshake not captured yet.\n");
			return (1);
		}

		// Todo: overflow to higher bits (pn is 6 bytes wide)
		st_cur->pn[5] += 1;

		h80211[1] = h80211[1] | 0x40; // Set Protected Frame flag

		encrypt_ccmp(h80211, length, st_cur->ptk + 32, st_cur->pn);
		length += 16;
		data_begin += 8;
	}
	else if (opt.prgalen > 0)
	{
		if (my_create_wep_packet(h80211, &length, data_begin) != 0) return (1);
	}

	if ((lopt.tods == 2) && lopt.bidir)
	{
		dest_net = get_entry(packet); // Search the list to determine in which
		// network part to send the packet.
		if (dest_net == 0)
		{
			send_packet(_wi_out, h80211, (size_t) length, kNoChange);
		}
		else if (dest_net == 1)
		{
			swap_ra_ta(h80211);
			send_packet(_wi_out, h80211, (size_t) length, kNoChange);
		}
		else
		{
			send_packet(_wi_out, h80211, (size_t) length, kNoChange);
			swap_ra_ta(h80211);
			send_packet(_wi_out, h80211, (size_t) length, kNoChange);
		}
	}
	else
	{
		send_packet(_wi_out, h80211, (size_t) length, kNoChange);
	}

	return (0);
}

static int packet_recv(unsigned char * packet, size_t length)
{
	REQUIRE(packet != NULL);

	unsigned char K[64];
	unsigned char bssid[6], smac[6], dmac[6], stmac[6];
	unsigned char * buffer;
	unsigned long crc;

	size_t len;
	size_t z;
	int fragnum, seqnum, morefrag;
	int process_packet;

	struct WPA_ST_info * st_cur;
	struct WPA_ST_info * st_prv;

	z = ((packet[1] & 3) != 3) ? 24 : 30;
	if ((packet[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	if (length < z + 8)
	{
		return (1);
	}

	// FromDS/ToDS fields
	switch (packet[1] & 3)
	{
		case 0:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			memset(stmac, 0, 6);
			break;
		case 1:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			memcpy(stmac, packet + 10, 6);
			break;
		case 2:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 16, 6);
			memcpy(stmac, packet + 4, 6);
			break;
		default:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 24, 6);
			memcpy(stmac, packet + 4, 6);
			break;
	}

	fragnum = packet[22] & 0x0F;
	seqnum = (packet[22] >> 4) | (packet[23] << 4);
	morefrag = packet[1] & 0x04;

	/* Fragment? */
	if (fragnum > 0 || morefrag)
	{
		addFrag(packet, smac, length, opt.crypt, lopt.wepkey, lopt.weplen);
		buffer = getCompleteFrag(
			smac, seqnum, &len, opt.crypt, lopt.wepkey, lopt.weplen);
		timeoutFrag();

		/* we got frag, no compelete packet avail -> do nothing */
		if (buffer == NULL) return (1);

		//             printf("got all frags!!!\n");
		memcpy(packet, buffer, len);
		length = len;
		free(buffer);
		buffer = NULL;
	}

	process_packet = 0;

	// In WDS mode we want to see packets from both sides of the network
	if ((packet[0] & 0x08) == 0x08)
	{
		if (memcmp(bssid, opt.r_bssid, 6) == 0)
		{
			process_packet = 1;
		}
		else if (lopt.tods == 2 && memcmp(bssid, opt.r_trans, 6) == 0)
		{
			process_packet = 1;
		}
	}

	if (process_packet)
	{
		/* find station */

		st_prv = NULL;
		st_cur = st_1st;

		while (st_cur != NULL)
		{
			if (!memcmp(st_cur->stmac, stmac, 6)) break;

			st_prv = st_cur;
			st_cur = st_cur->next;
		}

		/* if it's a new station, add it */

		if (st_cur == NULL)
		{
			if (!(st_cur
				  = (struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info))))
			{
				perror("malloc failed");
				return (1);
			}

			memset(st_cur, 0, sizeof(struct WPA_ST_info));

			if (st_1st == NULL)
				st_1st = st_cur;
			else
				st_prv->next = st_cur;

			memcpy(st_cur->stmac, stmac, 6);
			memcpy(st_cur->bssid, bssid, 6);
		}

		/* check if we haven't already processed this packet */

		crc = calc_crc_buf(packet + z, length - z);

		if ((packet[1] & 3) == 2)
		{
			if (st_cur->t_crc == crc)
			{
				return (1);
			}

			st_cur->t_crc = crc;
		}
		else
		{
			if (st_cur->f_crc == crc)
			{
				return (1);
			}

			st_cur->f_crc = crc;
		}

		/* check the SNAP header to see if data is encrypted *
		 * as unencrypted data begins with AA AA 03 00 00 00 */

		if (packet[z] != packet[z + 1] || packet[z + 2] != 0x03)
		{
			/* check the extended IV flag */

			if ((packet[z + 3] & 0x20) == 0)
			{
				if (opt.crypt != CRYPT_WEP) return (1);

				memcpy(K, packet + z, 3);
				memcpy(K + 3, lopt.wepkey, lopt.weplen);

				if (decrypt_wep(
						packet + z + 4, length - z - 4, K, 3 + lopt.weplen)
					== 0)
				{
					printf("ICV check failed!\n");
					return (1);
				}

				/* WEP data packet was successfully decrypted, *
				 * remove the WEP IV & ICV and write the data  */

				length -= 8;

				/* can overlap */
				memmove(packet + z, packet + z + 4, length - z);

				packet[1] &= 0xBF;
			}
			else
			{
				if (opt.crypt != CRYPT_WPA) return (1);

				/* if the PTK is valid, try to decrypt */

				if (!st_cur->valid_ptk) return (1);

				if (st_cur->keyver == 1)
				{
					if (decrypt_tkip(packet, length, st_cur->ptk + 32) == 0)
					{
						printf("ICV check failed (WPA-TKIP)!\n");
						return (1);
					}

					length -= 20;
				}
				else
				{
					if (memcmp(smac, st_cur->stmac, 6) == 0)
					{
						st_cur->pn[0] = packet[z + 7];
						st_cur->pn[1] = packet[z + 6];
						st_cur->pn[2] = packet[z + 5];
						st_cur->pn[3] = packet[z + 4];
						st_cur->pn[4] = packet[z + 1];
						st_cur->pn[5] = packet[z + 0];
					}

					if (decrypt_ccmp(packet, length, st_cur->ptk + 32) == 0)
					{
						printf("ICV check failed (WPA-CCMP)!\n");
						return (1);
					}

					length -= 16;
				}

				/* WPA data packet was successfully decrypted, *
				 * remove the WPA Ext.IV & MIC, write the data */

				/* can overlap */
				memmove(packet + z, packet + z + 8, length - z);

				packet[1] &= 0xBF;
			}
		}
		else if (opt.crypt == CRYPT_WPA)
		{
			/* check ethertype == EAPOL */

			z += 6;

			if (packet[z] != 0x88 || packet[z + 1] != 0x8E)
			{
				return (1);
			}

			z += 2;

			/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

			if (packet[z + 1] != 0x03
				|| (packet[z + 4] != 0xFE && packet[z + 4] != 0x02))
				return (1);

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) == 0
				&& (packet[z + 6] & 0x80) != 0
				&& (packet[z + 5] & 0x01) == 0)
			{
				/* set authenticator nonce */

				memcpy(st_cur->anonce, &packet[z + 17], 32);
			}

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

			if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) == 0
				&& (packet[z + 6] & 0x80) == 0
				&& (packet[z + 5] & 0x01) != 0)
			{
				if (memcmp(&packet[z + 17], ZERO, 32) != 0)
				{
					/* set supplicant nonce */

					memcpy(st_cur->snonce, &packet[z + 17], 32);
				}

				/* copy the MIC & eapol frame */

				st_cur->eapol_size = (packet[z + 2] << 8) + packet[z + 3] + 4;

				if (length - z < st_cur->eapol_size
					|| st_cur->eapol_size > sizeof(st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					st_cur->eapol_size = 0;
					return (1);
				}

				memcpy(st_cur->keymic, &packet[z + 81], 16); //-V512
				memcpy(st_cur->eapol, &packet[z], st_cur->eapol_size);
				memset(st_cur->eapol + 81, 0, 16);

				/* copy the key descriptor version */

				st_cur->keyver = packet[z + 6] & 7;
			}

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) != 0
				&& (packet[z + 6] & 0x80) != 0
				&& (packet[z + 5] & 0x01) != 0)
			{
				if (memcmp(&packet[z + 17], ZERO, 32) != 0)
				{
					/* set authenticator nonce */

					memcpy(st_cur->anonce, &packet[z + 17], 32);
				}

				/* copy the MIC & eapol frame */

				st_cur->eapol_size = (packet[z + 2] << 8) + packet[z + 3] + 4;

				if (length - z < st_cur->eapol_size
					|| st_cur->eapol_size > sizeof(st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					st_cur->eapol_size = 0;
					return (1); // continue;
				}

				memcpy(st_cur->keymic, &packet[z + 81], 16); //-V512
				memcpy(st_cur->eapol, &packet[z], st_cur->eapol_size);
				memset(st_cur->eapol + 81, 0, 16);

				/* copy the key descriptor version */

				st_cur->keyver = packet[z + 6] & 7;
			}

			st_cur->valid_ptk = calc_ptk(st_cur, lopt.pmk);

			if (st_cur->valid_ptk)
			{
				printf("WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X\n",
					   st_cur->stmac[0],
					   st_cur->stmac[1],
					   st_cur->stmac[2],
					   st_cur->stmac[3],
					   st_cur->stmac[4],
					   st_cur->stmac[5]);
			}
		}

		switch (packet[1] & 3)
		{
			case 1:
				memcpy(h80211, packet + 16, 6); //-V525
				memcpy(h80211 + 6, packet + 10, 6); // SRC_MAC
				break;
			case 2:
				memcpy(h80211, packet + 4, 6); // DST_MAC
				memcpy(h80211 + 6, packet + 16, 6); // SRC_MAC
				break;
			case 3:
				memcpy(h80211, packet + 16, 6); // DST_MAC
				memcpy(h80211 + 6, packet + 24, 6); // SRC_MAC
				break;
			default:
				break;
		}

		/* Keep track of known MACs, so we only have to tunnel into one side of
		 * the WDS network */
		if (((packet[1] & 3) == 3) && lopt.bidir)
		{
			if (!memcmp(packet + 10, opt.r_bssid, 6))
			{
				set_entry(packet + 24, 0);
			}
			if (!memcmp(packet + 10, opt.r_trans, 6))
			{
				set_entry(packet + 24, 1);
			}
		}

		if (memcmp(dmac, SPANTREE, 6) == 0)
		{
			if (length <= z + 8) return (1);

			memcpy(h80211 + 14, packet + z, length - z);

			length = length - z + 14;

			h80211[12] = ((length - 14) >> 8) & 0xFF;
			h80211[13] = (length - 14) & 0xFF;
		}
		else
		{
			memcpy(h80211 + 12, packet + z + 6, 2); // copy ether type

			if (length <= z + 8) return (1);

			memcpy(h80211 + 14, packet + z + 8, length - z - 8);
			length = length - z - 8 + 14;
		}

		ti_write(dev.dv_ti, h80211, length);
	}
	else
	{
		return (1);
	}

	return (0);
}

int main(int argc, char * argv[])
{
	int ret_val, i, n, ret;
	unsigned int un;
	struct pcap_pkthdr pkh;
	fd_set read_fds;
	unsigned char buffer[4096];
	unsigned char bssid[6];
	char *s, buf[128];
	size_t caplen, len;

	ac_crypto_init();

	/* check the arguments */

	memset(&opt, 0, sizeof(opt));
	memset(&dev, 0, sizeof(dev));

	rFragment = (pFrag_t) malloc(sizeof(struct Fragment_list));
	ALLEGE(rFragment != NULL);
	memset(rFragment, 0, sizeof(struct Fragment_list));

	opt.r_nbpps = 100;
	lopt.tods = 0;

	rand_init();

	while (1)
	{
		int option_index = 0;

		static const struct option long_options[] = {{"netmask", 1, 0, 'm'},
													 {"bssid", 1, 0, 'd'},
													 {"repeat", 0, 0, 'f'},
													 {"help", 0, 0, 'H'},
													 {0, 0, 0, 0}};

		const int option = getopt_long(argc,
									   argv,
									   "x:a:h:i:r:y:t:s:bw:p:e:m:d:fH",
									   long_options,
									   &option_index);

		if (option < 0) break;

		switch (option)
		{
			case 0:

				break;

			case ':':
			case '?':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case 'x':

				ret = sscanf(optarg, "%d", &opt.r_nbpps);
				if (opt.r_nbpps < 1 || opt.r_nbpps > 1024 || ret != 1)
				{
					printf("Invalid number of packets per second. [1-1024]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'a':

				if (getmac(optarg, 1, opt.r_bssid) != 0)
				{
					printf("Invalid AP MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'h':

				if (getmac(optarg, 1, opt.r_smac) != 0)
				{
					printf("Invalid source MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'y':

				if (opt.prga != NULL)
				{
					printf("PRGA file already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				if (opt.crypt != CRYPT_NONE)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				if (read_prga(&(opt.prga), optarg) != 0)
				{
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'i':

				if (opt.s_face != NULL || opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				opt.s_face = optarg;
				break;

			case 't':

				if (atoi(optarg) == 1)
					lopt.tods = 1;
				else if (atoi(optarg) == 2)
					lopt.tods = 2;
				else
					lopt.tods = 0;
				break;

			case 's':

				if (getmac(optarg, 1, opt.r_trans) != 0)
				{
					printf("Invalid Transmitter MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'b':

				lopt.bidir = 1;
				break;

			case 'w':

				if (opt.prga != NULL)
				{
					printf("PRGA file already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				if (opt.crypt != CRYPT_NONE)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WEP;

				i = 0;
				s = optarg;

				buf[0] = s[0];
				buf[1] = s[1];
				buf[2] = '\0';

				while (sscanf(buf, "%x", &un) == 1)
				{
					if (un > 255)
					{
						printf("Invalid WEP key.\n");
						printf("\"%s --help\" for help.\n", argv[0]);
						return (EXIT_FAILURE);
					}

					lopt.wepkey[i++] = (uint8_t) un;

					if (i >= 64) break;

					s += 2;

					if (s[0] == ':' || s[0] == '-') s++;

					if (s[0] == '\0' || s[1] == '\0') break;

					buf[0] = s[0];
					buf[1] = s[1];
				}

				if (i != 5 && i != 13 && i != 16 && i != 29 && i != 61)
				{
					printf("Invalid WEP key length.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				lopt.weplen = i;

				break;

			case 'e':

				if (lopt.essid[0])
				{
					printf("ESSID already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WPA;

				memset(lopt.essid, 0, sizeof(lopt.essid));
				strncpy(lopt.essid, optarg, sizeof(lopt.essid) - 1);
				break;

			case 'p':

				if (opt.prga != NULL)
				{
					printf("PRGA file already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				if (opt.crypt != CRYPT_NONE && opt.crypt != CRYPT_WPA)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WPA;

				memset(lopt.passphrase, 0, sizeof(lopt.passphrase));
				strncpy(lopt.passphrase, optarg, sizeof(lopt.passphrase) - 1);

				break;

			case 'm':

				if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
				{
					printf("Notice: netmask already given\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					break;
				}
				if (getmac(optarg, 1, opt.f_netmask) != 0)
				{
					printf("Notice: invalid netmask\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;
			case 'd':
				if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
				{
					printf("Notice: bssid already given\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					break;
				}
				if (getmac(optarg, 1, opt.f_bssid) != 0)
				{
					printf("Notice: invalid bssid\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;
			case 'f':
				lopt.repeat = 1;
				break;
			case 'r':

				if (opt.s_face != NULL || opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				opt.s_file = optarg;
				break;

			case 'H':

				printf(usage,
					   getVersion("Airtun-ng",
								  _MAJ,
								  _MIN,
								  _SUB_MIN,
								  _REVISION,
								  _BETA,
								  _RC));
				return (EXIT_FAILURE);

			default:
				goto usage;
		}
	}

	if (argc - optind != 1)
	{
		if (argc == 1)
		{
		usage:
			printf(
				usage,
				getVersion(
					"Airtun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC));
		}
		if (argc - optind == 0)
		{
			printf("No replay interface specified.\n");
		}
		if (argc > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return (EXIT_FAILURE);
	}

	if ((memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
		&& (memcmp(opt.f_bssid, NULL_MAC, 6) == 0))
	{
		printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (memcmp(opt.r_bssid, NULL_MAC, 6) == 0)
	{
		printf("Please specify a BSSID (-a).\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if ((memcmp(opt.r_trans, NULL_MAC, 6) == 0) && lopt.tods == 2)
	{
		printf("Please specify a Transmitter (-s).\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (opt.crypt == CRYPT_WPA)
	{
		if (lopt.passphrase[0] != '\0')
		{
			/* compute the Pairwise Master Key */

			if (lopt.essid[0] == '\0')
			{
				printf("You must also specify the ESSID (-e).\n");
				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);
			}

			calc_pmk(lopt.passphrase, lopt.essid, lopt.pmk);
		}
	}

	dev.fd_rtc = -1;

/* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
	if (1)
	{
		if ((dev.fd_rtc = open("/dev/rtc0", O_RDONLY)) < 0)
		{
			dev.fd_rtc = 0;
		}

		if ((dev.fd_rtc == 0) && (dev.fd_rtc = open("/dev/rtc", O_RDONLY)) < 0)
		{
			dev.fd_rtc = 0;
		}

		if (dev.fd_rtc > 0)
		{
			if (ioctl(dev.fd_rtc, RTC_IRQP_SET, 1024) < 0)
			{
				perror("ioctl(RTC_IRQP_SET) failed");
				printf("Make sure enhanced rtc device support is enabled in "
					   "the kernel (module\n"
					   "rtc, not genrtc) - also try 'echo 1024 "
					   ">/proc/sys/dev/rtc/max-user-freq'.\n");
				close(dev.fd_rtc);
				dev.fd_rtc = -1;
			}
			else
			{
				if (ioctl(dev.fd_rtc, RTC_PIE_ON, 0) < 0)
				{
					perror("ioctl(RTC_PIE_ON) failed");
					close(dev.fd_rtc);
					dev.fd_rtc = -1;
				}
			}
		}
		else
		{
			printf("For information, no action required:"
				   " Using gettimeofday() instead of /dev/rtc\n");
			dev.fd_rtc = -1;
		}
	}
#endif /* linux */
#endif /* __i386__ */

	/* open the replay interface */
	_wi_out = wi_open(argv[optind]);
	if (!_wi_out) return (EXIT_FAILURE);
	dev.fd_out = wi_fd(_wi_out);

	/* open the packet source */
	if (opt.s_face != NULL)
	{
		_wi_in = wi_open(opt.s_face);
		if (!_wi_in) return (EXIT_FAILURE);
		dev.fd_in = wi_fd(_wi_in);
	}
	else
	{
		_wi_in = _wi_out;
		dev.fd_in = dev.fd_out;
	}

	/* drop privileges */
	if (setuid(getuid()) == -1)
	{
		perror("setuid");
	}

	/* XXX */
	if (opt.r_nbpps == 0)
	{
		if (dev.is_wlanng || dev.is_hostap)
			opt.r_nbpps = 200;
		else
			opt.r_nbpps = 500;
	}

	if (opt.s_file != NULL)
	{
		if (!(dev.f_cap_in = fopen(opt.s_file, "rb")))
		{
			perror("open failed");
			return (EXIT_FAILURE);
		}

		n = sizeof(struct pcap_file_header);

		if (fread(&dev.pfh_in, 1, n, dev.f_cap_in) != (size_t) n)
		{
			perror("fread(pcap file header) failed");
			return (EXIT_FAILURE);
		}

		if (dev.pfh_in.magic != TCPDUMP_MAGIC
			&& dev.pfh_in.magic != TCPDUMP_CIGAM)
		{
			fprintf(stderr,
					"\"%s\" isn't a pcap file (expected "
					"TCPDUMP_MAGIC).\n",
					opt.s_file);
			return (EXIT_FAILURE);
		}

		if (dev.pfh_in.magic == TCPDUMP_CIGAM) SWAP32(dev.pfh_in.linktype);

		if (dev.pfh_in.linktype != LINKTYPE_IEEE802_11
			&& dev.pfh_in.linktype != LINKTYPE_PRISM_HEADER
			&& dev.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR
			&& dev.pfh_in.linktype != LINKTYPE_PPI_HDR)
		{
			fprintf(stderr,
					"Wrong linktype from pcap file header "
					"(expected LINKTYPE_IEEE802_11) -\n"
					"this doesn't look like a regular 802.11 "
					"capture.\n");
			return (EXIT_FAILURE);
		}
	}

	dev.dv_ti = ti_open(NULL);
	if (!dev.dv_ti)
	{
		printf("error opening tap device: %s\n", strerror(errno));
		return (EXIT_FAILURE);
	}
	printf("created tap interface %s\n", ti_name(dev.dv_ti));

	if (opt.prgalen <= 0 && opt.crypt == CRYPT_NONE)
	{
		printf("No encryption specified. Sending and receiving frames through "
			   "%s.\n",
			   argv[optind]);
	}
	else if (opt.crypt == CRYPT_WPA)
	{
		printf("WPA encryption specified. Sending and receiving frames through "
			   "%s.\n",
			   argv[optind]);
	}
	else if (opt.crypt == CRYPT_WEP)
	{
		printf("WEP encryption specified. Sending and receiving frames through "
			   "%s.\n",
			   argv[optind]);
	}
	else
	{
		printf("WEP encryption by PRGA specified. No reception, only sending "
			   "frames through %s.\n",
			   argv[optind]);
	}

	if (lopt.tods == 1)
	{
		printf("ToDS bit set in all frames.\n");
	}
	else if (lopt.tods == 2)
	{
		printf("ToDS and FromDS bit set in all frames (WDS/Bridge) - ");
		if (lopt.bidir)
		{
			printf("bidirectional mode\n");
		}
		else
		{
			printf("unidirectional mode\n");
		}
	}
	else
	{
		printf("FromDS bit set in all frames.\n");
	}

	for (;;)
	{
		if (opt.s_file != NULL)
		{
			n = sizeof(pkh);

			if (fread(&pkh, n, 1, dev.f_cap_in) != 1)
			{
				printf("Finished reading input file %s.\n", opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (dev.pfh_in.magic == TCPDUMP_CIGAM)
			{
				SWAP32(pkh.caplen);
				SWAP32(pkh.len);
			}

			n = caplen = pkh.caplen;

			if (n <= 0 || n > (int) sizeof(h80211))
			{
				printf("Finished reading input file %s.\n", opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (fread(h80211, n, 1, dev.f_cap_in) != 1)
			{
				printf("Finished reading input file %s.\n", opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (dev.pfh_in.linktype == LINKTYPE_PRISM_HEADER)
			{
				if (h80211[7] == 0x40)
					n = 64;
				else
					n = *(int *) (h80211 + 4); //-V1032

				if (n < 8 || n >= (int) caplen) continue;

				memcpy(tmpbuf, h80211, caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, caplen);
			}

			if (dev.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
			{
				/* remove the radiotap header */

				n = *(unsigned short *) (h80211 + 2); //-V1032

				if (n <= 0 || n >= (int) caplen) continue; //-V560

				memcpy(tmpbuf, h80211, caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, caplen);
			}

			if (dev.pfh_in.linktype == LINKTYPE_PPI_HDR)
			{
				/* remove the PPI header */

				n = le16_to_cpu(*(unsigned short *) (h80211 + 2)); //-V1032

				if (n <= 0 || n >= (int) caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24
					&& le16_to_cpu(*(unsigned short *) (h80211 + 8)) //-V1032
						   == 2)
					n = 32;

				if (n <= 0 || n >= (int) caplen) continue; //-V560

				memcpy(tmpbuf, h80211, caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, caplen);
			}

			if (lopt.repeat)
			{
				if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
				{
					switch (h80211[1] & 3)
					{
						case 0:
							memcpy(bssid, h80211 + 16, 6);
							break;
						case 1:
							memcpy(bssid, h80211 + 4, 6);
							break;
						case 2:
							memcpy(bssid, h80211 + 10, 6);
							break;
						default:
							memcpy(bssid, h80211 + 10, 6);
							break;
					}
					if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
					{
						if (is_filtered_netmask(bssid)) continue;
					}
					else
					{
						if (memcmp(opt.f_bssid, bssid, 6) != 0) continue;
					}
				}
				send_packet(_wi_out, h80211, (size_t) caplen, kNoChange);
			}

			packet_recv(h80211, caplen);
			msleep(1000 / opt.r_nbpps);
			continue;
		}

		FD_ZERO(&read_fds);
		FD_SET(dev.fd_in, &read_fds);
		FD_SET(ti_fd(dev.dv_ti), &read_fds);
		ret_val = select(
			MAX(ti_fd(dev.dv_ti), dev.fd_in) + 1, &read_fds, NULL, NULL, NULL);
		if (ret_val < 0) break;
		if (ret_val > 0)
		{
			if (FD_ISSET(ti_fd(dev.dv_ti), &read_fds))
			{
				len = ti_read(dev.dv_ti, buffer, sizeof(buffer));
				if (len > 0)
				{
					packet_xmit(buffer, len);
				}
			}
			if (FD_ISSET(dev.fd_in, &read_fds))
			{
				len = read_packet(_wi_in, buffer, sizeof(buffer), NULL);
				if (len > 0)
				{
					packet_recv(buffer, len);
				}
			}
		} // if( ret_val > 0 )
	} // for( ; ; )

	ti_close(dev.dv_ti);

	/* that's all, folks */

	return (EXIT_SUCCESS);
}
