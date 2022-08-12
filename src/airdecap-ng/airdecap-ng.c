/*
 *  802.11 to Ethernet pcap translator
 *
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005  Christophe Devine
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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>

#include "aircrack-ng/version.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/defs.h"
#include "aircrack-ng/osdep/byteorder.h"
#include "aircrack-ng/adt/avl_tree.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/tui/console.h"

static const char usage[] =

	"\n"
	"  %s - (C) 2006-2022 Thomas d\'Otreppe\n"
	"  https://www.aircrack-ng.org\n"
	"\n"
	"  usage: airdecap-ng [options] <pcap file>\n"
	"\n"
	"  Common options:\n"
	"      -l         : don't remove the 802.11 header\n"
	"      -b <bssid> : access point MAC address filter\n"
	"      -e <essid> : target network SSID\n"
	"      -o <fname> : output file for decrypted packets (default <src>-dec)\n"
	"\n"
	"  WEP specific option:\n"
	"      -w <key>   : target network WEP key in hex\n"
	"      -c <fname> : output file for corrupted WEP packets (default "
	"<src>-bad)\n"
	"\n"
	"  WPA specific options:\n"
	"      -p <pass>  : target network WPA passphrase\n"
	"      -k <pmk>   : WPA Pairwise Master Key in hex\n"
	"\n"
	"      --help     : Displays this usage screen\n"
	"\n"
	"  If your capture contains any WDS packet, you must specify the -b\n"
	"  option (otherwise only packets destined to the AP will be decrypted)\n"
	"\n";

static struct decap_stats
{
	unsigned long nb_stations; /* # of stations seen */
	unsigned long nb_read; /* # of packets read       */
	unsigned long nb_wep; /* # of WEP data packets   */
	unsigned long nb_bad; /* # of bad data packets   */
	unsigned long nb_wpa; /* # of WPA data packets   */
	unsigned long nb_plain; /* # of plaintext packets  */
	unsigned long nb_unwep; /* # of decrypted WEP pkt  */
	unsigned long nb_unwpa; /* # of decrypted WPA pkt  */
	unsigned long nb_failed_tkip; /* # of failed WPA TKIP pkt decryptions */
	unsigned long nb_failed_ccmp; /* # of failed WPA CCMP pkt decryptions */
} stats;

static struct options
{
	int no_convert;
	char essid[36];
	char passphrase[65];
	unsigned char bssid[6];
	unsigned char pmk[40];
	unsigned char wepkey[64];
	int weplen, crypt;
	int store_bad;
	char decrypted_fpath[65536];
	char corrupted_fpath[65536];
} opt;

static unsigned char buffer[65536];
static unsigned char buffer2[65536];
static bool wds = false;

/* this routine handles to 802.11 to Ethernet translation */

static int
write_packet(FILE * f_out, struct pcap_pkthdr * pkh, unsigned char * h80211)
{
	REQUIRE(f_out != NULL);
	REQUIRE(pkh != NULL);
	REQUIRE(h80211 != NULL);

	int n;
	unsigned char arphdr[12];
	int qosh_offset = 0;

	if (opt.no_convert)
	{
		if (buffer != h80211) memcpy(buffer, h80211, pkh->caplen);
	}
	else
	{
		/* create the Ethernet link layer (MAC dst+src) */

		switch (h80211[1] & 3)
		{
			case 0: /* To DS = 0, From DS = 0: DA, SA, BSSID */

				memcpy(arphdr + 0, h80211 + 4, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 10, sizeof(arphdr) / 2);
				break;

			case 1: /* To DS = 1, From DS = 0: BSSID, SA, DA */

				memcpy(arphdr + 0, h80211 + 16, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 10, sizeof(arphdr) / 2);
				break;

			case 2: /* To DS = 0, From DS = 1: DA, BSSID, SA */

				memcpy(arphdr + 0, h80211 + 4, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 16, sizeof(arphdr) / 2);
				break;

			default: /* To DS = 1, From DS = 1: RA, TA, DA, SA */

				memcpy(arphdr + 0, h80211 + 16, sizeof(arphdr) / 2);
				memcpy(arphdr + 6, h80211 + 24, sizeof(arphdr) / 2);
				break;
		}

		/* check QoS header */
		if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
		{
			qosh_offset += 2;
		}

		/* remove the 802.11 + LLC header */

		if ((h80211[1] & 3) != 3)
		{
			pkh->len -= 24 + qosh_offset + 6;
			pkh->caplen -= 24 + qosh_offset + 6;

			/* can overlap */
			memmove(buffer + 12, h80211 + qosh_offset + 30, pkh->caplen);
		}
		else
		{
			pkh->len -= 30 + qosh_offset + 6;
			pkh->caplen -= 30 + qosh_offset + 6;

			memmove(buffer + 12, h80211 + qosh_offset + 36, pkh->caplen);
		}

		memcpy(buffer, arphdr, 12);

		pkh->len += 12;
		pkh->caplen += 12;
	}

	pkh->len = __cpu_to_le32(pkh->len);
	pkh->caplen = __cpu_to_le32(pkh->caplen);

	n = sizeof(struct pcap_pkthdr);

	if (fwrite(pkh, 1, n, f_out) != (size_t) n)
	{
		perror("fwrite(packet header) failed");
		return (EXIT_FAILURE);
	}

	n = __le32_to_cpu(pkh->caplen);

	if (fwrite(buffer, 1, n, f_out) != (size_t) n)
	{
		perror("fwrite(packet data) failed");
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int main(int argc, char * argv[])
{
	time_t tt;
	unsigned magic;
	char *s, buf[128];
	FILE *f_in, *f_out, *f_bad = NULL;
	unsigned long crc;
	int i = 0, linktype;
	unsigned n;
	unsigned z;
	unsigned char * h80211 = NULL;
	unsigned char bssid[6] = {0}, stmac[6] = {0};

	c_avl_tree_t * stations = c_avl_create(station_compare);
	ALLEGE(stations != NULL);
	struct WPA_ST_info * st_cur;
	struct pcap_file_header pfh;
	struct pcap_pkthdr pkh;

	ac_crypto_init();

	/* parse the arguments */

	memset(&opt, 0, sizeof(opt));

	while (1)
	{
		int option_index = 0;

		const struct option long_options[] = {{"bssid", 1, 0, 'b'},
											  {"debug", 1, 0, 'd'},
											  {"help", 0, 0, 'H'},
											  {0, 0, 0, 0}};

		int option = getopt_long(
			argc, argv, "lb:k:e:o:p:w:c:H", long_options, &option_index);

		if (option < 0) break;

		switch (option)
		{
			case ':':
			case '?':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case 'l':

				opt.no_convert = 1;
				break;

			case 'b':

				i = 0;
				s = optarg;

				while (sscanf(s, "%x", &n) == 1)
				{
					if (n > 255)
					{
						printf("Invalid BSSID (not a MAC).\n");
						printf("\"%s --help\" for help.\n", argv[0]);
						return (EXIT_FAILURE);
					}

					opt.bssid[i] = n;

					if (++i >= 6) break;

					if (!(s = strchr(s, ':'))) break;

					s++;
				}

				if (i != 6)
				{
					printf("Invalid BSSID (not a MAC).\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'k':

				if (opt.crypt != CRYPT_NONE)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WPA;

				i = 0;
				s = optarg;

				buf[0] = s[0];
				buf[1] = s[1];
				buf[2] = '\0';

				while (sscanf(buf, "%x", &n) == 1)
				{
					if (n > 255)
					{
						printf("Invalid WPA PMK.\n");
						printf("\"%s --help\" for help.\n", argv[0]);
						return (EXIT_FAILURE);
					}

					opt.pmk[i++] = n;
					if (i >= 32) break;

					s += 2;

					if (s[0] == ':' || s[0] == '-') s++;

					if (s[0] == '\0' || s[1] == '\0') break;

					buf[0] = s[0];
					buf[1] = s[1];
				}

				if (i != 32)
				{
					printf("Invalid WPA PMK.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'e':

				if (opt.essid[0])
				{
					printf("ESSID already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				memset(opt.essid, 0, sizeof(opt.essid));
				strncpy(opt.essid, optarg, sizeof(opt.essid) - 1);
				break;

			case 'o':

				if (opt.decrypted_fpath[0])
				{
					printf(
						"filename for decrypted packets already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				strncpy(opt.decrypted_fpath,
						optarg,
						sizeof(opt.decrypted_fpath) - 1);
				break;

			case 'c':

				if (opt.corrupted_fpath[0])
				{
					printf(
						"filename for corrupted packets already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				strncpy(opt.corrupted_fpath,
						optarg,
						sizeof(opt.corrupted_fpath) - 1);
				break;

			case 'p':

				if (opt.crypt != CRYPT_NONE)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WPA;

				memset(opt.passphrase, 0, sizeof(opt.passphrase));
				strncpy(opt.passphrase, optarg, sizeof(opt.passphrase) - 1);
				break;

			case 'w':

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

				while (sscanf(buf, "%x", &n) == 1)
				{
					if (n > 255)
					{
						printf("Invalid WEP key.\n");
						printf("\"%s --help\" for help.\n", argv[0]);
						return (EXIT_FAILURE);
					}

					opt.wepkey[i++] = n;

					if (i >= 64) break;

					s += 2;

					if (s[0] == ':' || s[0] == '-') s++;

					if (s[0] == '\0' || s[1] == '\0') break;

					buf[0] = s[0];
					buf[1] = s[1];
				}

				if (i != 5 && i != 13 && i != 16 && i != 29 && i != 61)
				{
					printf("Invalid WEP key length. [5,13,16,29,61]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.weplen = i;

				break;

			case 'H':

				printf(usage,
					   getVersion("Airdecap-ng",
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
			printf(usage,
				   getVersion("Airdecap-ng",
							  _MAJ,
							  _MIN,
							  _SUB_MIN,
							  _REVISION,
							  _BETA,
							  _RC));
		}
		if (argc - optind == 0)
		{
			printf("No file to decrypt specified.\n");
		}
		if (argc > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return (EXIT_FAILURE);
	}

	if (opt.crypt == CRYPT_WPA)
	{
		if (opt.passphrase[0] != '\0')
		{
			/* compute the Pairwise Master Key */

			if (opt.essid[0] == '\0')
			{
				printf("You must also specify the ESSID (-e).\n");
				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);
			}

			calc_pmk(opt.passphrase, opt.essid, opt.pmk);
		}
	}

	/* open the input and output pcap files */

	if ((f_in = fopen(argv[optind], "rb")) == NULL)
	{
		perror("fopen failed\n");
		printf("Could not open \"%s\".\n", argv[optind]);
		return (EXIT_FAILURE);
	}

	n = sizeof(pfh);

	if (fread(&pfh, 1, n, f_in) != (size_t) n)
	{
		perror("fread(pcap file header) failed");
		return (EXIT_FAILURE);
	}

	if (pfh.magic != TCPDUMP_MAGIC && pfh.magic != TCPDUMP_CIGAM)
	{
		printf("\"%s\" isn't a pcap file (expected "
			   "TCPDUMP_MAGIC).\n",
			   argv[optind]);
		return (EXIT_FAILURE);
	}

	if ((magic = pfh.magic) == TCPDUMP_CIGAM) SWAP32(pfh.linktype);

	if (pfh.linktype != LINKTYPE_IEEE802_11
		&& pfh.linktype != LINKTYPE_PRISM_HEADER
		&& pfh.linktype != LINKTYPE_RADIOTAP_HDR
		&& pfh.linktype != LINKTYPE_PPI_HDR)
	{
		printf("\"%s\" isn't a regular 802.11 "
			   "(wireless) capture.\n",
			   argv[optind]);
		return (EXIT_FAILURE);
	}

	linktype = pfh.linktype;

	n = strlen(argv[optind]);

	if (n > 4 && (n + 5 < (int) sizeof(buffer)) && argv[optind][n - 4] == '.')
	{
		memcpy(buffer, argv[optind], n - 4);
		memcpy(buffer2, argv[optind], n - 4);
		memcpy(buffer + n - 4, "-dec", 4);
		memcpy(buffer2 + n - 4, "-bad", 4);
		memcpy(buffer + n, argv[optind] + n - 4, 5);
		memcpy(buffer2 + n, argv[optind] + n - 4, 5);
	}
	else
	{
		if (n > 5 && (n + 6 < (int) sizeof(buffer))
			&& argv[optind][n - 5] == '.')
		{
			memcpy(buffer, argv[optind], n - 5);
			memcpy(buffer2, argv[optind], n - 5);
			memcpy(buffer + n - 5, "-dec", 4);
			memcpy(buffer2 + n - 5, "-bad", 4);
			memcpy(buffer + n - 1, argv[optind] + n - 5, 6);
			memcpy(buffer2 + n - 1, argv[optind] + n - 5, 6);
		}
		else
		{
			memset(buffer, 0, sizeof(buffer));
			memset(buffer2, 0, sizeof(buffer));
			snprintf(
				(char *) buffer, sizeof(buffer) - 1, "%s-dec", argv[optind]);
			snprintf(
				(char *) buffer2, sizeof(buffer) - 1, "%s-bad", argv[optind]);
		}
	}

	if (opt.crypt == CRYPT_WEP && opt.no_convert == 1)
	{
		opt.store_bad = 1;
	}

	/* Support manually-configured output files*/
	if (opt.decrypted_fpath[0])
		f_out = fopen(opt.decrypted_fpath, "wb+");
	else
		f_out = fopen((char *) buffer, "wb+");

	if (f_out == NULL)
	{
		perror("fopen failed");
		printf("Could not create \"%s\".\n", buffer);
		return (EXIT_FAILURE);
	}

	if (opt.store_bad)
	{
		if (opt.corrupted_fpath[0])
			f_bad = fopen(opt.corrupted_fpath, "wb+");
		else
			f_bad = fopen((char *) buffer2, "wb+");

		if (f_bad == NULL)
		{
			perror("fopen failed");
			printf("Could not create \"%s\".\n", buffer2);
			return (EXIT_FAILURE);
		}
	}

#if (AIRCRACK_NG_BYTE_ORDER == AIRCRACK_NG_BIG_ENDIAN)
	pfh.magic = TCPDUMP_CIGAM;
#else
	pfh.magic = TCPDUMP_MAGIC;
#endif
	pfh.version_major = cpu_to_le16(PCAP_VERSION_MAJOR);
	pfh.version_minor = cpu_to_le16(PCAP_VERSION_MINOR);
	pfh.thiszone = 0;
	pfh.sigfigs = 0;
	pfh.snaplen = cpu_to_le32(65535);
	pfh.linktype = cpu_to_le32((opt.no_convert) ? LINKTYPE_IEEE802_11
												: LINKTYPE_ETHERNET);

	n = sizeof(pfh);

	if (fwrite(&pfh, 1, n, f_out) != (size_t) n)
	{
		perror("fwrite(pcap file header) failed");
		return (EXIT_FAILURE);
	}

	if (opt.store_bad)
	{
		ALLEGE(f_bad != NULL);

		if (fwrite(&pfh, 1, n, f_bad) != (size_t) n)
		{
			perror("fwrite(pcap file header) failed");
			return (EXIT_FAILURE);
		}
	}

	/* loop reading and deciphering the packets */

	memset(&stats, 0, sizeof(stats));
	tt = time(NULL);

	while (1)
	{
		if (time(NULL) - tt > 0)
		{
			/* update the status line every second */

			erase_line(0);
			printf("Read %lu packets...\r", stats.nb_read);
			fflush(stdout);
			tt = time(NULL);
		}

		/* read one packet */

		n = sizeof(pkh);

		if (fread(&pkh, 1, n, f_in) != (size_t) n) break;

		if (magic == TCPDUMP_CIGAM)
		{
			SWAP32(pkh.caplen);
			SWAP32(pkh.len);
		}

		n = pkh.caplen;

		if (n <= 0 || n > 65535)
		{
			printf("Corrupted file? Invalid packet length %u.\n", n);
			break;
		}

		if (fread(buffer, 1, n, f_in) != (size_t) n) break;

		stats.nb_read++;

		h80211 = buffer;

		if (linktype == LINKTYPE_PRISM_HEADER)
		{
			/* remove the prism header */

			if (h80211[7] == 0x40)
				n = 64; /* prism54 */
			else
			{
				n = *(int *) (h80211 + 4);

				if (magic == TCPDUMP_CIGAM) SWAP32(n);
			}

			if (n < 8 || n >= (unsigned) pkh.caplen) continue;

			h80211 += n;
			pkh.caplen -= n;
		}

		if (linktype == LINKTYPE_RADIOTAP_HDR)
		{
			/* remove the radiotap header */

			n = le16_to_cpu(*(unsigned short *) (h80211 + 2));

			if (n <= 0 || n >= (unsigned) pkh.caplen) continue;

			h80211 += n;
			pkh.caplen -= n;
		}

		if (linktype == LINKTYPE_PPI_HDR)
		{
			/* Remove the PPI header */

			n = le16_to_cpu(*(unsigned short *) (h80211 + 2));

			if (n <= 0 || n >= (unsigned) pkh.caplen) continue;

			/* for a while Kismet logged broken PPI headers */
			if (n == 24 && le16_to_cpu(*(unsigned short *) (h80211 + 8)) == 2)
				n = 32;

			if (n <= 0 || n >= (unsigned) pkh.caplen) continue; //-V560

			h80211 += n;
			pkh.caplen -= n;
		}

		/* remove the FCS if present (madwifi) */

		if (check_crc_buf(h80211, pkh.caplen - 4) == 1)
		{
			pkh.len -= 4;
			pkh.caplen -= 4;
		}

		/* check if data */

		if ((h80211[0] & 0x0C) != 0x08) continue;

		/* check minimum size */

		z = ((*(h80211 + 1) & 3) != 3) ? 24 : 30;

		if (z + 16 > pkh.caplen) continue;

		/* check QoS header */
		if (GET_SUBTYPE(h80211[0]) == IEEE80211_FC0_SUBTYPE_QOS)
		{
			z += 2;
		}

		/* check the BSSID */

		switch (*(h80211 + 1) & 3)
		{
			case 0:
				memcpy(bssid, h80211 + 16, sizeof(bssid)); //-V525
				break; // Adhoc
			case 1:
				memcpy(bssid, h80211 + 4, sizeof(bssid));
				break; // ToDS
			case 2:
				memcpy(bssid, h80211 + 10, sizeof(bssid));
				break; // FromDS
			case 3:
				wds = true;
				if (memcmp(opt.bssid, ZERO, 6) != 0)
				{
					/* BSSID has been specified */
					if (memcmp(opt.bssid, h80211 + 4, 6) != 0)
						if (memcmp(opt.bssid, h80211 + 10, 6) != 0)
							/* BSSID doesn't match either RA nor TA */
							continue;
						else
							/* BSSID is equal to TA */
							memcpy(bssid, h80211 + 10, sizeof(bssid));
					else
						/* BSSID is equal to RA */
						memcpy(bssid, h80211 + 4, sizeof(bssid));
				}
				else
					/* BSSID has not been specified, set BSSID from TA*/
					memcpy(bssid, h80211 + 10, sizeof(bssid));
				break; // WDS
		}

		if (memcmp(opt.bssid, ZERO, 6) != 0)
			if (memcmp(opt.bssid, bssid, 6) != 0) continue;

		/* locate the station's MAC address */

		switch (*(h80211 + 1) & 3)
		{
			case 1:
				memcpy(stmac, h80211 + 10, sizeof(stmac)); //-V525
				break;
			case 2:
				memcpy(stmac, h80211 + 4, sizeof(stmac));
				break;
			case 3:
				if (memcmp(opt.bssid, ZERO, 6) != 0)
				{
					/* BSSID has been specified */
					if (memcmp(bssid, h80211 + 4, 6) != 0)
						/* BSSID is not RA, STA must be RA */
						memcpy(stmac, h80211 + 4, sizeof(stmac));
				}
				else
					/* BSSID is RA or not specified, set STA from TA */
					memcpy(stmac, h80211 + 10, sizeof(stmac));
				break; // WDS
			default:
				continue;
		}

		int not_found = c_avl_get(stations, stmac, (void **) &st_cur);

		/* if it's a new station, add it */

		if (not_found)
		{
			if (!(st_cur
				  = (struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info))))
			{
				perror("malloc failed");
				break;
			}

			memset(st_cur, 0, sizeof(struct WPA_ST_info));

			memcpy(st_cur->stmac, stmac, sizeof(st_cur->stmac));
			memcpy(st_cur->bssid, bssid, sizeof(st_cur->bssid));
			c_avl_insert(stations, st_cur->stmac, st_cur);
			stats.nb_stations++;
		}

		ALLEGE(st_cur != NULL);

		/* check if we haven't already processed this packet */

		crc = calc_crc_buf(h80211 + z, pkh.caplen - z);

		if ((*(h80211 + 1) & 3) == 2)
		{
			if (st_cur->t_crc == crc) continue;

			st_cur->t_crc = crc;
		}
		else
		{
			if (st_cur->f_crc == crc) continue;

			st_cur->f_crc = crc;
		}

		/* check the SNAP header to see if data is encrypted *
		 * as unencrypted data begins with AA AA 03 00 00 00 */

		if (h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03)
		{
			/* check the extended IV flag */

			if ((h80211[z + 3] & 0x20) == 0)
			{
				unsigned char K[64];

				stats.nb_wep++;

				if (opt.crypt != CRYPT_WEP) continue;

				memcpy(K, h80211 + z, 3);
				memcpy(K + 3, opt.wepkey, opt.weplen);

				if (opt.store_bad) memcpy(buffer2, h80211, pkh.caplen);

				if (decrypt_wep(
						h80211 + z + 4, pkh.caplen - z - 4, K, 3 + opt.weplen)
					== 0)
				{
					if (opt.store_bad)
					{
						stats.nb_bad++;
						memcpy(h80211, buffer2, pkh.caplen);
						if (write_packet(f_bad, &pkh, h80211) != 0) break;
					}
					continue;
				}

				/* WEP data packet was successfully decrypted, *
				 * remove the WEP IV & ICV and write the data  */

				pkh.len -= 8;
				pkh.caplen -= 8;

				memmove(h80211 + z, h80211 + z + 4, pkh.caplen - z);

				stats.nb_unwep++;

				*(h80211 + 1) &= 0xBF;

				if (write_packet(f_out, &pkh, h80211) != 0) break;
			}
			else
			{
				stats.nb_wpa++;

				if (opt.crypt != CRYPT_WPA) continue;

				/* if the PTK is valid, try to decrypt */

				if (!st_cur->valid_ptk) continue;

				if (st_cur->keyver == 1)
				{
					if (decrypt_tkip(h80211, pkh.caplen, st_cur->ptk + 32) == 0)
					{
						stats.nb_failed_tkip++;
						continue;
					}

					pkh.len -= 20;
					pkh.caplen -= 20;
				}
				else if (st_cur->keyver == 2)
				{
					if (decrypt_ccmp(h80211, pkh.caplen, st_cur->ptk + 32) == 0)
					{
						stats.nb_failed_ccmp++;
						continue;
					}

					pkh.len -= 16;
					pkh.caplen -= 16;
				}
				else
				{
					fprintf(stderr, "unsupported keyver: %d\n", st_cur->keyver);
					continue;
				}

				/* WPA data packet was successfully decrypted, *
				 * remove the WPA Ext.IV & MIC, write the data */

				if (pkh.caplen > z)
				{
					/* can overlap */
					memmove(h80211 + z, h80211 + z + 8, pkh.caplen - z);
				}
				else
				{
					/* overflow */
					continue;
				}

				stats.nb_unwpa++;

				*(h80211 + 1) &= 0xBF;

				if (write_packet(f_out, &pkh, h80211) != 0) break;
			}
		}
		else
		{
			/* check ethertype == EAPOL */

			z += 6;

			if (h80211[z] != 0x88 || h80211[z + 1] != 0x8E)
			{
				stats.nb_plain++;

				if (opt.crypt != CRYPT_NONE) continue;

				if (write_packet(f_out, &pkh, h80211) != 0)
					break;
				else
					continue;
			}

			z += 2;

			/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

			if (h80211[z + 1] != 0x03
				|| (h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02))
				continue;

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) == 0)
			{
				/* set authenticator nonce */

				memcpy(st_cur->anonce, &h80211[z + 17], 32);
			}

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) == 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					/* set supplicant nonce */

					memcpy(st_cur->snonce, &h80211[z + 17], 32);
				}

				/* copy the MIC & eapol frame */

				st_cur->eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;

				if (pkh.len - z < st_cur->eapol_size
					|| st_cur->eapol_size == 0 //-V560
					|| st_cur->eapol_size > sizeof(st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					st_cur->eapol_size = 0;
					continue;
				}

				memcpy(st_cur->keymic, &h80211[z + 81], 16); //-V512
				memcpy(st_cur->eapol, &h80211[z], st_cur->eapol_size);
				memset(st_cur->eapol + 81, 0, 16);

				/* copy the key descriptor version */

				st_cur->keyver = h80211[z + 6] & 7;
			}

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					/* set authenticator nonce */

					memcpy(st_cur->anonce, &h80211[z + 17], 32);
				}

				/* copy the MIC & eapol frame */

				st_cur->eapol_size = (h80211[z + 2] << 8) + h80211[z + 3] + 4;

				if (pkh.len - z < st_cur->eapol_size
					|| st_cur->eapol_size == 0 //-V560
					|| st_cur->eapol_size > sizeof(st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					st_cur->eapol_size = 0;
					continue;
				}

				memcpy(st_cur->keymic, &h80211[z + 81], sizeof(st_cur->keymic));
				memcpy(st_cur->eapol, &h80211[z], st_cur->eapol_size);
				memset(
					st_cur->eapol + 81,
					0,
					16); // where does this size come from? eapol is char[256]

				/* copy the key descriptor version */

				st_cur->keyver = h80211[z + 6] & 7;
			}

			memcpy(st_cur->bssid, bssid, sizeof(st_cur->bssid));
			st_cur->valid_ptk = calc_ptk(st_cur, opt.pmk);
		}
	}

	/* cleanup avl tree */
	void *key, *value;
	while (c_avl_pick(stations, &key, &value) == 0)
	{
		free(value);
	}
	c_avl_destroy(stations);

	fclose(f_in);
	fclose(f_out);
	if (f_bad != NULL) fclose(f_bad);

	/* write some statistics */

	erase_line(2);
	printf("Total number of stations seen     %8lu\n"
		   "Total number of packets read      %8lu\n"
		   "Total number of WEP data packets  %8lu\n"
		   "Total number of WPA data packets  %8lu\n"
		   "Number of plaintext data packets  %8lu\n"
		   "Number of decrypted WEP  packets  %8lu\n"
		   "Number of corrupted WEP  packets  %8lu\n"
		   "Number of decrypted WPA  packets  %8lu\n"
		   "Number of bad TKIP (WPA) packets  %8lu\n"
		   "Number of bad CCMP (WPA) packets  %8lu\n",
		   stats.nb_stations,
		   stats.nb_read,
		   stats.nb_wep,
		   stats.nb_wpa,
		   stats.nb_plain,
		   stats.nb_unwep,
		   stats.nb_bad,
		   stats.nb_unwpa,
		   stats.nb_failed_tkip,
		   stats.nb_failed_ccmp);
	if (!memcmp(opt.bssid, ZERO, 6) && wds)
		printf("Warning: WDS packets detected, but no BSSID specified\n");

	return (EXIT_SUCCESS);
}
