/*
 *  Copyright (C) 2011 Andrea Bittau <bittau@cs.stanford.edu>
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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/aircrack-ng.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/ptw/aircrack-ptw-lib.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/support/common.h"

struct packet
{
	struct timespec p_ts;
	unsigned char p_data[2048];
	int p_len;
};

struct client
{
	unsigned char c_mac[6];
	int c_wpa;
	int c_wpa_got;
	struct packet c_handshake[4];
	struct client * c_next;
};

static struct network
{
	unsigned char n_bssid[6];
	unsigned char n_beacon[2048];
	int n_beaconlen;
	char n_ssid[256];
	struct client n_clients;
	struct client * n_handshake;
	struct network * n_next;
} _networks;

static char * _outfilename;
static int _outfd;

static int open_pcap(const char * fname)
{
	REQUIRE(fname != NULL);

	int fd;
	struct pcap_file_header pfh;

	memset(&pfh, 0, sizeof(pfh));
	pfh.magic = TCPDUMP_MAGIC;
	pfh.version_major = PCAP_VERSION_MAJOR;
	pfh.version_minor = PCAP_VERSION_MINOR;
	pfh.thiszone = 0;
	pfh.sigfigs = 0;
	pfh.snaplen = 65535;
	pfh.linktype = LINKTYPE_IEEE802_11;

	fd = open(fname,
			  O_WRONLY | O_CREAT | O_TRUNC,
			  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) err(1, "open(%s)", fname);

	if (write(fd, &pfh, sizeof(pfh)) != sizeof(pfh)) err(1, "write()");

	return (fd);
}

static inline void
write_pcap(int fd, const struct timespec * ts, const void * p, const int len)
{
	REQUIRE(p != NULL);

	struct pcap_pkthdr pkh;

	memset(&pkh, 0, sizeof(pkh));

	pkh.caplen = pkh.len = len;
	pkh.tv_sec = ts->tv_sec;
	pkh.tv_usec = ts->tv_nsec / 1000UL;

	if (write(fd, &pkh, sizeof(pkh)) != sizeof(pkh)) err(1, "write()");

	if (write(fd, p, len) != len) err(1, "write()");
}

static inline void packet_write_pcap(int fd, const struct packet * p)
{
	write_pcap(fd, &p->p_ts, p->p_data, p->p_len);
}

static void print_network(const struct network * n)
{
	REQUIRE(n != NULL);

	printf("Net %.2x:%.2x:%.2x:%.2x:%.2x:%.2x %s\n",
		   n->n_bssid[0],
		   n->n_bssid[1],
		   n->n_bssid[2],
		   n->n_bssid[3],
		   n->n_bssid[4],
		   n->n_bssid[5],
		   n->n_ssid);
}

static void save_network(const struct timespec * ts, const struct network * n)
{
	REQUIRE(n != NULL);

	int i;

	if (_outfd == 0)
	{
		_outfd = open_pcap(_outfilename);
	}
	write_pcap(_outfd, ts, n->n_beacon, n->n_beaconlen);

	for (i = 0; i < 4; i++)
	{
		struct packet * p = &n->n_handshake->c_handshake[i];

		ALLEGE(p != NULL); //-V547

		if (p->p_len) packet_write_pcap(_outfd, p);
	}
}

static void fix_beacon(struct network * n)
{
	REQUIRE(n != NULL);

	unsigned char * p;
	int ssidlen;
	int origlen;

	/* beacon surgery */
	p = n->n_beacon + sizeof(struct ieee80211_frame) + 8 + 2 + 2;

	ssidlen = strlen(n->n_ssid);
	ALLEGE((n->n_beaconlen + ssidlen) <= (int) sizeof(n->n_beacon));

	ALLEGE(*p == IEEE80211_ELEMID_SSID);
	p++;

	if (*p != 0 && p[1] != 0) return;

	origlen = *p;
	*p++ = ssidlen;

	ALLEGE(origlen == 0 || p[0] == 0);

	memmove(
		p + ssidlen, p + origlen, n->n_beaconlen - (p + origlen - n->n_beacon));
	memcpy(p, n->n_ssid, ssidlen);

	n->n_beaconlen += ssidlen - origlen;
}

static void check_network(struct timespec * ts, int * dlt, struct network * n)
{
	UNUSED_PARAM(dlt);
	REQUIRE(n != NULL);

	if (!n->n_beaconlen || !n->n_handshake || !n->n_ssid[0]) return;

	fix_beacon(n);

	print_network(n);

	save_network(ts, n);
}

static inline struct network * find_net(const unsigned char * b)
{
	REQUIRE(b != NULL);

	struct network * n = _networks.n_next;

	while (n)
	{
		if (memcmp(b, n->n_bssid, sizeof(n->n_bssid)) == 0) return (n);

		n = n->n_next;
	}

	return (NULL);
}

static inline struct network * net_add(const unsigned char * bssid)
{
	REQUIRE(bssid != NULL);

	struct network * n = malloc(sizeof(*n));

	if (!n) err(1, "malloc()");

	memset(n, 0, sizeof(*n));

	memcpy(n->n_bssid, bssid, sizeof(n->n_bssid));

	n->n_next = _networks.n_next;
	_networks.n_next = n;

	return (n);
}

static inline struct network * find_add_net(const unsigned char * bssid)
{
	struct network * n;

	n = find_net(bssid);
	if (n) return (n);

	return (net_add(bssid));
}

static inline struct client * find_client(const struct network * n,
										  const unsigned char * mac)
{
	REQUIRE(n != NULL);

	struct client * c = n->n_clients.c_next;

	while (c)
	{
		if (memcmp(c->c_mac, mac, sizeof(c->c_mac)) == 0) return (c);

		c = c->c_next;
	}

	return (NULL);
}

static struct client * find_add_client(struct network * n,
									   const unsigned char * mac)
{
	struct client * c;

	c = find_client(n, mac);
	if (c) return (c);

	c = malloc(sizeof(*c));
	if (!c) err(1, "malloc()");

	memset(c, 0, sizeof(*c));

	memcpy(c->c_mac, mac, sizeof(c->c_mac));

	c->c_next = n->n_clients.c_next;
	n->n_clients.c_next = c;

	return (c);
}

static int parse_rsn(const unsigned char * p, const int l, const int rsn)
{
	REQUIRE(p != NULL);

	int c;
	const unsigned char * start = p;
	int psk = 0;
	int wpa = 0;

	if (l < 2) return (0);

	if (memcmp(p, "\x01\x00", 2) != 0) return (0);

	wpa = 1;

	if (l < 8) return (-1);

	p += 2;
	p += 4;

	/* cipher */
	c = le16toh(*((uint16_t *) p));

	p += 2 + 4 * c;

	if (l < ((p - start) + 2)) return (-1);

	/* auth */
	c = le16toh(*((uint16_t *) p));
	p += 2;

	if (l < ((p - start) + c * 4)) return (-1);

	while (c--)
	{
		if (rsn && memcmp(p, "\x00\x0f\xac\x02", 4) == 0) psk = 1;

		if (!rsn && memcmp(p, "\x00\x50\xf2\x02", 4) == 0) psk = 1;

		p += 4;
	}

	ALLEGE(l >= (p - start));

	if (!psk) wpa = 0;

	return (wpa);
}

static int parse_elem_vendor(const unsigned char * e, const int l)
{
	REQUIRE(e != NULL);

	const struct ieee80211_ie_wpa * wpa = (const struct ieee80211_ie_wpa *) e;

	if (l < 5) return (0);

	if (memcmp(wpa->wpa_oui, "\x00\x50\xf2", 3) != 0) return (0);

	if (l < 8) return (0);

	if (wpa->wpa_type != WPA_OUI_TYPE) return (0);

	return (parse_rsn((unsigned char *) &wpa->wpa_version, l - 6, 0));
}

static void process_beacon(struct timespec * ts,
						   int * dlt,
						   struct ieee80211_frame * wh,
						   int totlen)
{
	REQUIRE(wh != NULL);

	unsigned char * p = (unsigned char *) (wh + 1);
	int bhlen = 8 + 2 + 2;
	int len = totlen;
	char ssid[256];
	int wpa = 0;
	int rc;
	int ssids = 0;
	struct network * n;

	totlen -= sizeof(*wh);

	if (totlen < bhlen) goto __bad;

	if (!(IEEE80211_BEACON_CAPABILITY(p) & IEEE80211_CAPINFO_PRIVACY)) return;

	p += bhlen;
	totlen -= bhlen;

	ssid[0] = 0;

	while (totlen > 2)
	{
		int id = *p++;
		int l = *p++;

		totlen -= 2;

		if (totlen < l) goto __bad;

		switch (id)
		{
			case IEEE80211_ELEMID_SSID:
				if (++ssids > 1) break;

				if (!(l == 0 || p[0] == 0))
				{
					memcpy(ssid, p, l);
					ssid[l] = 0;
				}
				break;

			case IEEE80211_ELEMID_VENDOR:
				if ((rc = parse_elem_vendor(&p[-2], l + 2)) == -1) goto __bad;

				if (rc) wpa = 1;
				break;

			case IEEE80211_ELEMID_RSN:
				if ((rc = parse_rsn(p, l, 1)) == -1) goto __bad;

				if (rc) wpa = 1;
				break;
		}

		p += l;
		totlen -= l;
	}

	if (!wpa) return;

	n = find_add_net(wh->i_addr3);

	if (n->n_beaconlen) return;

	n->n_beaconlen = len;
	ALLEGE(n->n_beaconlen <= (int) sizeof(n->n_beacon));
	memcpy(n->n_beacon, wh, n->n_beaconlen);
	strncpy(n->n_ssid, ssid, sizeof(n->n_ssid));
	(n->n_ssid)[sizeof(n->n_ssid) - 1] = '\0';

	check_network(ts, dlt, n);
	return;
__bad:
	printf("bad beacon\n");
}

static void packet_copy(struct packet * p,
						struct timespec * ts,
						const void * d,
						const int len)
{
	REQUIRE(p != NULL);
	REQUIRE(len <= (int) sizeof(p->p_data));

	if (ts)
	{
		p->p_ts.tv_sec = ts->tv_sec;
		p->p_ts.tv_nsec = ts->tv_nsec;
	}
	p->p_len = len;
	memcpy(p->p_data, d, len);
}

static void process_eapol(struct timespec * ts,
						  int * dlt,
						  struct network * n,
						  struct client * c,
						  const unsigned char * p,
						  const int len,
						  struct ieee80211_frame * wh,
						  const int totlen)
{
	UNUSED_PARAM(dlt);

	int num, i;

	num = eapol_handshake_step(p, len);
	if (num == 0) return;

	REQUIRE(c != NULL);

	/* reset... should use time, too.  XXX conservative - check retry */
	if (c->c_wpa == 0 || num <= c->c_wpa)
	{
		for (i = 0; i < 4; i++) c->c_handshake[i].p_len = 0;

		c->c_wpa_got = 0;
	}

	c->c_wpa = num;

	switch (num)
	{
		case 1:
			c->c_wpa_got |= 1;
			break;

		case 2:
			c->c_wpa_got |= 2;
			c->c_wpa_got |= 4;
			break;

		case 3:
			REQUIRE(p != NULL);
			if (memcmp(&p[17], ZERO, 32) != 0) c->c_wpa_got |= 1;

			c->c_wpa_got |= 4;
			break;

		case 4:
			REQUIRE(p != NULL);
			if (memcmp(&p[17], ZERO, 32) != 0) c->c_wpa_got |= 2;

			c->c_wpa_got |= 4;
			break;

		default:
			abort();
	}

	packet_copy(&c->c_handshake[num - 1], ts, wh, totlen);

	if (c->c_wpa_got == 7)
	{
		REQUIRE(n != NULL);

		n->n_handshake = c;
	}
}

static void process_data(struct timespec * ts,
						 int * dlt,
						 struct ieee80211_frame * wh,
						 int len)
{
	REQUIRE(wh != NULL);

	unsigned char * p = (unsigned char *) (wh + 1);
	struct llc * llc;
	int wep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	int eapol = 0;
	struct client * c;
	int stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	int orig = len;
	unsigned char *bssid, *clientaddr;
	struct network * n;

	len -= sizeof(*wh);

	if (stype == IEEE80211_FC0_SUBTYPE_QOS)
	{
		p += 2;
		len -= 2;
	}

	if (!wep && len >= 8)
	{
		llc = (struct llc *) p;

		eapol = memcmp(llc, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8) == 0;

		p += 8;
		len -= 8;
	}

	if (!eapol) return;

	if (len < 5) return;

	/* type == key */
	if (p[1] != 0x03) return;

	/* desc == WPA or RSN */
	if (p[4] != 0xFE && p[4] != 0x02) return;

	bssid = wh->i_addr1;
	clientaddr = wh->i_addr2;

	if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
	{
		bssid = wh->i_addr2;
		clientaddr = wh->i_addr1;
	}
	else if (!(wh->i_fc[1] & IEEE80211_FC1_DIR_TODS))
		bssid = wh->i_addr3; /* IBSS */

	n = find_add_net(bssid);

	if (n->n_handshake) return;

	c = find_add_client(n, clientaddr);

	process_eapol(ts, dlt, n, c, p, len, wh, orig);

	if (n->n_handshake) check_network(ts, dlt, n);
}

static void grab_hidden_ssid(struct timespec * ts,
							 int * dlt,
							 const unsigned char * bssid,
							 struct ieee80211_frame * wh,
							 int len,
							 const int off)
{
	REQUIRE(wh != NULL);

	struct network * n;
	unsigned char * p = ((unsigned char *) (wh + 1)) + off;
	int l;

	n = find_net(bssid);
	if (n && n->n_ssid[0]) return;

	len -= sizeof(*wh) + off + 2;

	if (len < 0) goto __bad;

	if (*p++ != IEEE80211_ELEMID_SSID) goto __bad;

	l = *p++;
	if (l > len) goto __bad;

	if (l == 0) return;

	if (!n) n = net_add(bssid);

	memcpy(n->n_ssid, p, l);
	n->n_ssid[l] = 0;

	check_network(ts, dlt, n);
	return;

__bad:
	printf("bad grab_hidden_ssid\n");
	return;
}

static void
process_packet(struct timespec * ts, int * dlt, void * packet, const int len)
{
	REQUIRE(packet != NULL);

	struct ieee80211_frame * wh = (struct ieee80211_frame *) packet;

	if (len < (int) sizeof(*wh)) return;

	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)
	{
		case IEEE80211_FC0_TYPE_MGT:
			switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
			{
				case IEEE80211_FC0_SUBTYPE_BEACON:
					process_beacon(ts, dlt, wh, len);
					break;

				case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
					grab_hidden_ssid(ts, dlt, wh->i_addr3, wh, len, 2 + 2);
					break;

				case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
					grab_hidden_ssid(ts, dlt, wh->i_addr3, wh, len, 2 + 2 + 6);
					break;

				case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
					grab_hidden_ssid(ts, dlt, wh->i_addr3, wh, len, 8 + 2 + 2);
					break;
			}
			break;

		case IEEE80211_FC0_TYPE_DATA:
			process_data(ts, dlt, wh, len);
			break;
	}
}

static void pwn(const char * fname)
{
	REQUIRE(fname != NULL);

	struct wif * wi;
	struct timespec ts;
	int dlt;
	char crap[2048];
	int rc;

	if (strlen(fname) + 7 >= sizeof(crap))
	{
		printf("Filename too long, aborting\n");
		return;
	}

	memset(crap, 0, sizeof(crap));
	snprintf(crap, sizeof(crap), "file://%s", fname);

	wi = wi_open(crap);
	if (!wi)
	{
		printf("Bad file - skipping %s\n", fname);
		return;
	}

	while ((rc = wi_read(
				wi, &ts, &dlt, (unsigned char *) crap, sizeof(crap), NULL))
		   > 0)
		process_packet(&ts, &dlt, crap, rc);

	wi_close(wi);
}

static void free_data(void)
{
	struct network * nets = _networks.n_next;
	while (nets)
	{
		// Free clients
		struct client * clients = nets->n_handshake;
		while (clients)
		{
			struct client * client_prev = clients;
			clients = clients->c_next;
			free(client_prev);
		}

		// Free net
		struct network * net_prev = nets;
		nets = nets->n_next;
		free(net_prev);
	}

	free(_outfilename);
}

int main(int argc, char * argv[])
{
	if (argc < 3)
	{
		printf("Usage: %s <out.cap> <in.cap> [in2.cap] [...]\n", argv[0]);
		return (EXIT_FAILURE);
	}

	_outfilename = strdup(argv[1]);
	if (_outfilename == NULL)
	{
		perror("strdup()");
		return (EXIT_FAILURE);
	}

	for (int i = 2; i < argc; i++)
	{
		const char * in = argv[i];
		int prog = (int) (((double) (i - 1)) / ((double) (argc - 2))
#if defined(__x86_64__) && defined(__CYGWIN__)
						  * (0.0f + 100));
#else
						  * 100.0);
#endif

		printf("Pwning %s (%d/%d %d%%)\n", in, i - 1, argc - 2, prog);
		fflush(stdout);

		pwn(in);
	}

	// Cleanup
	free_data();

	printf("Done\n");
	exit(EXIT_SUCCESS);
}
