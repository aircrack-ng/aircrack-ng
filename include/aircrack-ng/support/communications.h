/*
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2006-2009 Martin Beck <martin.beck2@gmx.de>
 *  Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
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

#ifndef AIRCRACK_NG_COMMUNICATIONS_H
#define AIRCRACK_NG_COMMUNICATIONS_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <aircrack-ng/defs.h>
#include <aircrack-ng/support/pcap_local.h>
#include <aircrack-ng/osdep/osdep.h>
#include <aircrack-ng/support/common.h>
#include <aircrack-ng/third-party/ieee80211.h>

/* Tagged parameters in beacon-frames */
#define MGNT_PAR_SSID 0x00
#define MGNT_PAR_CHANNEL 0x03
#define MGNT_PAR_HT_INFO 0x3d

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

static const int bitrates[] = {RATE_1M,
							   RATE_2M,
							   RATE_5_5M,
							   RATE_6M,
							   RATE_9M,
							   RATE_11M,
							   RATE_12M,
							   RATE_18M,
							   RATE_24M,
							   RATE_36M,
							   RATE_48M,
							   RATE_54M};

struct communication_options
{
	uint8_t f_bssid[6];
	uint8_t f_dmac[6];
	uint8_t f_smac[6];
	uint8_t f_netmask[6];
	int f_minlen;
	int f_maxlen;
	int f_type;
	int f_subtype;
	int f_tods;
	int f_fromds;
	int f_iswep;

	uint8_t deauth_rc;
	int r_nbpps;
	unsigned int r_fctrl;
	uint8_t r_bssid[6];
	uint8_t r_dmac[6];
	uint8_t r_smac[6];
	uint8_t r_trans[6];
	uint8_t r_dip[4];
	uint8_t r_sip[4];
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
	uint8_t * prga;
	size_t prgalen;

	int a_mode;
	int a_count;
	int a_delay;
	int f_retry;

	int ringbuffer;
	int ghost;

	int delay;
	int npackets;

	int fast;
	int bittest;

	int nodetect;
	int ignore_negative_one;
	int rtc;

	int reassoc;

	int crypt;
	uint8_t wepkey[64];
	size_t weplen;

	int f_index; /* outfiles index       */
	FILE * f_txt; /* output csv file      */
	FILE * f_kis; /* output kismet csv file      */
	FILE * f_kis_xml; /* output kismet netxml file */
	FILE * f_gps; /* output gps file      */
	FILE * f_cap; /* output cap file      */
	FILE * f_ivs; /* output ivs file      */
	FILE * f_xor; /* output prga file     */
	FILE * f_logcsv; /* output rolling AP/GPS csv log */

	char * f_cap_name;
	char * prefix;

	int output_format_pcap;
	int output_format_csv;
	int output_format_kismet_csv;
	int output_format_kismet_netxml;
	int output_format_log_csv;

	int usegpsd; /* do we use GPSd?      */
	int record_data; /* do we record data?   */

	unsigned char sharedkey[3][4096]; /* array for 3 packets with a size of \
							   up to 4096Byte */
	time_t sk_start;
	size_t sk_len;
	size_t sk_len2;

	int quiet;
	int verbose;
};

struct devices
{
	int fd_in, arptype_in;
	int fd_out, arptype_out;
	int fd_rtc;
	struct tif * dv_ti;
	struct tif * dv_ti2;

	uint8_t mac_in[6];
	uint8_t mac_out[6];

	int is_wlanng;
	int is_hostap;
	int is_madwifi;
	int is_madwifing;
	int is_bcm43xx;

	FILE * f_cap_in;

	struct pcap_file_header pfh_in;
};

/* Expects host-endian arguments, but returns little-endian seq. */
static inline uint16_t fnseq(uint16_t fn, uint16_t seq)
{
	uint16_t r = 0;

	if (fn > 15)
	{
		fprintf(stderr, "too many fragments (%d)\n", fn);
		exit(EXIT_FAILURE);
	}

	r = fn;

	r |= ((seq % 4096) << IEEE80211_SEQ_SEQ_SHIFT);

	return (htole16(r));
}

static inline int get_ip_port(char * iface, char * ip, const int ip_size)
{
	REQUIRE(iface != NULL);
	REQUIRE(ip != NULL);
	REQUIRE(ip_size > 0);

	char * host;
	char * ptr;
	int port = -1;
	struct in_addr addr;

	host = strdup(iface);
	if (!host) return (-1);

	ptr = strchr(host, ':');
	if (!ptr) goto out;

	*ptr++ = 0;

	if (!inet_aton(host, (struct in_addr *) &addr))
		goto out; /* XXX resolve hostname */

	if (strlen(host) > 15) goto out;

	strncpy(ip, host, (size_t) ip_size);

	port = (int) strtol(ptr, NULL, 10);
	if (port <= 0 || port > 65535) port = -1;

out:
	free(host);
	return (port);
}

int read_packet(struct wif * wi,
				void * buf,
				uint32_t count,
				struct rx_info * ri);

int wait_for_beacon(struct wif * wi,
					uint8_t * bssid,
					uint8_t * capa,
					char * essid);

int attack_check(uint8_t * bssid,
				 char * essid,
				 uint8_t * capa,
				 struct wif * wi,
				 int ignore_negative_one);

typedef void (*read_sleep_cb)(void);

static inline void read_sleep(int fd_in, unsigned long usec, read_sleep_cb cb)
{
	struct timeval tv, tv2, tv3;
	fd_set rfds;

	gettimeofday(&tv, NULL);
	gettimeofday(&tv2, NULL);

	tv3.tv_sec = 0;
	tv3.tv_usec = 10000;

	while (((tv2.tv_sec * 1000000UL - tv.tv_sec * 1000000UL)
			+ (tv2.tv_usec - tv.tv_usec))
		   < (usec))
	{
		FD_ZERO(&rfds);
		FD_SET(fd_in, &rfds);

		if (select(fd_in + 1, &rfds, NULL, NULL, &tv3) < 0)
		{
			continue;
		}

		if (FD_ISSET(fd_in, &rfds)) cb();

		gettimeofday(&tv2, NULL);
	}
}

extern unsigned long nb_pkt_sent;

enum Send_Packet_Option
{
	kNoChange = 1 << 0,
	kRewriteSequenceNumber = 1 << 1,
	kRewriteDuration = 1 << 2,
};

static inline int send_packet(struct wif * wi,
							  void * buf,
							  size_t count,
							  enum Send_Packet_Option option)
{
	REQUIRE(buf != NULL);
	REQUIRE(count > 0 && count < INT_MAX);
	REQUIRE(option >= kNoChange && option <= kRewriteDuration); //-V1016

	uint8_t * pkt = (uint8_t *) buf;

	if ((option & kRewriteSequenceNumber) != 0 && (count > 24)
		&& (pkt[1] & 0x04) == 0
		&& (pkt[22] & 0x0F) == 0)
	{
		pkt[22] = (uint8_t)((nb_pkt_sent & 0x0000000F) << 4);
		pkt[23] = (uint8_t)((nb_pkt_sent & 0x00000FF0) >> 4);
	}

	if ((option & kRewriteDuration) != 0 && count > 24)
	{
		// Set the duration...
		pkt[2] = 0x3A;
		pkt[3] = 0x01;

		// Reset Retry Flag
		pkt[1] = (uint8_t)(pkt[1] & ~0x4);
	}

	int rc;
	do
	{
		rc = wi_write(wi, NULL, LINKTYPE_IEEE802_11, buf, (int) count, NULL);
		if (rc == -1 && errno == ENOBUFS)
		{
			usleep(10000);
		}
	} while (rc == -1 && (errno == EAGAIN || errno == ENOBUFS));

	if (rc == -1)
	{
		perror("wi_write()");
		return (-1);
	}

	++nb_pkt_sent;

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
		   int nodetect);

int capture_ask_packet(int * caplen, int just_grab);
int filter_packet(unsigned char * h80211, int caplen);

int dump_initialize(char * prefix);
int dump_initialize_multi_format(char * prefix, int ivs_only);

int check_shared_key(const uint8_t * h80211, size_t caplen);
int encrypt_data(uint8_t * data, size_t length);

int create_wep_packet(uint8_t * packet, size_t * length, size_t hdrlen);

int set_clear_arp(uint8_t * buf, uint8_t * smac, uint8_t * dmac);
int set_final_arp(uint8_t * buf, uint8_t * mymac);
int set_clear_ip(uint8_t * buf, size_t ip_len);
int set_final_ip(uint8_t * buf, uint8_t * mymac);
int msleep(int msec);
int read_prga(unsigned char ** dest, char * file);
int set_bitrate(struct wif * wi, int rate);

#endif //AIRCRACK_NG_COMMUNICATIONS_H
