/*
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef _AIRODUMP_NG_H_
#define _AIRODUMP_NG_H_

#include "eapol.h"
#include "pcap.h"
#include <sys/ioctl.h>
#if !defined(TIOCGWINSZ) && !defined(linux)
#include <sys/termios.h>
#endif

/* some constants */

#define REFRESH_RATE 100000 /* default delay in us between updates */
#define DEFAULT_HOPFREQ 250 /* default delay in ms between channel hopping */
#define DEFAULT_CWIDTH 20 /* 20 MHz channels by default */

#define NB_PWR 5 /* size of signal power ring buffer */
#define NB_PRB 10 /* size of probed ESSID ring buffer */

#define MAX_CARDS 8 /* maximum number of cards to capture from */

#define STD_OPN 0x0001
#define STD_WEP 0x0002
#define STD_WPA 0x0004
#define STD_WPA2 0x0008

#define STD_FIELD (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define ENC_WEP 0x0010
#define ENC_TKIP 0x0020
#define ENC_WRAP 0x0040
#define ENC_CCMP 0x0080
#define ENC_WEP40 0x1000
#define ENC_WEP104 0x0100
#define ENC_GCMP 0x4000

#define ENC_FIELD                                                              \
	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104         \
	 | ENC_GCMP)

#define AUTH_OPN 0x0200
#define AUTH_PSK 0x0400
#define AUTH_MGT 0x0800

#define AUTH_FIELD (AUTH_OPN | AUTH_PSK | AUTH_MGT)

#define STD_QOS 0x2000

#define QLT_TIME 5
#define QLT_COUNT 25

#define SORT_BY_NOTHING 0
#define SORT_BY_BSSID 1
#define SORT_BY_POWER 2
#define SORT_BY_BEACON 3
#define SORT_BY_DATA 4
#define SORT_BY_PRATE 5
#define SORT_BY_CHAN 6
#define SORT_BY_MBIT 7
#define SORT_BY_ENC 8
#define SORT_BY_CIPHER 9
#define SORT_BY_AUTH 10
#define SORT_BY_ESSID 11
#define MAX_SORT 11

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

// milliseconds to store last packets
#define BUFFER_TIME 3000

extern int get_ram_size(void);

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

#define MIN_RAM_SIZE_LOAD_OUI_RAM 32768

/* linked list of received packets for the last few seconds */
struct pkt_buf
{
	struct pkt_buf * next; /* next packet in list */
	unsigned char * packet; /* packet */
	unsigned short length; /* packet length */
	struct timeval ctime; /* capture time */
};

/* oui struct for list management */
struct oui
{
	char id[9]; /* TODO: Don't use ASCII chars to compare, use unsigned char[3]
				   (later) with the value (hex ascii will have to be converted)
				   */
	char
		manuf[128]; /* TODO: Switch to a char * later to improve memory usage */
	struct oui * next;
};

/* WPS_info struct */
struct WPS_info
{
	unsigned char version; /* WPS Version */
	unsigned char state; /* Current WPS state */
	unsigned char ap_setup_locked; /* AP setup locked */
	unsigned int meth; /* WPS Config Methods */
};

#define MAX_AC_MCS_INDEX 8

/* 802.11n channel information */
struct n_channel_info
{
	char mcs_index; /* Maximum MCS TX index     */
	char sec_channel; /* 802.11n secondary channel*/
	unsigned char short_gi_20; /* Short GI for 20MHz       */
	unsigned char short_gi_40; /* Short GI for 40MHz       */
	unsigned char any_chan_width; /* Support for 20 or 40MHz
									as opposed to only 20 or
									only 40MHz               */
};

/* 802.11ac channel information */
struct ac_channel_info
{
	unsigned char center_sgmt[2];
	/* 802.11ac Center segment 0*/
	unsigned char mu_mimo; /* MU-MIMO support          */
	unsigned char short_gi_80; /* Short GI for 80MHz       */
	unsigned char short_gi_160; /* Short GI for 160MHz      */
	unsigned char split_chan; /* 80+80MHz Channel support */
	unsigned char mhz_160_chan; /* 160 MHz channel support  */
	unsigned char wave_2; /* Wave 2                   */
	unsigned char mcs_index[MAX_AC_MCS_INDEX];
	/* Maximum TX rate          */
};

enum channel_width_enum
{
	CHANNEL_UNKNOWN_WIDTH,
	CHANNEL_3MHZ,
	CHANNEL_5MHZ,
	CHANNEL_10MHZ,
	CHANNEL_20MHZ,
	CHANNEL_22MHZ,
	CHANNEL_30MHZ,
	CHANNEL_20_OR_40MHZ,
	CHANNEL_40MHZ,
	CHANNEL_80MHZ,
	CHANNEL_80_80MHZ,
	CHANNEL_160MHZ
};

/* linked list of detected access points */
struct AP_info
{
	struct AP_info * prev; /* prev. AP in list         */
	struct AP_info * next; /* next  AP in list         */

	time_t tinit, tlast; /* first and last time seen */

	int channel; /* AP radio channel         */
	enum channel_width_enum channel_width; /* Channel width            */
	char standard[3]; /* 802.11 standard: n or ac */
	struct n_channel_info n_channel; /* 802.11n channel info     */
	struct ac_channel_info ac_channel; /* 802.11ac channel info    */
	int max_speed; /* AP maximum speed in Mb/s */
	int avg_power; /* averaged signal power    */
	int best_power; /* best signal power    */
	int power_index; /* index in power ring buf. */
	int power_lvl[NB_PWR]; /* signal power ring buffer */
	int preamble; /* 0 = long, 1 = short      */
	int security; /* ENC_*, AUTH_*, STD_*     */
	int beacon_logged; /* We need 1 beacon per AP  */
	int dict_started; /* 1 if dict attack started */
	int ssid_length; /* length of ssid           */
	float gps_loc_min[5]; /* min gps coordinates      */
	float gps_loc_max[5]; /* max gps coordinates      */
	float gps_loc_best[5]; /* best gps coordinates     */

	unsigned long nb_bcn; /* total number of beacons  */
	unsigned long nb_pkt; /* total number of packets  */
	unsigned long nb_data; /* number of  data packets  */
	unsigned long nb_data_old; /* number of data packets/sec*/
	int nb_dataps; /* number of data packets/sec*/
	struct timeval tv; /* time for data per second */

	unsigned char bssid[6]; /* the access point's MAC   */
	char * manuf; /* the access point's manufacturer */
	unsigned char essid[MAX_IE_ELEMENT_SIZE];
	/* ascii network identifier */
	unsigned long long timestamp;
	/* Timestamp to calculate uptime   */

	unsigned char lanip[4]; /* last detected ip address */
	/* if non-encrypted network */

	unsigned char ** uiv_root; /* unique iv root structure */
	/* if wep-encrypted network */

	int rx_quality; /* percent of captured beacons */
	int fcapt; /* amount of captured frames   */
	int fmiss; /* amount of missed frames     */
	unsigned int last_seq; /* last sequence number        */
	struct timeval ftimef; /* time of first frame         */
	struct timeval ftimel; /* time of last frame          */
	struct timeval ftimer; /* time of restart             */

	char * key; /* if wep-key found by dict */
	int essid_stored; /* essid stored in ivs file? */

	char decloak_detect; /* run decloak detection? */
	struct pkt_buf * packets; /* list of captured packets (last few seconds) */
	char is_decloak; /* detected decloak */

	// This feature eats 48Mb per AP
	int EAP_detected;
	unsigned char * data_root; /* first 2 bytes of data if */
	/* WEP network; used for    */
	/* detecting WEP cloak	  */
	/* + one byte to indicate   */
	/* (in)existence of the IV  */

	int marked;
	int marked_color;
	struct WPS_info wps;
};

/* linked list of detected clients */

struct ST_info
{
	struct ST_info * prev; /* the prev client in list   */
	struct ST_info * next; /* the next client in list   */
	struct AP_info * base; /* AP this client belongs to */
	time_t tinit, tlast; /* first and last time seen  */
	unsigned long nb_pkt; /* total number of packets   */
	unsigned char stmac[6]; /* the client's MAC address  */
	char * manuf; /* the client's manufacturer */
	int probe_index; /* probed ESSIDs ring index  */
	char probes[NB_PRB][MAX_IE_ELEMENT_SIZE];
	/* probed ESSIDs ring buffer */
	int ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
	int power; /* last signal power         */
	int best_power; /* best signal power    */
	int rate_to; /* last bitrate to station   */
	int rate_from; /* last bitrate from station */
	struct timeval ftimer; /* time of restart           */
	int missed; /* number of missed packets  */
	unsigned int lastseq; /* last seen sequence number */
	struct WPA_hdsk wpa; /* WPA handshake data        */
	int qos_to_ds; /* does it use 802.11e to ds */
	int qos_fr_ds; /* does it receive 802.11e   */
	int channel; /* Channel station is seen   */
	float gps_loc_min[5]; /* min gps coordinates      */
	float gps_loc_max[5]; /* max gps coordinates      */
	float gps_loc_best[5]; /* best gps coordinates     */
	/*  Not used yet		  */
};

/* linked list of detected macs through ack, cts or rts frames */

struct NA_info
{
	struct NA_info * prev; /* the prev client in list   */
	struct NA_info * next; /* the next client in list   */
	time_t tinit, tlast; /* first and last time seen  */
	unsigned char namac[6]; /* the stations MAC address  */
	int power; /* last signal power         */
	int channel; /* captured on channel       */
	int ack; /* number of ACK frames      */
	int ack_old; /* old number of ACK frames  */
	int ackps; /* number of ACK frames/s    */
	int cts; /* number of CTS frames      */
	int rts_r; /* number of RTS frames (rx) */
	int rts_t; /* number of RTS frames (tx) */
	int other; /* number of other frames    */
	struct timeval tv; /* time for ack per second   */
};

#endif
