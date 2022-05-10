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

#include <aircrack-ng/ce-wpa/crypto_engine.h>
#include <aircrack-ng/adt/avl_tree.h>
#include <aircrack-ng/support/pcap_local.h>
#include <aircrack-ng/ptw/aircrack-ptw-lib.h>

#ifndef AIRCRACK_NG_STATION_H
#define AIRCRACK_NG_STATION_H

#define NB_PRB 10 /* size of probed ESSID ring buffer */

#define NB_PWR 5 /* size of signal power ring buffer */

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

/** linked list of detected access points. */
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
	unsigned int security; /* ENC_*, AUTH_*, STD_*     */
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
	char * manuf; /* the access point's manufacturer */
	unsigned long long timestamp; /* Timestamp to calculate uptime   */

	uint8_t bssid[6]; /* access point MAC address     */
	uint8_t essid[ESSID_LENGTH + 1]; /* access point identifier      */
	uint8_t lanip[4]; /* IP address if unencrypted    */
	uint8_t * ivbuf; /* table holding WEP IV data    */
	uint8_t ** uiv_root; /* IV uniqueness root struct    */
	long ivbuf_size; /* IV buffer allocated size     */
	long nb_ivs; /* total number of unique IVs   */
	long nb_ivs_clean; /* total number of unique IVs   */
	long nb_ivs_vague; /* total number of unique IVs   */
	unsigned int crypt; /* encryption algorithm         */
	int eapol; /* set if EAPOL is present      */
	int target; /* flag set if AP is a target   */
	struct ST_info * st_1st; /* DEPRECATED: linked list of stations */
	c_avl_tree_t * stations; /* AVL tree of stations keyed on MAC*/
	struct WPA_hdsk wpa; /* valid WPA handshake data     */
	PTW_attackstate * ptw_clean;
	PTW_attackstate * ptw_vague;

	int wpa_stored; /* wpa stored in ivs file?   */
	int essid_stored; /* essid stored in ivs file? */

	int rx_quality; /* percent of captured beacons */
	int fcapt; /* amount of captured frames   */
	int fmiss; /* amount of missed frames     */
	unsigned int last_seq; /* last sequence number        */
	struct timeval ftimef; /* time of first frame         */
	struct timeval ftimel; /* time of last frame          */
	struct timeval ftimer; /* time of restart             */

	char * key; /* if wep-key found by dict */

	char decloak_detect; /* run decloak detection? */
	struct pkt_buf * packets; /* list of captured packets (last few seconds) */
	char is_decloak; /* detected decloak */

	// This feature eats 48Mb per AP
	int EAP_detected;
	uint8_t * data_root; /* first 2 bytes of data if */
	/* WEP network; used for    */
	/* detecting WEP cloak	  */
	/* + one byte to indicate   */
	/* (in)existence of the IV  */

	int marked;
	int marked_color;
	struct WPS_info wps;
};

/** linked list of detected clients */
struct ST_info
{
	struct ST_info * prev; /* the prev client in list   */
	struct ST_info * next; /* the next client in list   */
	struct AP_info * base; /* AP this client belongs to */
	uint8_t stmac[6]; /* the client's MAC address  */
	struct WPA_hdsk wpa; /* WPA handshake data        */

	char * manuf; /* the client's manufacturer */

	time_t tinit, tlast; /* first and last time seen  */
	unsigned long nb_pkt; /* total number of packets   */
	uint8_t essid[ESSID_LENGTH + 1]; /* last associated essid     */
	int essid_length; /* essid length of last asso */
	int probe_index; /* probed ESSIDs ring index  */
	char probes[NB_PRB][MAX_IE_ELEMENT_SIZE]; /* probed ESSIDs ring buffer */
	int ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
	int power; /* last signal power         */
	int best_power; /* best signal power    */
	int rate_to; /* last bitrate to station   */
	int rate_from; /* last bitrate from station */
	struct timeval ftimer; /* time of restart           */
	int missed; /* number of missed packets  */
	unsigned int lastseq; /* last seen sequnce number  */
	int wpatype; /* 1=wpa1 2=wpa2             */
	int wpahash; /* 1=md5(tkip) 2=sha1(ccmp)  */
	int wep; /* capability encryption bit */

	int qos_to_ds; /* does it use 802.11e to ds */
	int qos_fr_ds; /* does it receive 802.11e   */
	int channel; /* Channel station is seen   */
	float gps_loc_min[5]; /* min gps coordinates      */
	float gps_loc_max[5]; /* max gps coordinates      */
	float gps_loc_best[5]; /* best gps coordinates     */
};

#endif //AIRCRACK_NG_STATION_H
