/*
 *  Airodump-ng text files output
 *
 *  Copyright (C) 2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h> // ftruncate
#include <sys/types.h> // ftruncate
#include <sys/time.h>
#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "aircrack-ng/defs.h"
#include "airodump-ng.h"
#include "aircrack-ng/support/communications.h"
#include "dump_write.h"
#include "dump_write_private.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/utf8/verifyssid.h"
#include "dump_write_wifi_scanner.h"
#include "dump_csv.h"
#include "dump_kismet_csv.h"

extern struct communication_options opt;

extern int getFrequencyFromChannel(int channel); // "aircrack-osdep/common.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

int dump_write_airodump_ng_logcsv_add_ap(const struct AP_info * ap_cur,
										 const int32_t ri_power,
										 struct tm * tm_gpstime,
										 float * gps_loc)
{
	if (ap_cur == NULL || !opt.output_format_log_csv || !opt.f_logcsv)
	{
		return (0);
	}

	// Local computer time
	const struct tm * ltime = localtime(&ap_cur->tlast);
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);

	// Gps time
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	// ESSID
	fprintf(opt.f_logcsv, "%s,", ap_cur->essid);

	// BSSID
    fprintf_mac_address(opt.f_logcsv, &ap_cur->bssid);
    fprintf(opt.f_logcsv, ","); 


	// RSSI
	fprintf(opt.f_logcsv, "%d,", ri_power);

	// Network Security
    if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) == 0)
    {
		fputs(" ", opt.f_logcsv);
    }
	else
	{
		if (ap_cur->security & STD_WPA2) fputs(" WPA2 ", opt.f_logcsv);
		if (ap_cur->security & STD_WPA) fputs(" WPA ", opt.f_logcsv);
		if (ap_cur->security & STD_WEP) fputs(" WEP ", opt.f_logcsv);
		if (ap_cur->security & STD_OPN) fputs(" OPN", opt.f_logcsv);
	}

	fputs(",", opt.f_logcsv);

	// Lat, Lon, Lat Error, Lon Error
	fprintf(opt.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,AP\r\n",
			gps_loc[0],
			gps_loc[1],
			gps_loc[5],
			gps_loc[6]);

	return (0);
}

int dump_write_airodump_ng_logcsv_add_client(const struct AP_info * ap_cur,
											 const struct ST_info * st_cur,
											 const int32_t ri_power,
											 struct tm * tm_gpstime,
											 float * gps_loc)
{
	if (st_cur == NULL || !opt.output_format_log_csv || !opt.f_logcsv)
	{
		return (0);
	}

	// Local computer time
	struct tm * ltime = localtime(&ap_cur->tlast);
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);

	// GPS time
	fprintf(opt.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	// Client => No ESSID
	fprintf(opt.f_logcsv, ",");

	// BSSID
    fprintf_mac_address(opt.f_logcsv, &st_cur->stmac);
    fprintf(opt.f_logcsv, ","); 


	// RSSI
	fprintf(opt.f_logcsv, "%d,", ri_power);

	// Client => Network Security: none
	fprintf(opt.f_logcsv, ",");

	// Lat, Lon, Lat Error, Lon Error
	fprintf(opt.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,",
			gps_loc[0],
			gps_loc[1],
			gps_loc[5],
			gps_loc[6]);

	// Type
	fprintf(opt.f_logcsv, "Client\r\n");

	return (0);
}

static char * sanitize_xml(unsigned char * text, size_t length)
{
	size_t i;
	size_t len, current_text_len;
	unsigned char * pos;
	char * newtext = NULL;
	if (text != NULL && length > 0)
	{
		len = 8 * length;
		newtext = (char *) calloc(
			1, (len + 1) * sizeof(char)); // Make sure we have enough space
		ALLEGE(newtext != NULL);
		pos = text;
		for (i = 0; i < length; ++i, ++pos)
		{
			switch (*pos)
			{
				case '&':
					strncat(newtext, "&amp;", len);
					break;
				case '<':
					strncat(newtext, "&lt;", len);
					break;
				case '>':
					strncat(newtext, "&gt;", len);
					break;
				case '\'':
					strncat(newtext, "&apos;", len);
					break;
				case '"':
					strncat(newtext, "&quot;", len);
					break;
				case '\r':
					strncat(newtext, "&#xD;", len);
					break;
				case '\n':
					strncat(newtext, "&#xA;", len);
					break;
				default:
					if (isprint((int) (*pos)))
					{
						newtext[strlen(newtext)] = *pos;
					}
					else
					{
						strncat(newtext, "&#x", len);
						current_text_len = strlen(newtext);
						snprintf(newtext + current_text_len,
								 len - current_text_len + 1,
								 "%4x",
								 *pos);
						strncat(newtext, ";", len);
					}
					break;
			}
		}
		char * tmp_newtext = (char *) realloc(newtext, strlen(newtext) + 1);
		ALLEGE(tmp_newtext != NULL);
		newtext = tmp_newtext;
	}

	return (newtext);
}

#define KISMET_NETXML_HEADER_BEGIN                                             \
	"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE "              \
	"detection-run SYSTEM "                                                    \
	"\"http://kismetwireless.net/kismet-3.1.0.dtd\">\n\n<detection-run "       \
	"kismet-version=\"airodump-ng-1.0\" start-time=\""
#define KISMET_NETXML_HEADER_END "\">\n\n"

#define KISMET_NETXML_TRAILER "</detection-run>"

#define TIME_STR_LENGTH 255
static int dump_write_kismet_netxml_client_info(struct ST_info * client,
												int client_no)
{
	char first_time[TIME_STR_LENGTH];
	char last_time[TIME_STR_LENGTH];
	char * manuf;
	int client_max_rate, average_power, max_power, i, nb_probes_written,
		is_unassociated;
	char * essid = NULL;

	if (client == NULL || (client_no <= 0 || client_no >= INT_MAX))
	{
		return (1);
	}

	is_unassociated = (client->base == NULL
					   || MAC_ADDRESS_IS_BROADCAST(&client->base->bssid));

	strncpy(first_time, ctime(&client->tinit), TIME_STR_LENGTH - 1);
	first_time[strlen(first_time) - 1] = 0; // remove new line

	strncpy(last_time, ctime(&client->tlast), TIME_STR_LENGTH - 1);
	last_time[strlen(last_time) - 1] = 0; // remove new line

	fprintf(opt.f_kis_xml,
			"\t\t<wireless-client number=\"%d\" "
			"type=\"%s\" first-time=\"%s\""
			" last-time=\"%s\">\n",
			client_no,
			(is_unassociated) ? "tods" : "established",
			first_time,
			last_time);

    fprintf(opt.f_kis_xml, "\t\t\t<client-mac>");
    fprintf_mac_address(opt.f_kis_xml, &client->stmac);
    fprintf(opt.f_kis_xml, "</client-mac>\n");

	/* Manufacturer, if set using standard oui list */
	manuf
		= sanitize_xml((unsigned char *)client->manuf, strlen(client->manuf));
	fprintf(opt.f_kis_xml,
			"\t\t\t<client-manuf>%s</client-manuf>\n",
			(manuf != NULL) ? manuf : "Unknown");
	free(manuf);

	/* SSID item, aka Probes */
	nb_probes_written = 0;
	for (i = 0; i < NB_PRB; i++)
	{
		if (client->probes[i][0] == '\0') continue;

		fprintf(opt.f_kis_xml,
				"\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(opt.f_kis_xml,
				"\t\t\t\t<type>Probe Request</type>\n"
				"\t\t\t\t<max-rate>54.000000</max-rate>\n"
				"\t\t\t\t<packets>1</packets>\n"
				"\t\t\t\t<encryption>None</encryption>\n");
		essid = sanitize_xml((unsigned char *) client->probes[i],
							 (size_t) client->ssid_length[i]);
		if (essid != NULL)
		{
			fprintf(opt.f_kis_xml, "\t\t\t\t<ssid>%s</ssid>\n", essid);
			free(essid);
		}

		fprintf(opt.f_kis_xml, "\t\t\t</SSID>\n");

		++nb_probes_written;
	}

	// Unassociated client with broadcast probes
	if (is_unassociated && nb_probes_written == 0)
	{
		fprintf(opt.f_kis_xml,
				"\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(opt.f_kis_xml,
				"\t\t\t\t<type>Probe Request</type>\n"
				"\t\t\t\t<max-rate>54.000000</max-rate>\n"
				"\t\t\t\t<packets>1</packets>\n"
				"\t\t\t\t<encryption>None</encryption>\n");
		fprintf(opt.f_kis_xml, "\t\t\t</SSID>\n");
	}

	/* Channel
	   FIXME: Take opt.freqoption in account */
	fprintf(opt.f_kis_xml, "\t\t\t<channel>%d</channel>\n", client->channel);

	/* Rate: inaccurate because it's the latest rate seen */
	client_max_rate = (client->rate_from > client->rate_to) ? client->rate_from
															: client->rate_to;
	fprintf(opt.f_kis_xml,
			"\t\t\t<maxseenrate>%.6f</maxseenrate>\n",
			client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
				(0.0f + 1000000));
#else
				1000000.0);
#endif

	/* Those 2 lines always stays the same */
	fprintf(opt.f_kis_xml, "\t\t\t<carrier>IEEE 802.11b+</carrier>\n");
	fprintf(opt.f_kis_xml, "\t\t\t<encoding>CCK</encoding>\n");

	/* Packets */
	fprintf(opt.f_kis_xml,
			"\t\t\t<packets>\n"
			"\t\t\t\t<LLC>0</LLC>\n"
			"\t\t\t\t<data>0</data>\n"
			"\t\t\t\t<crypt>0</crypt>\n"
			"\t\t\t\t<total>%lu</total>\n"
			"\t\t\t\t<fragments>0</fragments>\n"
			"\t\t\t\t<retries>0</retries>\n"
			"\t\t\t</packets>\n",
			client->nb_pkt);

	/* SNR information */
	average_power = (client->power == -1) ? 0 : client->power;
	max_power = (client->best_power == -1) ? average_power : client->best_power;

	fprintf(opt.f_kis_xml,
			"\t\t\t<snr-info>\n"
			"\t\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
			"\t\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
			"\t\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
			"\t\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
			"\t\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
			"\t\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
			"\t\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
			"\t\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
			"\t\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
			"\t\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
			"\t\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
			"\t\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
			"\t\t\t</snr-info>\n",
			average_power,
			average_power,
			average_power,
			max_power,
			max_power);

	/* GPS Coordinates for clients */

	if (opt.usegpsd)
	{
		fprintf(opt.f_kis_xml,
				"\t\t\t<gps-info>\n"
				"\t\t\t\t<min-lat>%.6f</min-lat>\n"
				"\t\t\t\t<min-lon>%.6f</min-lon>\n"
				"\t\t\t\t<min-alt>%.6f</min-alt>\n"
				"\t\t\t\t<min-spd>%.6f</min-spd>\n"
				"\t\t\t\t<max-lat>%.6f</max-lat>\n"
				"\t\t\t\t<max-lon>%.6f</max-lon>\n"
				"\t\t\t\t<max-alt>%.6f</max-alt>\n"
				"\t\t\t\t<max-spd>%.6f</max-spd>\n"
				"\t\t\t\t<peak-lat>%.6f</peak-lat>\n"
				"\t\t\t\t<peak-lon>%.6f</peak-lon>\n"
				"\t\t\t\t<peak-alt>%.6f</peak-alt>\n"
				"\t\t\t\t<avg-lat>%.6f</avg-lat>\n"
				"\t\t\t\t<avg-lon>%.6f</avg-lon>\n"
				"\t\t\t\t<avg-alt>%.6f</avg-alt>\n"
				"\t\t\t</gps-info>\n",
				client->gps_loc_min[0],
				client->gps_loc_min[1],
				client->gps_loc_min[2],
				client->gps_loc_min[3],
				client->gps_loc_max[0],
				client->gps_loc_max[1],
				client->gps_loc_max[2],
				client->gps_loc_max[3],
				client->gps_loc_best[0],
				client->gps_loc_best[1],
				client->gps_loc_best[2],
				/* Can the "best" be considered as average??? */
				client->gps_loc_best[0],
				client->gps_loc_best[1],
				client->gps_loc_best[2]);
	}
	fprintf(opt.f_kis_xml, "\t\t</wireless-client>\n");

	return (0);
}

#define NETXML_ENCRYPTION_TAG "%s<encryption>%s</encryption>\n"
int dump_write_kismet_netxml(struct ap_list_head * const ap_list,
                             struct sta_list_head * const sta_list,
							 unsigned int f_encrypt,
							 char * airodump_start_time)
{
	int network_number, average_power, client_max_rate, max_power, client_nbr,
		fp;
	off_t fpos;
	struct ST_info * st_cur;
	char first_time[TIME_STR_LENGTH];
	char last_time[TIME_STR_LENGTH];
	char * manuf;
	char * essid = NULL;

	if (!opt.record_data || !opt.output_format_kismet_netxml) return (0);

	if (fseek(opt.f_kis_xml, 0, SEEK_SET) == -1)
	{
		return (0);
	}

	/* Header and airodump-ng start time */
	fprintf(opt.f_kis_xml,
			"%s%s%s",
			KISMET_NETXML_HEADER_BEGIN,
			airodump_start_time,
			KISMET_NETXML_HEADER_END);

	network_number = 0;

    struct AP_info * ap_cur;
    TAILQ_FOREACH(ap_cur, ap_list, entry)
	{
		if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
		{
			continue;
		}

		if (ap_cur->security != 0 && f_encrypt != 0
			&& ((ap_cur->security & f_encrypt) == 0))
		{
			continue;
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			continue;
		}

		++network_number; // Network Number
		strncpy(first_time, ctime(&ap_cur->tinit), TIME_STR_LENGTH - 1);
		first_time[strlen(first_time) - 1] = 0; // remove new line

		strncpy(last_time, ctime(&ap_cur->tlast), TIME_STR_LENGTH - 1);
		last_time[strlen(last_time) - 1] = 0; // remove new line

		fprintf(opt.f_kis_xml,
				"\t<wireless-network number=\"%d\" type=\"infrastructure\" ",
				network_number);
		fprintf(opt.f_kis_xml,
				"first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);

		fprintf(opt.f_kis_xml,
				"\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(opt.f_kis_xml, "\t\t\t<type>Beacon</type>\n");
		fprintf(opt.f_kis_xml,
				"\t\t\t<max-rate>%d.000000</max-rate>\n",
				ap_cur->max_speed);
		fprintf(
			opt.f_kis_xml, "\t\t\t<packets>%lu</packets>\n", ap_cur->nb_bcn);
		fprintf(opt.f_kis_xml, "\t\t\t<beaconrate>%d</beaconrate>\n", 10);

		// Encryption
		if (ap_cur->security & STD_OPN)
			fprintf(opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "None");
		else if (ap_cur->security & STD_WEP)
			fprintf(opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP");
		else if (ap_cur->security & STD_WPA2 || ap_cur->security & STD_WPA)
		{
			if (ap_cur->security & ENC_TKIP)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+TKIP");
			if (ap_cur->security & AUTH_MGT)
				fprintf(opt.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+MGT"); // Not a valid value: NetXML does not have a
			// value for WPA Enterprise
			if (ap_cur->security & AUTH_PSK)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+PSK");
			if (ap_cur->security & AUTH_CMAC)
				fprintf(opt.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+PSK+CMAC");
			if (ap_cur->security & ENC_CCMP)
				fprintf(opt.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+AES-CCM");
			if (ap_cur->security & ENC_WRAP)
				fprintf(opt.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+AES-OCB");
			if (ap_cur->security & ENC_GCMP)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+GCMP");
			if (ap_cur->security & ENC_GMAC)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+GMAC");
			if (ap_cur->security & AUTH_SAE)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+SAE");
			if (ap_cur->security & AUTH_OWE)
				fprintf(
					opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+OWE");
		}
		else if (ap_cur->security & ENC_WEP104)
			fprintf(opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP104");
		else if (ap_cur->security & ENC_WEP40)
			fprintf(opt.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP40");

		/* ESSID */
		fprintf(opt.f_kis_xml,
				"\t\t\t<essid cloaked=\"%s\">",
				(ap_cur->essid[0] == 0) ? "true" : "false");
		essid = sanitize_xml(ap_cur->essid, (size_t) ap_cur->ssid_length);
		if (essid != NULL)
		{
			fprintf(opt.f_kis_xml, "%s", essid);
			free(essid);
		}
		fprintf(opt.f_kis_xml, "</essid>\n");

		/* End of SSID tag */
		fprintf(opt.f_kis_xml, "\t\t</SSID>\n");

		/* BSSID */
        fprintf(opt.f_kis_xml, "\t\t<BSSID>");
        fprintf_mac_address(opt.f_kis_xml, &ap_cur->bssid);
        fprintf(opt.f_kis_xml, "</BSSID>\n");

		/* Manufacturer, if set using standard oui list */
		manuf = sanitize_xml((unsigned char *) ap_cur->manuf,
							 strlen(ap_cur->manuf));
		fprintf(opt.f_kis_xml,
				"\t\t<manuf>%s</manuf>\n",
				(manuf != NULL) ? manuf : "Unknown");
		free(manuf);

		/* Channel
		   FIXME: Take opt.freqoption in account */
		fprintf(opt.f_kis_xml,
				"\t\t<channel>%d</channel>\n",
				(ap_cur->channel) == -1 ? 0 : ap_cur->channel);

		/* Freq (in Mhz) and total number of packet on that frequency
		   FIXME: Take opt.freqoption in account */
		fprintf(opt.f_kis_xml,
				"\t\t<freqmhz>%d %lu</freqmhz>\n",
				(ap_cur->channel) == -1 ? 0 : getFrequencyFromChannel(
												  ap_cur->channel),
				// ap_cur->nb_data + ap_cur->nb_bcn );
				ap_cur->nb_pkt);

		/* XXX: What about 5.5Mbit */
		fprintf(opt.f_kis_xml,
				"\t\t<maxseenrate>%d</maxseenrate>\n",
				(ap_cur->max_speed == -1) ? 0 : ap_cur->max_speed * 1000);

		/* Those 2 lines always stays the same */
		fprintf(opt.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
		fprintf(opt.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

		/* Packets */
		fprintf(opt.f_kis_xml,
				"\t\t<packets>\n"
				"\t\t\t<LLC>%lu</LLC>\n"
				"\t\t\t<data>%lu</data>\n"
				"\t\t\t<crypt>0</crypt>\n"
				"\t\t\t<total>%lu</total>\n"
				"\t\t\t<fragments>0</fragments>\n"
				"\t\t\t<retries>0</retries>\n"
				"\t\t</packets>\n",
				ap_cur->nb_data,
				ap_cur->nb_data,
				// ap_cur->nb_data + ap_cur->nb_bcn );
				ap_cur->nb_pkt);

		/* XXX: What does that field mean? Is it the total size of data? */
		fprintf(opt.f_kis_xml, "\t\t<datasize>0</datasize>\n");

		/* Client information */
		client_nbr = 0;

		TAILQ_FOREACH(st_cur, sta_list, entry)
		{
			/* Check if the station is associated to the current AP */
			if (!MAC_ADDRESS_IS_BROADCAST(&st_cur->stmac) 
                && st_cur->base != NULL
				&& MAC_ADDRESS_EQUAL(&st_cur->base->bssid, &ap_cur->bssid))
			{
				dump_write_kismet_netxml_client_info(st_cur, ++client_nbr);
			}
		}

		/* SNR information */
		average_power = (ap_cur->avg_power == -1) ? 0 : ap_cur->avg_power;
		max_power
			= (ap_cur->best_power == -1) ? average_power : ap_cur->best_power;
		fprintf(opt.f_kis_xml,
				"\t\t<snr-info>\n"
				"\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
				"\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
				"\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
				"\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
				"\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
				"\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
				"\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
				"\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
				"\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
				"\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
				"\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
				"\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
				"\t\t</snr-info>\n",
				average_power,
				average_power,
				average_power,
				max_power,
				max_power);

		/* GPS Coordinates */
		if (opt.usegpsd)
		{
			fprintf(opt.f_kis_xml,
					"\t\t<gps-info>\n"
					"\t\t\t<min-lat>%.6f</min-lat>\n"
					"\t\t\t<min-lon>%.6f</min-lon>\n"
					"\t\t\t<min-alt>%.6f</min-alt>\n"
					"\t\t\t<min-spd>%.6f</min-spd>\n"
					"\t\t\t<max-lat>%.6f</max-lat>\n"
					"\t\t\t<max-lon>%.6f</max-lon>\n"
					"\t\t\t<max-alt>%.6f</max-alt>\n"
					"\t\t\t<max-spd>%.6f</max-spd>\n"
					"\t\t\t<peak-lat>%.6f</peak-lat>\n"
					"\t\t\t<peak-lon>%.6f</peak-lon>\n"
					"\t\t\t<peak-alt>%.6f</peak-alt>\n"
					"\t\t\t<avg-lat>%.6f</avg-lat>\n"
					"\t\t\t<avg-lon>%.6f</avg-lon>\n"
					"\t\t\t<avg-alt>%.6f</avg-alt>\n"
					"\t\t</gps-info>\n",
					ap_cur->gps_loc_min[0],
					ap_cur->gps_loc_min[1],
					ap_cur->gps_loc_min[2],
					ap_cur->gps_loc_min[3],
					ap_cur->gps_loc_max[0],
					ap_cur->gps_loc_max[1],
					ap_cur->gps_loc_max[2],
					ap_cur->gps_loc_max[3],
					ap_cur->gps_loc_best[0],
					ap_cur->gps_loc_best[1],
					ap_cur->gps_loc_best[2],
					/* Can the "best" be considered as average??? */
					ap_cur->gps_loc_best[0],
					ap_cur->gps_loc_best[1],
					ap_cur->gps_loc_best[2]);
		}

		/* BSS Timestamp */
		fprintf(opt.f_kis_xml,
				"\t\t<bsstimestamp>%llu</bsstimestamp>\n",
				ap_cur->timestamp);

		/* Trailing information */
		fprintf(opt.f_kis_xml,
				"\t\t<cdp-device></cdp-device>\n"
				"\t\t<cdp-portid></cdp-portid>\n");

		/* Closing tag for the current wireless network */
		fprintf(opt.f_kis_xml, "\t</wireless-network>\n");
		//-------- End of XML

	}

	/* Write all unassociated stations */
	TAILQ_FOREACH(st_cur, sta_list, entry)
	{
		/* If not associated and not Broadcast Mac */
		if (st_cur->base == NULL
			|| MAC_ADDRESS_IS_BROADCAST(&st_cur->base->bssid))
		{
			++network_number; // Network Number

			/* Write new network information */
			strncpy(first_time, ctime(&st_cur->tinit), TIME_STR_LENGTH - 1);
			first_time[strlen(first_time) - 1] = 0; // remove new line

			strncpy(last_time, ctime(&st_cur->tlast), TIME_STR_LENGTH - 1);
			last_time[strlen(last_time) - 1] = 0; // remove new line

			fprintf(opt.f_kis_xml,
					"\t<wireless-network number=\"%d\" type=\"probe\" ",
					network_number);
			fprintf(opt.f_kis_xml,
					"first-time=\"%s\" last-time=\"%s\">\n",
					first_time,
					last_time);

			/* BSSID */
            fprintf(opt.f_kis_xml, "\t\t<BSSID>");
            fprintf_mac_address(opt.f_kis_xml, &st_cur->stmac);
            fprintf(opt.f_kis_xml, "</BSSID>\n");

			/* Manufacturer, if set using standard oui list */
			manuf = sanitize_xml((unsigned char *) st_cur->manuf,
								 strlen(st_cur->manuf));
			fprintf(opt.f_kis_xml,
					"\t\t<manuf>%s</manuf>\n",
					(manuf != NULL) ? manuf : "Unknown");
			free(manuf);

			/* Channel
			   FIXME: Take opt.freqoption in account */
			fprintf(
				opt.f_kis_xml, "\t\t<channel>%d</channel>\n", st_cur->channel);

			/* Freq (in Mhz) and total number of packet on that frequency
			   FIXME: Take opt.freqoption in account */
			fprintf(opt.f_kis_xml,
					"\t\t<freqmhz>%d %lu</freqmhz>\n",
					getFrequencyFromChannel(st_cur->channel),
					st_cur->nb_pkt);

			/* Rate: inaccurate because it's the latest rate seen */
			client_max_rate = (st_cur->rate_from > st_cur->rate_to)
								  ? st_cur->rate_from
								  : st_cur->rate_to;
			fprintf(opt.f_kis_xml,
					"\t\t<maxseenrate>%.6f</maxseenrate>\n",
					client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
						(0.0f + 1000000));
#else
						1000000.0);
#endif

			fprintf(opt.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
			fprintf(opt.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

			/* Packets */
			fprintf(opt.f_kis_xml,
					"\t\t<packets>\n"
					"\t\t\t<LLC>0</LLC>\n"
					"\t\t\t<data>0</data>\n"
					"\t\t\t<crypt>0</crypt>\n"
					"\t\t\t<total>%lu</total>\n"
					"\t\t\t<fragments>0</fragments>\n"
					"\t\t\t<retries>0</retries>\n"
					"\t\t</packets>\n",
					st_cur->nb_pkt);

			/* XXX: What does that field mean? Is it the total size of data? */
			fprintf(opt.f_kis_xml, "\t\t<datasize>0</datasize>\n");

			/* SNR information */
			average_power = (st_cur->power == -1) ? 0 : st_cur->power;
			max_power = (st_cur->best_power == -1) ? average_power
												   : st_cur->best_power;

			fprintf(opt.f_kis_xml,
					"\t\t<snr-info>\n"
					"\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
					"\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
					"\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
					"\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
					"\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
					"\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
					"\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
					"\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
					"\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
					"\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
					"\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
					"\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
					"\t\t</snr-info>\n",
					average_power,
					average_power,
					average_power,
					max_power,
					max_power);

			/* GPS Coordinates for clients */

			if (opt.usegpsd)
			{
				fprintf(opt.f_kis_xml,
						"\t\t<gps-info>\n"
						"\t\t\t<min-lat>%.6f</min-lat>\n"
						"\t\t\t<min-lon>%.6f</min-lon>\n"
						"\t\t\t<min-alt>%.6f</min-alt>\n"
						"\t\t\t<min-spd>%.6f</min-spd>\n"
						"\t\t\t<max-lat>%.6f</max-lat>\n"
						"\t\t\t<max-lon>%.6f</max-lon>\n"
						"\t\t\t<max-alt>%.6f</max-alt>\n"
						"\t\t\t<max-spd>%.6f</max-spd>\n"
						"\t\t\t<peak-lat>%.6f</peak-lat>\n"
						"\t\t\t<peak-lon>%.6f</peak-lon>\n"
						"\t\t\t<peak-alt>%.6f</peak-alt>\n"
						"\t\t\t<avg-lat>%.6f</avg-lat>\n"
						"\t\t\t<avg-lon>%.6f</avg-lon>\n"
						"\t\t\t<avg-alt>%.6f</avg-alt>\n"
						"\t\t</gps-info>\n",
						st_cur->gps_loc_min[0],
						st_cur->gps_loc_min[1],
						st_cur->gps_loc_min[2],
						st_cur->gps_loc_min[3],
						st_cur->gps_loc_max[0],
						st_cur->gps_loc_max[1],
						st_cur->gps_loc_max[2],
						st_cur->gps_loc_max[3],
						st_cur->gps_loc_best[0],
						st_cur->gps_loc_best[1],
						st_cur->gps_loc_best[2],
						/* Can the "best" be considered as average??? */
						st_cur->gps_loc_best[0],
						st_cur->gps_loc_best[1],
						st_cur->gps_loc_best[2]);
			}

			fprintf(opt.f_kis_xml, "\t\t<bsstimestamp>0</bsstimestamp>\n");

			/* CDP information */
			fprintf(opt.f_kis_xml,
					"\t\t<cdp-device></cdp-device>\n"
					"\t\t<cdp-portid></cdp-portid>\n");

			/* Write client information */
			dump_write_kismet_netxml_client_info(st_cur, 1);

			fprintf(opt.f_kis_xml, "\t</wireless-network>");
		}
	}
	/* TODO: Also go through na_1st */

	/* Trailing */
	fprintf(opt.f_kis_xml, "%s\n", KISMET_NETXML_TRAILER);

	fflush(opt.f_kis_xml);

	/* Sometimes there can be crap at the end of the file, so truncating is a
	   good idea.
       XXX: Is this really correct? I hope fileno() won't have any 
       side effect 
	   */
	fp = fileno(opt.f_kis_xml);
	fpos = ftell(opt.f_kis_xml);
	if (fp == -1 || fpos == -1)
	{
		return (0);
	}

	IGNORE_NZ(ftruncate(fp, fpos));

	return (0);
}
#undef TIME_STR_LENGTH

void dump_write(
    struct dump_context_st * dump,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
    unsigned int const f_encrypt)
{
    if (dump == NULL)
    {
        goto done;
    }

    dump->dump(dump->priv, ap_list, sta_list, f_encrypt);

done:
    return;
}

static void dump_free(struct dump_context_st * dump)
{
    free(dump);
}

void dump_close(struct dump_context_st * dump)
{
    if (dump == NULL)
    {
        goto done;
    }

    if (dump->close != NULL)
    {
        dump->close(dump->priv);
    }

    dump_free(dump);

done:
    return; 
}

struct dump_context_st * dump_open(
    dump_type_t const  dump_type,
    char const * const filename,
    char const * const sys_name,
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds)
{
    bool had_error;
    struct dump_context_st * dump = calloc(1, sizeof *dump);

    if (dump == NULL)
    {
        goto done;
    }

    switch (dump_type)
    {
        case dump_type_wifi_scanner:
            if (!wifi_scanner_dump_open(dump,
                                        filename,
                                        sys_name,
                                        location_name,
                                        filter_seconds,
                                        file_reset_seconds))
            {
                had_error = true;
                goto done;
            }
            break;
        case dump_type_csv:
            if (!csv_dump_open(dump,
                               filename))
            {
                had_error = true;
                goto done;
            }
            break;
        case dump_type_kismet_csv:
            if (!kismet_csv_dump_open(dump,
                                      filename))
            {
                had_error = true;
                goto done;
            }
            break;
        default:
            had_error = true;
            goto done;
    }

    had_error = false;

done:
    if (had_error)
    {
        dump_close(dump);
        dump = NULL;
    }

    return dump;
}


