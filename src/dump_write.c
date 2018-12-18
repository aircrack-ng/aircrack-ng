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

#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h> // ftruncate
#include <sys/types.h> // ftruncate
#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "defs.h"
#include "airodump-ng.h"
#include "dump_write.h"
#include "crypto.h"
#include "aircrack-util/verifyssid.h"

extern int getFrequencyFromChannel(int channel); // "aircrack-osdep/common.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

static char * format_text_for_csv(const unsigned char * input, int len)
{
	// Unix style encoding
	char *ret, *rret;
	int i, pos, contains_space_end;
	const char * hex_table = "0123456789ABCDEF";

	if (len < 0)
	{
		return (NULL);
	}

	if (len == 0 || input == NULL)
	{
		ret = (char *) malloc(1);
		ALLEGE(ret != NULL);
		ret[0] = 0;
		return (ret);
	}

	pos = 0;
	contains_space_end = (input[0] == ' ') || input[len - 1] == ' ';

	// Make sure to have enough memory for all that stuff
	ret = (char *) malloc((len * 4) + 1 + 2);
	ALLEGE(ret != NULL);

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	for (i = 0; i < len; i++)
	{
		if (!isprint(input[i]) || input[i] == ',' || input[i] == '\\'
			|| input[i] == '"')
		{
			ret[pos++] = '\\';
		}

		if (isprint(input[i]))
		{
			ret[pos++] = input[i];
		}
		else if (input[i] == '\n' || input[i] == '\r' || input[i] == '\t')
		{
			ret[pos++]
				= (input[i] == '\n') ? 'n' : (input[i] == '\t') ? 't' : 'r';
		}
		else
		{
			ret[pos++] = 'x';
			ret[pos++] = hex_table[input[i] / 16];
			ret[pos++] = hex_table[input[i] % 16];
		}
	}

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	ret[pos++] = '\0';

	rret = realloc(ret, pos);
	ALLEGE(rret != NULL);

	return (rret) ? (rret) : (ret);
}

int dump_write_csv(void)
{
	int i, n, probes_written;
	struct tm * ltime;
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	char * temp;

	if (!G.record_data || !G.output_format_csv) return (0);

	fseek(G.f_txt, 0, SEEK_SET);

	fprintf(G.f_txt,
			"\r\nBSSID, First time seen, Last time seen, channel, Speed, "
			"Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, "
			"ID-length, ESSID, Key\r\n");

	ap_cur = G.ap_1st;

	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (ap_cur->security != 0 && G.f_encrypt != 0
			&& ((ap_cur->security & G.f_encrypt) == 0))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		fprintf(G.f_txt,
				"%02X:%02X:%02X:%02X:%02X:%02X, ",
				ap_cur->bssid[0],
				ap_cur->bssid[1],
				ap_cur->bssid[2],
				ap_cur->bssid[3],
				ap_cur->bssid[4],
				ap_cur->bssid[5]);

		ltime = localtime(&ap_cur->tinit);

		fprintf(G.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		ltime = localtime(&ap_cur->tlast);

		fprintf(G.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		fprintf(G.f_txt, "%2d, %3d,", ap_cur->channel, ap_cur->max_speed);

		if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) == 0)
			fprintf(G.f_txt, " ");
		else
		{
			if (ap_cur->security & STD_WPA2) fprintf(G.f_txt, " WPA2");
			if (ap_cur->security & STD_WPA) fprintf(G.f_txt, " WPA");
			if (ap_cur->security & STD_WEP) fprintf(G.f_txt, " WEP");
			if (ap_cur->security & STD_OPN) fprintf(G.f_txt, " OPN");
		}

		fprintf(G.f_txt, ",");

		if ((ap_cur->security
			 & (ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP104
				| ENC_WEP40
				| ENC_GCMP))
			== 0)
			fprintf(G.f_txt, " ");
		else
		{
			if (ap_cur->security & ENC_CCMP) fprintf(G.f_txt, " CCMP");
			if (ap_cur->security & ENC_WRAP) fprintf(G.f_txt, " WRAP");
			if (ap_cur->security & ENC_TKIP) fprintf(G.f_txt, " TKIP");
			if (ap_cur->security & ENC_WEP104) fprintf(G.f_txt, " WEP104");
			if (ap_cur->security & ENC_WEP40) fprintf(G.f_txt, " WEP40");
			if (ap_cur->security & ENC_WEP) fprintf(G.f_txt, " WEP");
			if (ap_cur->security & ENC_WEP) fprintf(G.f_txt, " GCMP");
		}

		fprintf(G.f_txt, ",");

		if ((ap_cur->security & (AUTH_OPN | AUTH_PSK | AUTH_MGT)) == 0)
			fprintf(G.f_txt, "   ");
		else
		{
			if (ap_cur->security & AUTH_MGT) fprintf(G.f_txt, " MGT");
			if (ap_cur->security & AUTH_PSK)
			{
				if (ap_cur->security & STD_WEP)
					fprintf(G.f_txt, " SKA");
				else
					fprintf(G.f_txt, " PSK");
			}
			if (ap_cur->security & AUTH_OPN) fprintf(G.f_txt, " OPN");
		}

		fprintf(G.f_txt,
				", %3d, %8lu, %8lu, ",
				ap_cur->avg_power,
				ap_cur->nb_bcn,
				ap_cur->nb_data);

		fprintf(G.f_txt,
				"%3d.%3d.%3d.%3d, ",
				ap_cur->lanip[0],
				ap_cur->lanip[1],
				ap_cur->lanip[2],
				ap_cur->lanip[3]);

		fprintf(G.f_txt, "%3d, ", ap_cur->ssid_length);

		if (verifyssid(ap_cur->essid))
			fprintf(G.f_txt, "%s, ", ap_cur->essid);
		else
		{
			temp = format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);
			fprintf(G.f_txt, "%s, ", temp);
			free(temp);
		}

		if (ap_cur->key != NULL)
		{
			for (i = 0; i < (int) strlen(ap_cur->key); i++)
			{
				fprintf(G.f_txt, "%02X", ap_cur->key[i]);
				if (i < (int) (strlen(ap_cur->key) - 1)) fprintf(G.f_txt, ":");
			}
		}

		fprintf(G.f_txt, "\r\n");

		ap_cur = ap_cur->next;
	}

	fprintf(G.f_txt,
			"\r\nStation MAC, First time seen, Last time seen, "
			"Power, # packets, BSSID, Probed ESSIDs\r\n");

	st_cur = G.st_1st;

	while (st_cur != NULL)
	{
		ap_cur = st_cur->base;

		if (ap_cur->nb_pkt < 2)
		{
			st_cur = st_cur->next;
			continue;
		}

		fprintf(G.f_txt,
				"%02X:%02X:%02X:%02X:%02X:%02X, ",
				st_cur->stmac[0],
				st_cur->stmac[1],
				st_cur->stmac[2],
				st_cur->stmac[3],
				st_cur->stmac[4],
				st_cur->stmac[5]);

		ltime = localtime(&st_cur->tinit);

		fprintf(G.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		ltime = localtime(&st_cur->tlast);

		fprintf(G.f_txt,
				"%04d-%02d-%02d %02d:%02d:%02d, ",
				1900 + ltime->tm_year,
				1 + ltime->tm_mon,
				ltime->tm_mday,
				ltime->tm_hour,
				ltime->tm_min,
				ltime->tm_sec);

		fprintf(G.f_txt, "%3d, %8lu, ", st_cur->power, st_cur->nb_pkt);

		if (!memcmp(ap_cur->bssid, BROADCAST, 6))
			fprintf(G.f_txt, "(not associated) ,");
		else
			fprintf(G.f_txt,
					"%02X:%02X:%02X:%02X:%02X:%02X,",
					ap_cur->bssid[0],
					ap_cur->bssid[1],
					ap_cur->bssid[2],
					ap_cur->bssid[3],
					ap_cur->bssid[4],
					ap_cur->bssid[5]);

		probes_written = 0;
		for (i = 0, n = 0; i < NB_PRB; i++)
		{
			if (st_cur->ssid_length[i] == 0) continue;

			if (verifyssid((const unsigned char *) st_cur->probes[i]))
			{
				temp = (char *) calloc(
					1, (st_cur->ssid_length[i] + 1) * sizeof(char));
				ALLEGE(temp != NULL);
				memcpy(temp, st_cur->probes[i], st_cur->ssid_length[i] + 1);
			}
			else
			{
				temp = format_text_for_csv((unsigned char *) st_cur->probes[i],
										   st_cur->ssid_length[i]);
			}

			if (probes_written == 0)
			{
				fprintf(G.f_txt, "%s", temp);
				probes_written = 1;
			}
			else
			{
				fprintf(G.f_txt, ",%s", temp);
			}

			free(temp);
		}

		fprintf(G.f_txt, "\r\n");

		st_cur = st_cur->next;
	}

	fprintf(G.f_txt, "\r\n");
	fflush(G.f_txt);
	return (0);
}

int dump_write_airodump_ng_logcsv_add_ap(const struct AP_info * ap_cur,
										 const int32_t ri_power)
{
	if (ap_cur == NULL || !G.output_format_log_csv || !G.f_logcsv)
	{
		return (0);
	}

	// Local computer time
	struct tm * ltime = localtime(&ap_cur->tlast);
	fprintf(G.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);

	// Gps time
	struct tm * tm_gpstime = &G.gps_time;
	fprintf(G.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	// ESSID
	fprintf(G.f_logcsv, "%s,", ap_cur->essid);

	// BSSID
	fprintf(G.f_logcsv,
			"%02X:%02X:%02X:%02X:%02X:%02X,",
			ap_cur->bssid[0],
			ap_cur->bssid[1],
			ap_cur->bssid[2],
			ap_cur->bssid[3],
			ap_cur->bssid[4],
			ap_cur->bssid[5]);

	// RSSI
	fprintf(G.f_logcsv, "%d,", ri_power);

	// Network Security
	if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) == 0)
		fputs(",", G.f_logcsv);
	else if (ap_cur->security & STD_WPA2)
		fputs("WPA2,", G.f_logcsv);
	else if (ap_cur->security & STD_WPA)
		fputs("WPA,", G.f_logcsv);
	else if (ap_cur->security & STD_WEP)
		fputs("WEP,", G.f_logcsv);
	else if (ap_cur->security & STD_OPN)
		fputs("OPN,", G.f_logcsv);

	// Lat, Lon, Lat Error, Lon Error
	fprintf(G.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,AP\r\n",
			G.gps_loc[0],
			G.gps_loc[1],
			G.gps_loc[5],
			G.gps_loc[6]);

	return (0);
}

int dump_write_airodump_ng_logcsv_add_client(const struct AP_info * ap_cur,
											 const struct ST_info * st_cur,
											 const int32_t ri_power)
{
	if (st_cur == NULL || !G.output_format_log_csv || !G.f_logcsv)
	{
		return (0);
	}

	// Local computer time
	struct tm * ltime = localtime(&ap_cur->tlast);
	fprintf(G.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + ltime->tm_year,
			1 + ltime->tm_mon,
			ltime->tm_mday,
			ltime->tm_hour,
			ltime->tm_min,
			ltime->tm_sec);

	// GPS time
	struct tm * tm_gpstime = &G.gps_time;
	fprintf(G.f_logcsv,
			"%04d-%02d-%02d %02d:%02d:%02d,",
			1900 + tm_gpstime->tm_year,
			1 + tm_gpstime->tm_mon,
			tm_gpstime->tm_mday,
			tm_gpstime->tm_hour,
			tm_gpstime->tm_min,
			tm_gpstime->tm_sec);

	// Client => No ESSID
	fprintf(G.f_logcsv, ",");

	// BSSID
	fprintf(G.f_logcsv,
			"%02X:%02X:%02X:%02X:%02X:%02X,",
			st_cur->stmac[0],
			st_cur->stmac[1],
			st_cur->stmac[2],
			st_cur->stmac[3],
			st_cur->stmac[4],
			st_cur->stmac[5]);

	// RSSI
	fprintf(G.f_logcsv, "%d,", ri_power);

	// Client => Network Security: none
	fprintf(G.f_logcsv, ",");

	// Lat, Lon, Lat Error, Lon Errorst_cur->power
	fprintf(G.f_logcsv,
			"%.6f,%.6f,%.3f,%.3f,",
			G.gps_loc[0],
			G.gps_loc[1],
			G.gps_loc[5],
			G.gps_loc[6]);

	// Type
	fprintf(G.f_logcsv, "Client\r\n");

	return (0);
}

static char * sanitize_xml(unsigned char * text, int length)
{
	int i;
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
		newtext = (char *) realloc(newtext, strlen(newtext) + 1);
		ALLEGE(newtext != NULL);
	}

	return (newtext);
}

char * get_manufacturer_from_string(char * buffer)
{
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0)
	{
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL)
		{
			buffer_manuf += 6; // skip '(hex)' and one more character (there's
			// at least one 'space' character after that
			// string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ')
			{
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0')
			{

				// First make sure there's no end of line
				if (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
					|| buffer_manuf[strlen(buffer_manuf) - 1] == '\r')
				{
					buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					if (*buffer_manuf != '\0'
						&& (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
							|| buffer[strlen(buffer_manuf) - 1] == '\r'))
					{
						buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0')
				{
					if ((manuf = (char *) malloc((strlen(buffer_manuf) + 1)
												 * sizeof(char)))
						== NULL)
					{
						perror("malloc failed");
						return (NULL);
					}
					snprintf(
						manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return (manuf);
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
					   || memcmp(client->base->bssid, BROADCAST, 6) == 0);

	strncpy(first_time, ctime(&client->tinit), TIME_STR_LENGTH - 1);
	first_time[strlen(first_time) - 1] = 0; // remove new line

	strncpy(last_time, ctime(&client->tlast), TIME_STR_LENGTH - 1);
	last_time[strlen(last_time) - 1] = 0; // remove new line

	fprintf(G.f_kis_xml,
			"\t\t<wireless-client number=\"%d\" "
			"type=\"%s\" first-time=\"%s\""
			" last-time=\"%s\">\n",
			client_no,
			(is_unassociated) ? "tods" : "established",
			first_time,
			last_time);

	fprintf(G.f_kis_xml,
			"\t\t\t<client-mac>%02X:%02X:%02X:%02X:%02X:%02X</client-mac>\n",
			client->stmac[0],
			client->stmac[1],
			client->stmac[2],
			client->stmac[3],
			client->stmac[4],
			client->stmac[5]);

	/* Manufacturer, if set using standard oui list */
	manuf
		= sanitize_xml((unsigned char *) client->manuf, strlen(client->manuf));
	fprintf(G.f_kis_xml,
			"\t\t\t<client-manuf>%s</client-manuf>\n",
			(manuf != NULL) ? manuf : "Unknown");
	free(manuf);

	/* SSID item, aka Probes */
	nb_probes_written = 0;
	for (i = 0; i < NB_PRB; i++)
	{
		if (client->probes[i][0] == '\0') continue;

		fprintf(G.f_kis_xml,
				"\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(G.f_kis_xml,
				"\t\t\t\t<type>Probe Request</type>\n"
				"\t\t\t\t<max-rate>54.000000</max-rate>\n"
				"\t\t\t\t<packets>1</packets>\n"
				"\t\t\t\t<encryption>None</encryption>\n");
		essid = sanitize_xml((unsigned char *) client->probes[i],
							 client->ssid_length[i]);
		if (essid != NULL)
		{
			fprintf(G.f_kis_xml, "\t\t\t\t<ssid>%s</ssid>\n", essid);
			free(essid);
		}

		fprintf(G.f_kis_xml, "\t\t\t</SSID>\n");

		++nb_probes_written;
	}

	// Unassociated client with broadcast probes
	if (is_unassociated && nb_probes_written == 0)
	{
		fprintf(G.f_kis_xml,
				"\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(G.f_kis_xml,
				"\t\t\t\t<type>Probe Request</type>\n"
				"\t\t\t\t<max-rate>54.000000</max-rate>\n"
				"\t\t\t\t<packets>1</packets>\n"
				"\t\t\t\t<encryption>None</encryption>\n");
		fprintf(G.f_kis_xml, "\t\t\t</SSID>\n");
	}

	/* Channel
	   FIXME: Take G.freqoption in account */
	fprintf(G.f_kis_xml, "\t\t\t<channel>%d</channel>\n", client->channel);

	/* Rate: inaccurate because it's the latest rate seen */
	client_max_rate = (client->rate_from > client->rate_to) ? client->rate_from
															: client->rate_to;
	fprintf(G.f_kis_xml,
			"\t\t\t<maxseenrate>%.6f</maxseenrate>\n",
			client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
				(0.0f + 1000000));
#else
				1000000.0);
#endif

	/* Those 2 lines always stays the same */
	fprintf(G.f_kis_xml, "\t\t\t<carrier>IEEE 802.11b+</carrier>\n");
	fprintf(G.f_kis_xml, "\t\t\t<encoding>CCK</encoding>\n");

	/* Packets */
	fprintf(G.f_kis_xml,
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

	fprintf(G.f_kis_xml,
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

	if (G.usegpsd)
	{
		fprintf(G.f_kis_xml,
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
	fprintf(G.f_kis_xml, "\t\t</wireless-client>\n");

	return (0);
}

#define NETXML_ENCRYPTION_TAG "%s<encryption>%s</encryption>\n"
int dump_write_kismet_netxml(void)
{
	int network_number, average_power, client_max_rate, max_power, client_nbr,
		fp, fpos;
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	char first_time[TIME_STR_LENGTH];
	char last_time[TIME_STR_LENGTH];
	char * manuf;
	char * essid = NULL;

	if (!G.record_data || !G.output_format_kismet_netxml) return (0);

	if (fseek(G.f_kis_xml, 0, SEEK_SET) == -1)
	{
		return (0);
	}

	/* Header and airodump-ng start time */
	fprintf(G.f_kis_xml,
			"%s%s%s",
			KISMET_NETXML_HEADER_BEGIN,
			G.airodump_start_time,
			KISMET_NETXML_HEADER_END);

	ap_cur = G.ap_1st;

	network_number = 0;
	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (ap_cur->security != 0 && G.f_encrypt != 0
			&& ((ap_cur->security & G.f_encrypt) == 0))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		++network_number; // Network Number
		strncpy(first_time, ctime(&ap_cur->tinit), TIME_STR_LENGTH - 1);
		first_time[strlen(first_time) - 1] = 0; // remove new line

		strncpy(last_time, ctime(&ap_cur->tlast), TIME_STR_LENGTH - 1);
		last_time[strlen(last_time) - 1] = 0; // remove new line

		fprintf(G.f_kis_xml,
				"\t<wireless-network number=\"%d\" type=\"infrastructure\" ",
				network_number);
		fprintf(G.f_kis_xml,
				"first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);

		fprintf(G.f_kis_xml,
				"\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time,
				last_time);
		fprintf(G.f_kis_xml, "\t\t\t<type>Beacon</type>\n");
		fprintf(G.f_kis_xml,
				"\t\t\t<max-rate>%d.000000</max-rate>\n",
				ap_cur->max_speed);
		fprintf(G.f_kis_xml, "\t\t\t<packets>%lu</packets>\n", ap_cur->nb_bcn);
		fprintf(G.f_kis_xml, "\t\t\t<beaconrate>%d</beaconrate>\n", 10);

		// Encryption
		if (ap_cur->security & STD_OPN)
			fprintf(G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "None");
		else if (ap_cur->security & STD_WEP)
			fprintf(G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP");
		else if (ap_cur->security & STD_WPA2 || ap_cur->security & STD_WPA)
		{
			if (ap_cur->security & ENC_TKIP)
				fprintf(
					G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+TKIP");
			if (ap_cur->security & AUTH_MGT)
				fprintf(G.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+MGT"); // Not a valid value: NetXML does not have a
			// value for WPA Enterprise
			if (ap_cur->security & AUTH_PSK)
				fprintf(
					G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+PSK");
			if (ap_cur->security & ENC_CCMP)
				fprintf(G.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+AES-CCM");
			if (ap_cur->security & ENC_WRAP)
				fprintf(G.f_kis_xml,
						NETXML_ENCRYPTION_TAG,
						"\t\t\t",
						"WPA+AES-OCB");
			if (ap_cur->security & ENC_GCMP)
				fprintf(
					G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+GCMP");
		}
		else if (ap_cur->security & ENC_WEP104)
			fprintf(G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP104");
		else if (ap_cur->security & ENC_WEP40)
			fprintf(G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP40");

		/* ESSID */
		fprintf(G.f_kis_xml,
				"\t\t\t<essid cloaked=\"%s\">",
				(ap_cur->essid[0] == 0) ? "true" : "false");
		essid = sanitize_xml(ap_cur->essid, ap_cur->ssid_length);
		if (essid != NULL)
		{
			fprintf(G.f_kis_xml, "%s", essid);
			free(essid);
		}
		fprintf(G.f_kis_xml, "</essid>\n");

		/* End of SSID tag */
		fprintf(G.f_kis_xml, "\t\t</SSID>\n");

		/* BSSID */
		fprintf(G.f_kis_xml,
				"\t\t<BSSID>%02X:%02X:%02X:%02X:%02X:%02X</BSSID>\n",
				ap_cur->bssid[0],
				ap_cur->bssid[1],
				ap_cur->bssid[2],
				ap_cur->bssid[3],
				ap_cur->bssid[4],
				ap_cur->bssid[5]);

		/* Manufacturer, if set using standard oui list */
		manuf = sanitize_xml((unsigned char *) ap_cur->manuf,
							 strlen(ap_cur->manuf));
		fprintf(G.f_kis_xml,
				"\t\t<manuf>%s</manuf>\n",
				(manuf != NULL) ? manuf : "Unknown");
		free(manuf);

		/* Channel
		   FIXME: Take G.freqoption in account */
		fprintf(G.f_kis_xml,
				"\t\t<channel>%d</channel>\n",
				(ap_cur->channel) == -1 ? 0 : ap_cur->channel);

		/* Freq (in Mhz) and total number of packet on that frequency
		   FIXME: Take G.freqoption in account */
		fprintf(G.f_kis_xml,
				"\t\t<freqmhz>%d %lu</freqmhz>\n",
				(ap_cur->channel) == -1 ? 0 : getFrequencyFromChannel(
												  ap_cur->channel),
				// ap_cur->nb_data + ap_cur->nb_bcn );
				ap_cur->nb_pkt);

		/* XXX: What about 5.5Mbit */
		fprintf(G.f_kis_xml,
				"\t\t<maxseenrate>%d</maxseenrate>\n",
				(ap_cur->max_speed == -1) ? 0 : ap_cur->max_speed * 1000);

		/* Those 2 lines always stays the same */
		fprintf(G.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
		fprintf(G.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

		/* Packets */
		fprintf(G.f_kis_xml,
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
		fprintf(G.f_kis_xml, "\t\t<datasize>0</datasize>\n");

		/* Client information */
		st_cur = G.st_1st;
		client_nbr = 0;

		while (st_cur != NULL)
		{
			/* Check if the station is associated to the current AP */
			if (memcmp(st_cur->stmac, BROADCAST, 6) != 0 && st_cur->base != NULL
				&& memcmp(st_cur->base->bssid, ap_cur->bssid, 6) == 0)
			{
				dump_write_kismet_netxml_client_info(st_cur, ++client_nbr);
			}

			/* Next client */
			st_cur = st_cur->next;
		}

		/* SNR information */
		average_power = (ap_cur->avg_power == -1) ? 0 : ap_cur->avg_power;
		max_power
			= (ap_cur->best_power == -1) ? average_power : ap_cur->best_power;
		fprintf(G.f_kis_xml,
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
		if (G.usegpsd)
		{
			fprintf(G.f_kis_xml,
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
		fprintf(G.f_kis_xml,
				"\t\t<bsstimestamp>%llu</bsstimestamp>\n",
				ap_cur->timestamp);

		/* Trailing information */
		fprintf(G.f_kis_xml,
				"\t\t<cdp-device></cdp-device>\n"
				"\t\t<cdp-portid></cdp-portid>\n");

		/* Closing tag for the current wireless network */
		fprintf(G.f_kis_xml, "\t</wireless-network>\n");
		//-------- End of XML

		ap_cur = ap_cur->next;
	}

	/* Write all unassociated stations */
	st_cur = G.st_1st;
	while (st_cur != NULL)
	{
		/* If not associated and not Broadcast Mac */
		if (st_cur->base == NULL
			|| memcmp(st_cur->base->bssid, BROADCAST, 6) == 0)
		{
			++network_number; // Network Number

			/* Write new network information */
			strncpy(first_time, ctime(&st_cur->tinit), TIME_STR_LENGTH - 1);
			first_time[strlen(first_time) - 1] = 0; // remove new line

			strncpy(last_time, ctime(&st_cur->tlast), TIME_STR_LENGTH - 1);
			last_time[strlen(last_time) - 1] = 0; // remove new line

			fprintf(G.f_kis_xml,
					"\t<wireless-network number=\"%d\" type=\"probe\" ",
					network_number);
			fprintf(G.f_kis_xml,
					"first-time=\"%s\" last-time=\"%s\">\n",
					first_time,
					last_time);

			/* BSSID */
			fprintf(G.f_kis_xml,
					"\t\t<BSSID>%02X:%02X:%02X:%02X:%02X:%02X</BSSID>\n",
					st_cur->stmac[0],
					st_cur->stmac[1],
					st_cur->stmac[2],
					st_cur->stmac[3],
					st_cur->stmac[4],
					st_cur->stmac[5]);

			/* Manufacturer, if set using standard oui list */
			manuf = sanitize_xml((unsigned char *) st_cur->manuf,
								 strlen(st_cur->manuf));
			fprintf(G.f_kis_xml,
					"\t\t<manuf>%s</manuf>\n",
					(manuf != NULL) ? manuf : "Unknown");
			free(manuf);

			/* Channel
			   FIXME: Take G.freqoption in account */
			fprintf(
				G.f_kis_xml, "\t\t<channel>%d</channel>\n", st_cur->channel);

			/* Freq (in Mhz) and total number of packet on that frequency
			   FIXME: Take G.freqoption in account */
			fprintf(G.f_kis_xml,
					"\t\t<freqmhz>%d %lu</freqmhz>\n",
					getFrequencyFromChannel(st_cur->channel),
					st_cur->nb_pkt);

			/* Rate: inaccurate because it's the latest rate seen */
			client_max_rate = (st_cur->rate_from > st_cur->rate_to)
								  ? st_cur->rate_from
								  : st_cur->rate_to;
			fprintf(G.f_kis_xml,
					"\t\t<maxseenrate>%.6f</maxseenrate>\n",
					client_max_rate /
#if defined(__x86_64__) && defined(__CYGWIN__)
						(0.0f + 1000000));
#else
						1000000.0);
#endif

			fprintf(G.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
			fprintf(G.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

			/* Packets */
			fprintf(G.f_kis_xml,
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
			fprintf(G.f_kis_xml, "\t\t<datasize>0</datasize>\n");

			/* SNR information */
			average_power = (st_cur->power == -1) ? 0 : st_cur->power;
			max_power = (st_cur->best_power == -1) ? average_power
												   : st_cur->best_power;

			fprintf(G.f_kis_xml,
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

			if (G.usegpsd)
			{
				fprintf(G.f_kis_xml,
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

			fprintf(G.f_kis_xml, "\t\t<bsstimestamp>0</bsstimestamp>\n");

			/* CDP information */
			fprintf(G.f_kis_xml,
					"\t\t<cdp-device></cdp-device>\n"
					"\t\t<cdp-portid></cdp-portid>\n");

			/* Write client information */
			dump_write_kismet_netxml_client_info(st_cur, 1);

			fprintf(G.f_kis_xml, "\t</wireless-network>");
		}
		st_cur = st_cur->next;
	}
	/* TODO: Also go through na_1st */

	/* Trailing */
	fprintf(G.f_kis_xml, "%s\n", KISMET_NETXML_TRAILER);

	fflush(G.f_kis_xml);

	/* Sometimes there can be crap at the end of the file, so truncating is a
	   good idea.
	   XXX: Is this really correct, I hope fileno() won't have any side effect
	   */
	fp = fileno(G.f_kis_xml);
	fpos = ftell(G.f_kis_xml);
	if (fp == -1 || fpos == -1)
	{
		return (0);
	}
	(void) ftruncate(fp, fpos);

	return (0);
}
#undef TIME_STR_LENGTH

#define KISMET_HEADER                                                          \
	"Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;Encryption;Decrypted;"   \
	"MaxRate;MaxSeenRate;Beacon;LLC;Data;Crypt;Weak;Total;Carrier;Encoding;"   \
	"FirstTime;LastTime;BestQuality;BestSignal;BestNoise;GPSMinLat;GPSMinLon;" \
	"GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;GPSBestLat;"  \
	"GPSBestLon;GPSBestAlt;DataSize;IPType;IP;\n"

int dump_write_kismet_csv(void)
{
	int i, k;
	struct AP_info * ap_cur;

	if (!G.record_data || !G.output_format_kismet_csv) return (0);

	if (fseek(G.f_kis, 0, SEEK_SET) == -1)
	{
		return (0);
	}

	fprintf(G.f_kis, KISMET_HEADER);

	ap_cur = G.ap_1st;

	k = 1;
	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (ap_cur->security != 0 && G.f_encrypt != 0
			&& ((ap_cur->security & G.f_encrypt) == 0))
		{
			ap_cur = ap_cur->next;
			continue;
		}

		if (is_filtered_essid(ap_cur->essid) || ap_cur->nb_pkt < 2)
		{
			ap_cur = ap_cur->next;
			continue;
		}

		// Network
		fprintf(G.f_kis, "%d;", k);

		// NetType
		fprintf(G.f_kis, "infrastructure;");

		// ESSID
		for (i = 0; i < ap_cur->ssid_length; i++)
		{
			fprintf(G.f_kis, "%c", ap_cur->essid[i]);
		}
		fprintf(G.f_kis, ";");

		// BSSID
		fprintf(G.f_kis,
				"%02X:%02X:%02X:%02X:%02X:%02X;",
				ap_cur->bssid[0],
				ap_cur->bssid[1],
				ap_cur->bssid[2],
				ap_cur->bssid[3],
				ap_cur->bssid[4],
				ap_cur->bssid[5]);

		// Info
		fprintf(G.f_kis, ";");

		// Channel
		fprintf(G.f_kis, "%d;", ap_cur->channel);

		// Cloaked
		fprintf(G.f_kis, "No;");

		// Encryption
		if ((ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)) != 0)
		{
			if (ap_cur->security & STD_WPA2) fprintf(G.f_kis, "WPA2,");
			if (ap_cur->security & STD_WPA) fprintf(G.f_kis, "WPA,");
			if (ap_cur->security & STD_WEP) fprintf(G.f_kis, "WEP,");
			if (ap_cur->security & STD_OPN) fprintf(G.f_kis, "OPN,");
		}

		if ((ap_cur->security
			 & (ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP104
				| ENC_WEP40
				| ENC_GCMP))
			== 0)
			fprintf(G.f_kis, "None,");
		else
		{
			if (ap_cur->security & ENC_CCMP) fprintf(G.f_kis, "AES-CCM,");
			if (ap_cur->security & ENC_WRAP) fprintf(G.f_kis, "WRAP,");
			if (ap_cur->security & ENC_TKIP) fprintf(G.f_kis, "TKIP,");
			if (ap_cur->security & ENC_WEP104) fprintf(G.f_kis, "WEP104,");
			if (ap_cur->security & ENC_WEP40) fprintf(G.f_kis, "WEP40,");
			/*            if( ap_cur->security & ENC_WEP    ) fprintf( G.f_kis,
			 * " WEP,");*/
			if (ap_cur->security & ENC_WEP40) fprintf(G.f_kis, "GCMP,");
		}

		fseek(G.f_kis, -1, SEEK_CUR);
		fprintf(G.f_kis, ";");

		// Decrypted
		fprintf(G.f_kis, "No;");

		// MaxRate
		fprintf(G.f_kis, "%d.0;", ap_cur->max_speed);

		// MaxSeenRate
		fprintf(G.f_kis, "0;");

		// Beacon
		fprintf(G.f_kis, "%lu;", ap_cur->nb_bcn);

		// LLC
		fprintf(G.f_kis, "0;");

		// Data
		fprintf(G.f_kis, "%lu;", ap_cur->nb_data);

		// Crypt
		fprintf(G.f_kis, "0;");

		// Weak
		fprintf(G.f_kis, "0;");

		// Total
		fprintf(G.f_kis, "%lu;", ap_cur->nb_data);

		// Carrier
		fprintf(G.f_kis, ";");

		// Encoding
		fprintf(G.f_kis, ";");

		// FirstTime
		fprintf(G.f_kis, "%s", ctime(&ap_cur->tinit));
		fseek(G.f_kis, -1, SEEK_CUR);
		fprintf(G.f_kis, ";");

		// LastTime
		fprintf(G.f_kis, "%s", ctime(&ap_cur->tlast));
		fseek(G.f_kis, -1, SEEK_CUR);
		fprintf(G.f_kis, ";");

		// BestQuality
		fprintf(G.f_kis, "%d;", ap_cur->avg_power);

		// BestSignal
		fprintf(G.f_kis, "0;");

		// BestNoise
		fprintf(G.f_kis, "0;");

		// GPSMinLat
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_min[0]);

		// GPSMinLon
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_min[1]);

		// GPSMinAlt
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_min[2]);

		// GPSMinSpd
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_min[3]);

		// GPSMaxLat
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_max[0]);

		// GPSMaxLon
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_max[1]);

		// GPSMaxAlt
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_max[2]);

		// GPSMaxSpd
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_max[3]);

		// GPSBestLat
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_best[0]);

		// GPSBestLon
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_best[1]);

		// GPSBestAlt
		fprintf(G.f_kis, "%.6f;", ap_cur->gps_loc_best[2]);

		// DataSize
		fprintf(G.f_kis, "0;");

		// IPType
		fprintf(G.f_kis, "0;");

		// IP
		fprintf(G.f_kis,
				"%d.%d.%d.%d;",
				ap_cur->lanip[0],
				ap_cur->lanip[1],
				ap_cur->lanip[2],
				ap_cur->lanip[3]);

		fprintf(G.f_kis, "\r\n");

		ap_cur = ap_cur->next;
		k++;
	}

	fflush(G.f_kis);
	return (0);
}
