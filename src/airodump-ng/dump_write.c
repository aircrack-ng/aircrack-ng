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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "aircrack-ng/defs.h"
#include "airodump-ng.h"
#include "aircrack-ng/support/communications.h"
#include "dump_write.h"
#include "dump_write_private.h"
#include "dump_write_wifi_scanner.h"
#include "dump_csv.h"
#include "dump_kismet_csv.h"
#include "dump_kismet_netxml.h"

extern struct communication_options opt;

extern int getFrequencyFromChannel(int channel); // "aircrack-osdep/common.h"

extern int is_filtered_essid(unsigned char * essid); // airodump-ng.c

int dump_write_airodump_ng_logcsv_add_ap(const struct AP_info * ap_cur,
										 const int32_t ri_power,
										 struct tm * tm_gpstime,
										 float const * const gps_loc)
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
											 float const * const gps_loc)
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
    int const file_reset_seconds,
    char const * const airodump_start_time,
    bool const use_gpsd)
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
        case dump_type_kismet_netxml:
            if (!kismet_netxml_dump_open(dump,
                                         filename,
                                         airodump_start_time,
                                         use_gpsd))
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


