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

#ifndef _AIRODUMP_NG_DUMP_WRITE_H_
#define _AIRODUMP_NG_DUMP_WRITE_H_

#include "ap_list.h"
#include "aircrack-ng/osdep/sta_list.h"

typedef enum dump_type_t
{
    dump_type_csv,
    dump_type_wifi_scanner,
    dump_type_kismet_csv,
    dump_type_kismet_netxml
} dump_type_t;

typedef struct dump_context_st dump_context_st;

struct dump_context_st * dump_open(
    dump_type_t const dump_type,
    char const * const filename,
    char const * const sys_name,
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds,
    char const * const airodump_start_time,
    bool const use_gpsd);

void dump_write(
    dump_context_st * const dump,
    struct ap_list_head * const ap_list,
    struct sta_list_head * const sta_list,
    unsigned int const f_encrypt); 

void dump_close(
    dump_context_st * const dump);


int dump_write_airodump_ng_logcsv_add_ap(const struct AP_info * ap_cur,
										 const int32_t ri_power,
										 struct tm * tm_gpstime,
										 float const * const gps_loc);

int dump_write_airodump_ng_logcsv_add_client(const struct AP_info * ap_cur,
											 const struct ST_info * st_cur,
											 const int32_t ri_power,
											 struct tm * tm_gpstime,
											 float const * const gps_loc);

int dump_write_kismet_netxml(struct ap_list_head * const ap_list,
                             struct sta_list_head * const sta_list,
							 unsigned int f_encrypt,
							 char * airodump_start_time);

#endif /* _AIRODUMP_NG_DUMP_WRITE_H_ */