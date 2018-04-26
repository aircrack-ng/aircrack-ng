/*
 * Copyright (c) 2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
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

#ifndef _OSDEP_NEXMON_H_
#define _OSDEP_NEXMON_H_

#define NEXUTIL_ERROR -1
#define NEXUTIL_NO_MONITOR_MODE 0
#define NEXUTIL_80211_HEADERS 1
#define NEXUTIL_RADIOTAP_HEADERS 2

#define NEXUTIL_MIN_RET_VALUE 0
#define NEXUTIL_MAX_RET_VALUE NEXUTIL_RADIOTAP_HEADERS

int get_nexutil_mon_value(const char * iface);
int is_nexmon(const char * iface);

#endif /* _OSDEP_NEXMON_H_ */