/*
 * Functions and macros to obtain 802.11n or ac rates based on MCS index
 *
 * Copyright (C) 2018-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#ifndef MCS_INDEX_RATES_H
#define MCS_INDEX_RATES_H

// http://mcsindex.com/

// 20/40/80/160MHz -> (0, 1, 2, 3)
// 0: long GI, 1: short GI
// amount of spatial streams (minus 1)
// MCS index
extern const float MCS_index_rates[4][2][8][10];

float get_80211n_rate(const int width,
					  const int is_short_GI,
					  const int mcs_index);
float get_80211ac_rate(const int width,
					   const int is_short_GI,
					   const int mcs_idx,
					   const int amount_ss);

#endif // MCS_INDEX_RATES_H
