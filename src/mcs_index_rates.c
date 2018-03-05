 /* 
 * Functions and macros to obtain 802.11n or ac rates based on MCS index
 * 
 * Copyright (C) 2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#include "mcs_index_rates.h"
#include <stdint.h>

// http://mcsindex.com/

// 20/40/80/160MHz -> (0, 1, 2, 3)
// 0: long GI, 1: short GI
// amount of spatial streams (minus 1)
// MCS index
const float MCS_index_rates[4][2][8][10] = 
{
	// 20MHz
	{
		// Long GI
		{
			// Spatial streams
			{ 6.5, 13.0, 19.5, 26, 39, 52, 58.5, 65, 78, 0 },
			{ 13, 26, 39, 52, 78, 104, 117, 130, 156, 0 },
			{ 19.5, 39, 58.5, 78, 117, 156, 175.5, 195, 234, 260 },
			{ 26, 52, 78, 104, 156, 208, 134, 260, 312, 0}
		},
		// Short GI
		{
			{ 7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65, 72.2, 86.7, 0 },
			{ 14.4, 28.9, 43.3, 57.8, 86.7, 115.6, 130.3, 144.4, 173.3, 0 },
			{ 21.7, 43.3, 65, 86.7, 130, 173.3, 195, 216.7, 260, 288.9 },
			{ 28.9, 57.8, 56.7, 115.6, 173.3, 231.1, 260, 288.9, 346.7, 0}
		}
	},
	// 40MHz
	{
		// Long GI
		{
			{ 13.5, 27, 40.5, 54, 81, 108, 121.5, 135, 162, 180 },
			{ 27, 54, 81, 108, 162, 216, 243, 270, 324, 360 },
			{ 40.5, 81, 121.5, 162, 243, 324, 364.5, 405, 486, 540 },
			{ 54, 108, 162, 216, 324, 432, 486, 540, 648, 720 }
		},
		// Short GI
		{
			{ 15, 30, 45, 60, 90, 120, 135, 150, 180, 200 },
			{ 30, 60, 90, 120, 180, 240, 270, 300, 360, 400 },
			{ 45, 90, 135, 180, 270, 360, 405, 450, 540, 600 },
			{ 60, 120, 180, 240, 360, 480, 540, 600, 720, 800 }
		}
	},
	// 80MHz
	{
		// Long GI
		{
			{ 29.3, 58.5, 87.8, 117, 175.5, 234, 263.3, 292.5, 351, 390 },
			{ 58.5, 117, 175.5, 234, 351, 468, 526.5, 585, 702, 780 },
			{ 87.8, 175.5, 263.3, 351, 526.5, 702, 0, 877.5, 1053, 1170 },
			{ 117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560 },
			{ 146.3, 292.5, 438.8, 585, 877.5, 1170, 1316.3, 1462.5, 1755, 1950 },
			{ 175.5, 351, 526.5, 702, 1053, 1404, 1579.5, 1755, 2106, 0 },
			{ 204.8, 409.5, 614.3, 819, 1228.5, 1638, 0, 2047.5, 2457, 2730 },
			{ 234, 468, 702, 936, 1404, 1872, 2106, 2340, 2808, 3120 }
		},
		// Short GI
		{
			{ 32.5, 65, 97.5, 130, 195, 260, 292.5, 325, 390, 433.3 },
			{ 65, 130, 195, 260, 390, 520, 585, 650, 780, 866.7 },
			{ 97.5, 195, 292.5, 390, 585, 780, 0, 975, 1170, 1300 },
			{ 130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733.3 },
			{ 162.5, 325, 487.5, 650, 975, 1300, 1462.5, 1625, 1950, 2166.7 },
			{ 195, 390, 585, 780, 1170, 1560, 1755, 1950, 2340, 0 },
			{ 227.5, 455, 682.5, 910, 1365, 1820, 0, 2275, 2730, 3033.3 },
			{ 260, 520, 780, 1040, 1560, 2080, 2340, 2600, 3120, 3466.7 }
		}
	},
	// 160MHz
	{
		// Long GI
		{
			{ 58.5, 117, 175.5, 234, 351, 468, 526.5, 585, 702, 780 },
			{ 117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560 },
			{ 175.5, 351, 526.5, 702, 1053, 1404, 1579.5, 1755, 2106, 0 },
			{ 234, 468, 702, 936, 1404, 1872, 2106, 2340, 2808, 3120 },
			{ 292.5, 585, 877.5, 1170, 1755, 2340, 2632.5, 2925, 3510, 3900 },
			{ 351, 702, 1053, 1404, 2106, 2808, 3159, 3510, 4212, 4680 },
			{ 409.5, 819, 1228.5, 1638, 2457, 3276, 3685.5, 4095, 4914, 5460 },
			{ 468, 936, 1404, 1872, 2808, 3744, 4212, 4680, 5616, 6240 }
		},
		// Short GI
		{
			{ 65, 130, 195, 260, 390, 520, 585, 650, 780, 866.7 },
			{ 130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733.3 },
			{ 195, 390, 585, 780, 1170, 1560, 1755, 1950, 2340, 0 },
			{ 260, 520, 780, 1040, 1560, 2080, 2340, 2600, 3120, 3466.7 },
			{ 325, 650, 975, 1300, 1950, 2600, 2925, 3250, 3900, 4333.3 },
			{ 390, 780, 1170, 1560, 2340, 3120, 3510, 3900, 4680, 5200 },
			{ 455, 910, 1365, 1820, 2730, 3640, 4095, 4550, 5460, 6066.7 },
			{ 520, 1040, 1560, 2080, 3120, 4160, 4680, 5200, 6240, 6933.3 }
		}
	}
};

float get_80211n_rate(const int width, const int is_short_GI, const int mcs_index)
{
	// Check MCS Index
	if (mcs_index < 0 || mcs_index > 31) {
		return -1.0;
	}
	uint8_t amount_ss = mcs_index / 8;
	uint8_t mcs_idx = mcs_index % 8;

	// Rate index
	uint8_t width_idx = 0;
	switch (width) {
		case 20:
			width_idx = 0;
			break;
		case 40:
			width_idx = 1;
			break;
		default:
			return -1.0;
	}

	// Short GI?
	uint8_t sgi = !!is_short_GI;

	return MCS_index_rates[width_idx][sgi][amount_ss][mcs_idx];
}

float get_80211ac_rate(const int width, const int is_short_GI, const int mcs_idx, const int amount_ss)
{
	// Check MCS Index
	if (mcs_idx < 0 || mcs_idx > 9) {
		return -1.0;
	}

	// Rate index
	uint8_t width_idx = 0;
	switch (width) {
		case 20:
			width_idx = 0;
			break;
		case 40:
			width_idx = 1;
			break;
		case 80:
			width_idx = 2;
			break;
		case 160:
			width_idx = 3;
			break;
		default:
			return -1.0;
	}

	// Check amount of spatial streams
	if (amount_ss < 1 || amount_ss > 8) {
		return -1.0;
	}

	// Short GI?
	uint8_t sgi = !!is_short_GI;

	return MCS_index_rates[width_idx][sgi][amount_ss - 1][mcs_idx];
}
