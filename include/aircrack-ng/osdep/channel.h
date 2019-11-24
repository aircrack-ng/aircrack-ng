/*
 *  OS dependent APIs for Linux
 *
 *  Copyright (C) 2018-2019 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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
 */

#ifndef OSDEP_CHANNELS_H
#define OSDEP_CHANNELS_H

#include <stdint.h>
#include <aircrack-ng/osdep/common.h>
#include <aircrack-ng/osdep/packed.h>

struct osdep_channel {
	int32_t channel;
	int32_t addl_channel;
	// Secondary channel
	// Only set when using 80+80MHz
	// Or with HT40; -1 indicates HT40-
	//  and +1 indicates HT40+
	uint32_t band;
	// Band is necessary
	// There is channel 1 in 2.4GHz, and also in 60GHz, 
	//  and possibly other bands
	uint16_t width;
	uint8_t ht;
	uint8_t unused;
} __packed;

struct osdep_freq {
	uint32_t freq_mhz;
	uint32_t addl_freq_mhz;
	// Secondary frequency
	// Only set when using 80+80MHz
	// Band isn't necessary since we already know freq
	uint16_t width;
	uint8_t ht;
	uint8_t unused;
} __packed;


#define HIGHEST_CHANNEL 220
#define LOWEST_CHANNEL -16

IMPORT int getFrequencyFromChannel(const int channel);
IMPORT int getChannelFromFrequency(const int frequency);

IMPORT uint32_t getBandFromChannel(const int channel);
IMPORT uint32_t getBandFromFreq(const int freq);

IMPORT int are_channel_params_valid(const struct osdep_channel * oc);
IMPORT int init_osdep_channel(struct osdep_channel * oc);
IMPORT int ntoh_osdep_channel(struct osdep_channel * oc);
IMPORT int hton_osdep_channel(struct osdep_channel * oc);

IMPORT int are_freq_params_valid(const struct osdep_freq * of);
IMPORT int init_osdep_freq(struct osdep_freq * of);
IMPORT int ntoh_osdep_freq(struct osdep_freq * of);
IMPORT int hton_osdep_freq(struct osdep_freq * of);


#define OSDEP_BAND_UNKNOWN 0
#define OSDEP_BAND_900MHZ 900
#define OSDEP_BAND_2400MHZ 2400
// 3657.5 -> 3692.5
#define OSDEP_BAND_3600MHZ 3600
// Public safety -> technically still part of the 5GHz
// 4940-4990 MHz
#define OSDEP_BAND_4900MHZ 4900
#define OSDEP_BAND_5GHZ 5000
// 802.11ad/ay
#define OSDEP_BAND_60GHZ 60000

// Ability to use half MHz channels
#define OSDEP_CHANNEL_1MHZ 2
#define OSDEP_CHANNEL_2MHZ 4
#define OSDEP_CHANNEL_4MHZ 8
#define OSDEP_CHANNEL_5MHZ 10
#define OSDEP_CHANNEL_10MHZ 20
#define OSDEP_CHANNEL_16MHZ 32
// 802.11b is actually 22MHz, but for simplication, use 20MHz
#define OSDEP_CHANNEL_20MHZ 40
#define OSDEP_CHANNEL_40MHZ 80
#define OSDEP_CHANNEL_80MHZ 160
#define OSDEP_CHANNEL_160MHZ 320

#define OSDEP_HT_IGNORE -1
#define OSDEP_NO_HT 0
// Reserved for 20MHz
#define OSDEP_HT 1
// The following two are for HT40-/+
#define OSDEP_HT_MINUS 2
#define OSDEP_HT_PLUS 3
#define OSDEP_VHT 4
// VHT Plus: 80+80MHz
#define OSDEP_VHT_PLUS 5
#define OSDEP_HE 6

// TODO: Create list of channels to hop on in a double array (using the macros
//        above as index.

#endif // OSDEP_CHANNELS_H
