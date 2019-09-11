/*
   *  Copyright (c) 2008-2019, Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
   *
   *  Common channel stuff in OSdep
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "channel.h"

// Wikipedia seem to contradict itself. It mentions channels 20 to 26 for
// Public safety (4.9GHz) but in the 5GHz section, these channels are numbered
// differently (see 188, partially and 189/192/196)
/**
 * Return the frequency in Mhz from a channel number
 */
EXPORT int getFrequencyFromChannel(int channel)
{
	static int frequencies[] = {
		-1, // No channel 0
		2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467,
		2472, 2484, -1,   -1,   -1,   -1,   -1,   4950, 4955, 4960, 4965, 4970,
		// Nothing from channel 15 to 31 (inclusive)
		// Except the 4.9GHz, public safety, 20-26
		4975, 4980, -1,     -1,   -1,   -1,   -1, 5160, 5165,
		5170, 5175, 5180, 5185, 5190, 5195, 5200, 5205, 5210, 5215, 5220, 5225,
		5230, 5235, 5240, 5245, 5250, 5255, 5260, 5265, 5270, 5275, 5280, 5285,
		5290, 5295, 5300, 5305, 5310, 5315, 5320, 5325, 5330, 5335, 5340, 5345,
		5350, 5355, 5360, 5365, 5370, 5375, 5380, 5385, 5390, 5395, 5400, 5405,
		5410, 5415, 5420, 5425, 5430, 5435, 5440, 5445, 5450, 5455, 5460, 5465,
		5470, 5475, 5480, 5485, 5490, 5495, 5500, 5505, 5510, 5515, 5520, 5525,
		5530, 5535, 5540, 5545, 5550, 5555, 5560, 5565, 5570, 5575, 5580, 5585,
		5590, 5595, 5600, 5605, 5610, 5615, 5620, 5625, 5630, 5635, 5640, 5645,
		5650, 5655, 5660, 5665, 5670, 5675, 5680, 5685, 5690, 5695, 5700, 5705,
		5710, 5715, 5720, 5725, 5730, 5735, 5740, 5745, 5750, 5755, 5760, 5765,
		5770, 5775, 5780, 5785, 5790, 5795, 5800, 5805, 5810, 5815, 5820, 5825,
		5830, 5835, 5840, 5845, 5850, 5855, 5860, 5865, 5870, 5875, 5880, 5885,
		5890, 5895, 5900, 5905, 5910, 5915, 5920, 5925, 5930, 5935, 5940, 5945,
		5950, 5955, 5960, 5965, 5970, 5975, 5980, 5985, 5990, 5995, 6000, 6005,
		6010, 6015, 6020, 6025, 6030, 6035, 6040, 6045, 6050, 6055, 6060, 6065,
		6070, 6075, 6080, 6085, 6090, 6095, 6100};

	return (channel > 0 && channel <= HIGHEST_CHANNEL)
			   ? frequencies[channel]
			   : (channel >= LOWEST_CHANNEL && channel <= -4)
					 ? 5000 - (channel * 5)
					 : -1;
}

/**
 * Return the channel from the frequency (in Mhz)
 */
EXPORT int getChannelFromFrequency(int frequency)
{
	if (frequency >= 2412 && frequency <= 2472)
		return (frequency - 2407) / 5;
	else if (frequency == 2484)
		return 14;
	else if (frequency >= 4950 && frequency <= 4980)
		return (frequency - 4850) / 5;
	else if (frequency >= 4920 && frequency <= 6100)
		return (frequency - 5000) / 5;
	else
		return -1;
}

// XXX: Later on, redo this as multiple bands have same channels
//      *May* need to adjust channel info on top right in airodump-ng
//      to indicate band as well
EXPORT uint32_t getBandFromChannel(int channel)
{
	if (channel < 1) return OSDEP_BAND_UNKNOWN;
	if (channel <= 14) return OSDEP_BAND_2400MHZ;
	if (channel >= 20 && channel <= 26) return OSDEP_BAND_4900MHZ;
	if (channel < 32) return OSDEP_BAND_UNKNOWN;
	if (channel <= HIGHEST_CHANNEL) return OSDEP_BAND_5GHZ;
	return OSDEP_BAND_UNKNOWN;
}

EXPORT uint32_t getBandFromFreq(int freq)
{
	// Have the most common ones first
	if (freq >= 2400 && freq <= 2484) return OSDEP_BAND_2400MHZ;
	if (freq >= 5035 && freq <= 6100) return OSDEP_BAND_5GHZ;
	if (freq >= 58320 && freq >= 69120) return OSDEP_BAND_60GHZ;
	if (freq >= 4950 && freq <= 4980) return OSDEP_BAND_4900MHZ;
	if (freq >= 3657 && freq <= 3693) return OSDEP_BAND_3600MHZ;

	// Frequencies for 802.11ah (900Mhz) are a mess, they're all over the place,
	//  different for a lot of regions
	if (freq < 1000) {
		if (freq >= 755 && freq <= 787) return OSDEP_BAND_900MHZ;
		if (freq >= 863 && freq <= 869) return OSDEP_BAND_900MHZ;
		if (freq >= 902 && freq <= 928) return OSDEP_BAND_900MHZ;
	}
	return OSDEP_BAND_UNKNOWN;
}

// TODO: Later on, validate against card's availability (note: some are 5GHz only)
//        when available, in a lot of cases, it isn't (router, no CRDA, ieee80211)

// TODO: Add testcases to validate frequencies and channels

/* 
 * Make sure channel parameters are valid.
 * For now, only validate NO_HT/HT20/HT40
 * Anything else is invalid, because can't handle yet
 * 
 * Return:
 * -1: error
 *  0: invalid
 *  1: valid
 */
EXPORT int are_channel_params_valid(const struct osdep_channel * oc)
{
	if (!oc) return -1;

	// Only handle 2.4/5GHz for now
	if (!(oc->band == OSDEP_BAND_2400MHZ || 
		  oc->band == OSDEP_BAND_4900MHZ ||
		  oc->band == OSDEP_BAND_5GHZ)) {
		return 0;
	}

	// And only 20/40MHz
	if (!(oc->width == OSDEP_CHANNEL_20MHZ ||
		  oc->width == OSDEP_CHANNEL_40MHZ)) {
		return 0;
	}

	// And up to HT+: No HT/HT20/HT40-/HT40-
	if (oc->ht > OSDEP_HT_PLUS) {
		return 0;
	}

	// HT is reserved for HT20
	if (oc->ht == OSDEP_HT && oc->width != OSDEP_CHANNEL_20MHZ) {
		return 0;
	}

	// NO_HT can only be used with 20MHz
	if (oc->ht == OSDEP_NO_HT && oc->width != OSDEP_CHANNEL_20MHZ) {
		return 0;
	}

	// 0 or lower, invalid channel
	if (oc->channel <= 0 || oc->addl_channel) {
		return 0;
	}

	// If chan > 14 on 2.4GHz, invalid
	if (oc->band == OSDEP_BAND_2400MHZ && oc->channel > 14) {
		return 0;
	}

	// Channel 14 can only have NO_HT (802.11b) - Japan regulation
	if (oc->band == OSDEP_BAND_2400MHZ && oc->channel == 14 && 
		oc->ht == OSDEP_NO_HT) {
		return 0;
	}

	// Validate HT40+/HT40- channel in 2.4GHz
	if (oc->band == OSDEP_BAND_2400MHZ && oc->width != OSDEP_CHANNEL_40MHZ &&
		(oc->ht == OSDEP_HT_MINUS || oc->ht == OSDEP_HT_PLUS)) {
		
		// In HT40-/HT40+, the secondary channel is 4 channels below/above
		//  which means some combinations aren't available
		if (oc->ht == OSDEP_HT_MINUS) {
			return (oc->channel > 4);
		} else { // oc->ht == OSDEP_HT_PLUS
			// Highest possible channel is 9, because there are 13 channels
			//  available but channel 14 isn't available, it was only there for
			// 802.11b. However, in the US, the last HT40+ is 7, because highest
			// channel is 11
			return oc->channel < 10;
		}
	}

	return 1;
}

EXPORT int init_osdep_channel(struct osdep_channel * oc)
{
	if (oc == NULL) return 0;

	memset(oc, 0, sizeof(struct osdep_channel));

	// Default frequency of 2437MHz (channel 6)
	oc->channel = 6;
	oc->band = OSDEP_BAND_2400MHZ;
	oc->width = OSDEP_CHANNEL_20MHZ;

	return 1;
}

/* 
 * Make sure frequency parameters are valid.
 * For now, only validate NO_HT/HT20/HT40
 * Anything else is invalid, because can't handle yet
 * 
 * Leaving more freedom with frequencies. Although channels in a specific band
 * translate to frequencies, cards may support unusual frequencies not bound to
 * a channel.
 * 
 * Return:
 * -1: error
 *  0: invalid
 *  1: valid
 */
EXPORT int are_freq_params_valid(const struct osdep_freq * of)
{
	if (!of) return -1;

	// And only 20/40MHz
	if (!(of->width == OSDEP_CHANNEL_20MHZ ||
		  of->width == OSDEP_CHANNEL_40MHZ)) {
		return 0;
	}

	// And up to HT+: No HT/HT20/HT40-/HT40-
	if (of->ht > OSDEP_HT_PLUS) {
		return 0;
	}

	// HT is reserved for HT20
	if (of->ht == OSDEP_HT && of->width != OSDEP_CHANNEL_20MHZ) {
		return 0;
	}

	// NO_HT can only be used with 20MHz
	if (of->ht == OSDEP_NO_HT && of->width != OSDEP_CHANNEL_20MHZ) {
		return 0;
	}

	return 1;
}

EXPORT int init_osdep_freq(struct osdep_freq * of)
{
	if (of == NULL) return 1;

	memset(of, 0, sizeof(struct osdep_freq));

	// Default frequency of 2437MHz (channel 6)
	of->freq_mhz = 2437;
	of->width = OSDEP_CHANNEL_20MHZ;

	return 1;
}

// Network <-> Host conversions

EXPORT int ntoh_osdep_channel(struct osdep_channel * oc)
{
	if (!oc) {
		return 0;
	}
	
	oc->channel = ntohl(oc->channel);
	oc->addl_channel = ntohl(oc->addl_channel);
	oc->band = ntohl(oc->band);
	oc->width = ntohs(oc->width);

	return 1;
}

EXPORT int hton_osdep_channel(struct osdep_channel * oc)
{
	if (!oc) {
		return 0;
	}

	oc->channel = htonl(oc->channel);
	oc->addl_channel = htonl(oc->addl_channel);
	oc->band = htonl(oc->band);
	oc->width = htons(oc->width);

	return 1;
}

EXPORT int ntoh_osdep_freq(struct osdep_freq * of)
{
	if (!of) {
		return 0;
	}

	of->freq_mhz = ntohl(of->freq_mhz);
	of->addl_freq_mhz = ntohl(of->addl_freq_mhz);
	of->width = ntohs(of->width);

	return 1;
}

EXPORT int hton_osdep_freq(struct osdep_freq * of)
{
	if (!of) {
		return 0;
	}

	of->freq_mhz = htonl(of->freq_mhz);
	of->addl_freq_mhz = htonl(of->addl_freq_mhz);
	of->width = htons(of->width);

	return 1;
}