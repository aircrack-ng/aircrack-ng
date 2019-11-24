/*
   *  Copyright (c) 2008-2019, Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
   *
   *  Transition/Helper functions for complex channel parameters
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

#include <stdint.h>
#include "aircrack-ng/support/ht_transition.h"

// This is temporarily there, the channel stuff is complex to tackle
EXPORT int transition_set_channel(const struct wif * swip, const int chan, const uint8_t htval)
{
	if (swip == NULL || chan <= 0) return -1;

	// Set band
	uint32_t band = getBandFromChannel(chan);
	if (band == OSDEP_BAND_UNKNOWN) return -1;

	// Create structure
	struct osdep_channel oc;
	
	if (init_osdep_channel(&oc) == 0) return -1;

	oc.channel = chan;
	oc.band = band;
	oc.ht = htval;
	if (htval == OSDEP_HT_MINUS || htval == OSDEP_HT_PLUS) {
		oc.width = OSDEP_CHANNEL_40MHZ;
	}

	return wi_set_channel(swip, &oc);
}

EXPORT int transition_set_freq(const struct wif * swip, const int freq, const uint8_t htval)
{
	if (swip == NULL || freq <= 0) return -1;

	// Create structure
	struct osdep_freq of;
	if (init_osdep_freq(&of) == 0)  return -1;

	of.freq_mhz = freq;
	of.ht = htval;
	if (htval == OSDEP_HT_MINUS || htval == OSDEP_HT_PLUS) {
		of.width = OSDEP_CHANNEL_40MHZ;
	}

	return wi_set_freq(swip, &of);
}