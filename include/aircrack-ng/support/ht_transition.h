/*
 *  OS dependent APIs for Linux
 *
 *  Copyright (C) 2019 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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
 
#ifndef SUPPORT_HT_TRANSITION_H
#define SUPPORT_HT_TRANSITION_H

#include <aircrack-ng/osdep/osdep.h>
#include <aircrack-ng/osdep/common.h>
#include <stdlib.h>

IMPORT int transition_set_channel(const struct wif * swip, const int chan, const uint8_t htval);
IMPORT int transition_set_freq(const struct wif * swip, const int freq, const uint8_t htval);

#endif /* SUPPORT_HT_TRANSITION_H */