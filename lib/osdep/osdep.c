/*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API.
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
#include <assert.h>
#include <string.h>

#include "osdep.h"
#include "network.h"

extern struct wif * file_open(char * iface);

EXPORT int wi_read(struct wif * wi,
				   struct timespec * ts,
				   int * dlt,
				   unsigned char * h80211,
				   int len,
				   struct rx_info * ri)
{
	assert(wi->wi_read);
	return wi->wi_read(wi, ts, dlt, h80211, len, ri);
}

EXPORT int wi_write(struct wif * wi,
					struct timespec * ts,
					int dlt,
					unsigned char * h80211,
					int len,
					struct tx_info * ti)
{
	assert(wi->wi_write);
	return wi->wi_write(wi, ts, dlt, h80211, len, ti);
}

EXPORT int wi_set_ht_channel(struct wif * wi, int chan, unsigned int htval)
{
	assert(wi->wi_set_ht_channel);
	return wi->wi_set_ht_channel(wi, chan, htval);
}

EXPORT int wi_set_channel(struct wif * wi, int chan)
{
	assert(wi->wi_set_channel);
	return wi->wi_set_channel(wi, chan);
}

EXPORT int wi_get_channel(struct wif * wi)
{
	assert(wi->wi_get_channel);
	return wi->wi_get_channel(wi);
}

EXPORT int wi_set_freq(struct wif * wi, int freq)
{
	assert(wi->wi_set_freq);
	return wi->wi_set_freq(wi, freq);
}

EXPORT int wi_get_freq(struct wif * wi)
{
	assert(wi->wi_get_freq);
	return wi->wi_get_freq(wi);
}

EXPORT int wi_get_monitor(struct wif * wi)
{
	assert(wi->wi_get_monitor);
	return wi->wi_get_monitor(wi);
}

EXPORT char * wi_get_ifname(struct wif * wi) { return wi->wi_interface; }

EXPORT void wi_close(struct wif * wi)
{
	assert(wi->wi_close);
	wi->wi_close(wi);
}

EXPORT int wi_fd(struct wif * wi)
{
	assert(wi->wi_fd);
	return wi->wi_fd(wi);
}

struct wif * wi_alloc(int sz)
{
	struct wif * wi;
	void * priv;

	/* Allocate wif & private state */
	wi = malloc(sizeof(*wi));
	if (!wi) return NULL;
	memset(wi, 0, sizeof(*wi));

	priv = malloc(sz);
	if (!priv)
	{
		free(wi);
		return NULL;
	}
	memset(priv, 0, sz);
	wi->wi_priv = priv;

	return wi;
}

void * wi_priv(struct wif * wi) { return wi->wi_priv; }

EXPORT int wi_get_mac(struct wif * wi, unsigned char * mac)
{
	assert(wi->wi_get_mac);
	return wi->wi_get_mac(wi, mac);
}

EXPORT int wi_set_mac(struct wif * wi, unsigned char * mac)
{
	assert(wi->wi_set_mac);
	return wi->wi_set_mac(wi, mac);
}

EXPORT int wi_get_rate(struct wif * wi)
{
	assert(wi->wi_get_rate);
	return wi->wi_get_rate(wi);
}

EXPORT int wi_set_rate(struct wif * wi, int rate)
{
	assert(wi->wi_set_rate);
	return wi->wi_set_rate(wi, rate);
}

EXPORT int wi_get_mtu(struct wif * wi)
{
	assert(wi->wi_get_mtu);
	return wi->wi_get_mtu(wi);
}

EXPORT int wi_set_mtu(struct wif * wi, int mtu)
{
	assert(wi->wi_set_mtu);
	return wi->wi_set_mtu(wi, mtu);
}

EXPORT struct wif * wi_open(char * iface)
{
	struct wif * wi;

	if (iface == NULL || iface[0] == 0)
	{
		return NULL;
	}

	wi = file_open(iface);
	if (wi == (struct wif *) -1) return NULL;
	if (!wi) wi = net_open(iface);
	if (!wi) wi = wi_open_osdep(iface);
	if (!wi) return NULL;

	strncpy(wi->wi_interface, iface, sizeof(wi->wi_interface) - 1);
	wi->wi_interface[sizeof(wi->wi_interface) - 1] = 0;

	return wi;
}

/* tap stuff */
EXPORT char * ti_name(struct tif * ti)
{
	assert(ti->ti_name);
	return ti->ti_name(ti);
}

EXPORT int ti_set_mtu(struct tif * ti, int mtu)
{
	assert(ti->ti_set_mtu);
	return ti->ti_set_mtu(ti, mtu);
}

EXPORT int ti_get_mtu(struct tif * ti)
{
	assert(ti->ti_get_mtu);
	return ti->ti_get_mtu(ti);
}

EXPORT void ti_close(struct tif * ti)
{
	assert(ti->ti_close);
	ti->ti_close(ti);
}

EXPORT int ti_fd(struct tif * ti)
{
	assert(ti->ti_fd);
	return ti->ti_fd(ti);
}

EXPORT int ti_read(struct tif * ti, void * buf, int len)
{
	assert(ti->ti_read);
	return ti->ti_read(ti, buf, len);
}

EXPORT int ti_write(struct tif * ti, void * buf, int len)
{
	assert(ti->ti_write);
	return ti->ti_write(ti, buf, len);
}

EXPORT int ti_set_mac(struct tif * ti, unsigned char * mac)
{
	assert(ti->ti_set_mac);
	return ti->ti_set_mac(ti, mac);
}

EXPORT int ti_set_ip(struct tif * ti, struct in_addr * ip)
{
	assert(ti->ti_set_ip);
	return ti->ti_set_ip(ti, ip);
}

struct tif * ti_alloc(int sz)
{
	struct tif * ti;
	void * priv;

	/* Allocate tif & private state */
	ti = malloc(sizeof(*ti));
	if (!ti) return NULL;
	memset(ti, 0, sizeof(*ti));

	priv = malloc(sz);
	if (!priv)
	{
		free(ti);
		return NULL;
	}
	memset(priv, 0, sz);
	ti->ti_priv = priv;

	return ti;
}

void * ti_priv(struct tif * ti) { return ti->ti_priv; }
