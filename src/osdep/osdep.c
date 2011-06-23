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
  *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "osdep.h"
#include "network.h"

extern struct wif *file_open(char *iface);

int wi_read(struct wif *wi, unsigned char *h80211, int len, struct rx_info *ri)
{
        assert(wi->wi_read);
        return wi->wi_read(wi, h80211, len, ri);
}

int wi_write(struct wif *wi, unsigned char *h80211, int len,
             struct tx_info *ti)
{
        assert(wi->wi_write);
        return wi->wi_write(wi, h80211, len, ti);
}

int wi_set_channel(struct wif *wi, int chan)
{
        assert(wi->wi_set_channel);
        return wi->wi_set_channel(wi, chan);
}

int wi_get_channel(struct wif *wi)
{
	assert(wi->wi_get_channel);
        return wi->wi_get_channel(wi);
}

int wi_set_freq(struct wif *wi, int freq)
{
        assert(wi->wi_set_freq);
        return wi->wi_set_freq(wi, freq);
}

int wi_get_freq(struct wif *wi)
{
	assert(wi->wi_get_freq);
        return wi->wi_get_freq(wi);
}

int wi_get_monitor(struct wif *wi)
{
        assert(wi->wi_get_monitor);
        return wi->wi_get_monitor(wi);
}

char *wi_get_ifname(struct wif *wi)
{
        return wi->wi_interface;
}

void wi_close(struct wif *wi)
{
        assert(wi->wi_close);
        wi->wi_close(wi);
}

int wi_fd(struct wif *wi)
{
	assert(wi->wi_fd);
	return wi->wi_fd(wi);
}

struct wif *wi_alloc(int sz)
{
        struct wif *wi;
	void *priv;

        /* Allocate wif & private state */
        wi = malloc(sizeof(*wi));
        if (!wi)
                return NULL;
        memset(wi, 0, sizeof(*wi));

        priv = malloc(sz);
        if (!priv) {
                free(wi);
                return NULL;
        }
        memset(priv, 0, sz);
        wi->wi_priv = priv;

	return wi;
}

void *wi_priv(struct wif *wi)
{
	return wi->wi_priv;
}

int wi_get_mac(struct wif *wi, unsigned char *mac)
{
	assert(wi->wi_get_mac);
	return wi->wi_get_mac(wi, mac);
}

int wi_set_mac(struct wif *wi, unsigned char *mac)
{
	assert(wi->wi_set_mac);
	return wi->wi_set_mac(wi, mac);
}

int wi_get_rate(struct wif *wi)
{
	assert(wi->wi_get_rate);
	return wi->wi_get_rate(wi);
}

int wi_set_rate(struct wif *wi, int rate)
{
	assert(wi->wi_set_rate);
	return wi->wi_set_rate(wi, rate);
}

int wi_get_mtu(struct wif *wi)
{
	assert(wi->wi_get_mtu);
	return wi->wi_get_mtu(wi);
}

int wi_set_mtu(struct wif *wi, int mtu)
{
	assert(wi->wi_set_mtu);
	return wi->wi_set_mtu(wi, mtu);
}

struct wif *wi_open(char *iface)
{
	struct wif *wi;

	wi = file_open(iface);
	if (wi == (struct wif*) -1)
		return NULL;
	if (!wi)
		wi = net_open(iface);
	if (!wi)
		wi = wi_open_osdep(iface);
	if (!wi)
		return NULL;

	strncpy(wi->wi_interface, iface, sizeof(wi->wi_interface)-1);
	wi->wi_interface[sizeof(wi->wi_interface)-1] = 0;

	return wi;
}

/* tap stuff */
char *ti_name(struct tif *ti)
{
	assert(ti->ti_name);
	return ti->ti_name(ti);
}

int ti_set_mtu(struct tif *ti, int mtu)
{
	assert(ti->ti_set_mtu);
	return ti->ti_set_mtu(ti, mtu);
}

int ti_get_mtu(struct tif *ti)
{
	assert(ti->ti_get_mtu);
	return ti->ti_get_mtu(ti);
}

void ti_close(struct tif *ti)
{
	assert(ti->ti_close);
	ti->ti_close(ti);
}

int ti_fd(struct tif *ti)
{
	assert(ti->ti_fd);
	return ti->ti_fd(ti);
}

int ti_read(struct tif *ti, void *buf, int len)
{
	assert(ti->ti_read);
	return ti->ti_read(ti, buf, len);
}

int ti_write(struct tif *ti, void *buf, int len)
{
	assert(ti->ti_write);
	return ti->ti_write(ti, buf, len);
}

int ti_set_mac(struct tif *ti, unsigned char *mac)
{
	assert(ti->ti_set_mac);
	return ti->ti_set_mac(ti, mac);
}

int ti_set_ip(struct tif *ti, struct in_addr *ip)
{
	assert(ti->ti_set_ip);
	return ti->ti_set_ip(ti, ip);
}

struct tif *ti_alloc(int sz)
{
        struct tif *ti;
	void *priv;

        /* Allocate tif & private state */
        ti = malloc(sizeof(*ti));
        if (!ti)
                return NULL;
        memset(ti, 0, sizeof(*ti));

        priv = malloc(sz);
        if (!priv) {
                free(ti);
                return NULL;
        }
        memset(priv, 0, sz);
        ti->ti_priv = priv;

	return ti;
}

void *ti_priv(struct tif *ti)
{
	return ti->ti_priv;
}
