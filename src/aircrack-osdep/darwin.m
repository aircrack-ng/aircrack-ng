/*
  *  Copyright (c) 2018, Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
  *  freebsd.c by Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for Darwin.
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

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <pcap.h>
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#include "osdep.h"

#include "radiotap/radiotap.h"

struct priv_darwin
{
	struct pcap_t *pp;
	CWInterface *interface;
	NSSet *channels;
};

static void do_free(struct wif *wi)
{
	if (wi)
	{
		if (wi->wi_priv)
		{
			struct priv_darwin *pn = (struct priv_darwin *) wi->wi_priv;
			// XXX: Do we need to free interface ?
			//if (pn->interface) {
			//	[pn->interface release];
			//}
			free(wi->wi_priv);
			wi->wi_priv = 0;
		}
		free(wi);
	}
}

static int darwin_set_channel(struct wif *wi, int chan)
{
	if (chan < 1)
	{
		return -1;
	}

	struct priv_darwin *pn = wi_priv(wi);

	return 0;
}

static int
darwin_write(struct wif *wi, unsigned char *h80211, int len, struct tx_info *ti)
{
	struct priv_darwin *pn = wi_priv(wi);
	int rc;

	/* XXX make use of ti */
	if (ti)
	{
	}

	return 0;
}

static void darwin_close(struct wif *wi)
{
	struct priv_darwin *pn = wi_priv(wi);

	do_free(wi);
}

static int darwin_get_channel(struct wif *wi) { return 0; }

static int
darwin_read(struct wif *wi, unsigned char *h80211, int len, struct rx_info *ri)
{
	return 0;
}

static int darwin_set_mac(struct wif *wi, unsigned char *mac)
{
	// NOT SUPPORTED
	return 0;
}

static int darwin_get_monitor(struct wif *wi)
{
	if (wi)
	{
	} /* XXX unused */
	/* XXX */
	return 0;
}

static int darwin_get_rate(struct wif *wi)
{
	struct priv_darwin *pn = wi_priv(wi);
	return 100000;
}

static int darwin_set_rate(struct wif *wi, int rate)
{
	// not supported

	return 0;
}

static int darwin_fd(struct wif *wi)
{
	struct priv_darwin *pn = wi_priv(wi);
	return -1;
}

static int darwin_get_mac(struct wif *wi, unsigned char *mac) { return 0; }

static int do_darwin_open(struct wif *wi, char *iface)
{
	int i;
	NSArray<CWInterface *> *cw_interfaces =
		[[CWWiFiClient sharedWiFiClient] interfaces];

	CWInterface *found = NULL;

	for (i = 0; i < [cw_interfaces count]; ++i)
	{
		if (strcmp([[cw_interfaces[i] interfaceName] UTF8String], iface) == 0)
		{
			found = cw_interfaces[i];
			break;
		}
	}

	if (found)
	{
		struct priv_darwin *pn = wi_priv(wi);
		pn->interface = found;

		// Disassociate
		[found disassociate];

		// Get channel list
		pn->channels = [found supportedWLANChannels];

		return 0;
	}

	return -1;
}

static struct wif *darwin_open(char *iface)
{
	struct wif *wi;
	struct priv_darwin *pn;
	int fd;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*pn));
	if (!wi) return NULL;

	wi->wi_read = darwin_read;
	wi->wi_write = darwin_write;
	wi->wi_set_channel = darwin_set_channel;
	wi->wi_get_channel = darwin_get_channel;
	wi->wi_close = darwin_close;
	wi->wi_fd = darwin_fd;
	wi->wi_get_mac = darwin_get_mac;
	wi->wi_set_mac = darwin_set_mac;
	wi->wi_get_rate = darwin_get_rate;
	wi->wi_set_rate = darwin_set_rate;
	wi->wi_get_monitor = darwin_get_monitor;

	/* setup iface */
	fd = do_darwin_open(wi, iface);
	if (fd == -1)
	{
		do_free(wi);
		return NULL;
	}

	/* setup private state */
	pn = wi_priv(wi);

	return wi;
}

struct wif *wi_open_osdep(char *iface) { return darwin_open(iface); }

EXPORT int get_battery_state(void)
{
	// Try using IOKit and the IOPowerSources functions.
	// IOPSCopyPowerSourcesInfo() -> IOPSCopyPowerSourcesList() -> extract a CFArray (listing the power sources) -> IOPSGetPowerSourceDescription() to grab the dictionary.

	//CFTypeRef iops = IOPSCopyPowerSourcesInfo();

	errno = EOPNOTSUPP;
	return -1;
}