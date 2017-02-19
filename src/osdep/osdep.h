/* 
 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 * All OS dependent crap should go here.
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

#ifndef __AIRCRACK_NG_OSEDEP_H__
#define __AIRCRACK_NG_OSEDEP_H__

#include <netinet/in.h>
#include <stdint.h>

#include "byteorder.h"
#include "packed.h"

#if defined(__APPLE_CC__) && defined(_XCODE)
#include <pcap/bpf.h>
#undef	LINKTYPE_RADIOTAP_HDR
#define LINKTYPE_RADIOTAP_HDR   DLT_IEEE802_11_RADIO
#undef	LINKTYPE_IEEE802_11
#define LINKTYPE_IEEE802_11     DLT_IEEE802_11
#undef	LINKTYPE_PRISM_HEADER
#define LINKTYPE_PRISM_HEADER   DLT_PRISM_HEADER
#undef	LINKTYPE_ETHERNET
#define LINKTYPE_ETHERNET       DLT_ERF_ETH
#undef	LINKTYPE_PPI_HDR
#define LINKTYPE_PPI_HDR        DLT_PPI
#undef	TCPDUMP_MAGIC
#define TCPDUMP_MAGIC           0xa1b2c3d4
#endif

/* For all structures, when adding new fields, always append them to the end.
 * This way legacy binary code does not need to be recompiled.  This is
 * particularly useful for DLLs.  -sorbo
 */

struct tx_info {
        unsigned int     ti_rate;
};

struct rx_info {
        uint64_t ri_mactime;
        int32_t ri_power;
        int32_t ri_noise;
        uint32_t ri_channel;
        uint32_t ri_freq;
        uint32_t ri_rate;
        uint32_t ri_antenna;
} __packed;

/* Normal code should not access this directly.  Only osdep.
 * This structure represents a single interface.  It should be created with
 * wi_open and destroyed with wi_close.
 */
#define MAX_IFACE_NAME	64
struct wif {
        int     (*wi_read)(struct wif *wi, unsigned char *h80211, int len,
                           struct rx_info *ri);
        int     (*wi_write)(struct wif *wi, unsigned char *h80211, int len,
                            struct tx_info *ti);
        int     (*wi_set_channel)(struct wif *wi, int chan);
        int     (*wi_get_channel)(struct wif *wi);
        int     (*wi_set_freq)(struct wif *wi, int freq);
        int     (*wi_get_freq)(struct wif *wi);
	void	(*wi_close)(struct wif *wi);
	int	(*wi_fd)(struct wif *wi);
	int	(*wi_get_mac)(struct wif *wi, unsigned char *mac);
	int	(*wi_set_mac)(struct wif *wi, unsigned char *mac);
	int	(*wi_set_rate)(struct wif *wi, int rate);
	int	(*wi_get_rate)(struct wif *wi);
	int	(*wi_set_mtu)(struct wif *wi, int mtu);
	int	(*wi_get_mtu)(struct wif *wi);
        int     (*wi_get_monitor)(struct wif *wi);

        void	*wi_priv;
        char	wi_interface[MAX_IFACE_NAME];
};

/* Routines to be used by client code */
extern struct wif *wi_open(char *iface);
extern int wi_read(struct wif *wi, unsigned char *h80211, int len,
		   struct rx_info *ri);
extern int wi_write(struct wif *wi, unsigned char *h80211, int len,
		    struct tx_info *ti);
extern int wi_set_channel(struct wif *wi, int chan);
extern int wi_get_channel(struct wif *wi);
extern int wi_set_freq(struct wif *wi, int freq);
extern int wi_get_freq(struct wif *wi);
extern void wi_close(struct wif *wi);
extern char *wi_get_ifname(struct wif *wi);
extern int wi_get_mac(struct wif *wi, unsigned char *mac);
extern int wi_set_mac(struct wif *wi, unsigned char *mac);
extern int wi_get_rate(struct wif *wi);
extern int wi_set_rate(struct wif *wi, int rate);
extern int wi_get_monitor(struct wif *wi);
extern int wi_get_mtu(struct wif *wi);
extern int wi_set_mtu(struct wif *wi, int mtu);

/* wi_open_osdep should determine the type of card and setup the wif structure
 * appropriately.  There is one per OS.  Called by wi_open.
 */
extern struct wif *wi_open_osdep(char *iface);

/* This will return the FD used for reading.  This is required for using select
 * on it.
 */
extern int wi_fd(struct wif *wi);

/* Helper routines for osdep code.  */
extern struct wif *wi_alloc(int sz);
extern void *wi_priv(struct wif *wi);

/* Client code can use this to determine the battery state.  One per OS. */
extern int get_battery_state(void);

/* Client code can create a tap interface */
/* XXX we can unify the tap & wi stuff in the future, but for now, lets keep
 * them separate until we learn something.
 */
struct tif {
	int	(*ti_read)(struct tif *ti, void *buf, int len);
	int	(*ti_write)(struct tif *ti, void *buf, int len);
	int	(*ti_fd)(struct tif *ti);
	char	*(*ti_name)(struct tif *ti);
	int	(*ti_set_mtu)(struct tif *ti, int mtu);
	int	(*ti_get_mtu)(struct tif *ti);
	int	(*ti_set_ip)(struct tif *ti, struct in_addr *ip);
	int	(*ti_set_mac)(struct tif *ti, unsigned char *mac);
	void	(*ti_close)(struct tif *ti);

	void	*ti_priv;
};
/* one per OS */
extern struct tif *ti_open(char *iface);

/* osdep routines */
extern struct tif *ti_alloc(int sz);
extern void *ti_priv(struct tif *ti);

/* client routines */
extern char *ti_name(struct tif *ti);
extern int ti_set_mtu(struct tif *ti, int mtu);
extern int ti_get_mtu(struct tif *ti);
extern void ti_close(struct tif *ti);
extern int ti_fd(struct tif *ti);
extern int ti_read(struct tif *ti, void *buf, int len);
extern int ti_write(struct tif *ti, void *buf, int len);
extern int ti_set_mac(struct tif *ti, unsigned char *mac);
extern int ti_set_ip(struct tif *ti, struct in_addr *ip);

#endif /* __AIRCRACK_NG_OSEDEP_H__ */
