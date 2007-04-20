/*-
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * Networking structures.
 *
 */

#ifndef __AIRCRACK_NG_OSDEP_NETWORK_H__
#define __AIRCRACK_NG_OSDEP_NETWORK_H__

enum {
	NET_RC = 1,
	NET_GET_CHAN,
	NET_SET_CHAN,
	NET_WRITE,
	NET_PACKET,
	NET_MAC,
};

struct net_hdr {
	uint8_t		nh_type;
	uint32_t	nh_len;
	uint8_t		nh_data[0];
};

struct wif *net_open(char *iface);

#endif /* __AIRCRACK_NG_OSEDEP_NETWORK_H__ */
