/*
 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * Networking structures.
 *
 */

#ifndef __AIRCRACK_NG_OSDEP_NETWORK_H__
#define __AIRCRACK_NG_OSDEP_NETWORK_H__

#include <inttypes.h>
#include <sys/types.h>

#include "osdep.h"

enum {
	NET_RC = 1,
	NET_GET_CHAN,
	NET_SET_CHAN,
	NET_WRITE,
	NET_PACKET,		/* 5 */
	NET_GET_MAC,
	NET_MAC,
	NET_GET_MONITOR,
	NET_GET_RATE,
	NET_SET_RATE,
};

struct net_hdr {
	uint8_t		nh_type;
	uint32_t	nh_len;
	uint8_t		nh_data[0];
} __packed;

extern struct wif *net_open(char *iface);
extern int net_send(int s, int command, void *arg, int len);
extern int net_read_exact(int s, void *arg, int len);
extern int net_get(int s, void *arg, int *len);




#endif /* __AIRCRACK_NG_OSEDEP_NETWORK_H__ */
