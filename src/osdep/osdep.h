/*-
 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * All OS dependent crap should go here.
 *
 */

#ifndef __AIRCRACK_NG_OSEDEP_H__
#define __AIRCRACK_NG_OSEDEP_H__

#include <netinet/in.h>
#include <stdint.h>

#include "packed.h"

/* For all structures, when adding new fields, always append them to the end.
 * This way legacy binary code does not need to be recompiled.  This is
 * particularly useful for DLLs.  -sorbo
 */

struct tx_info {
        unsigned int     ti_rate;
};

struct rx_info {
        uint64_t ri_mactime;
        uint32_t ri_power;
        uint32_t ri_noise;
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
 * them seperate until we learn something.
 */
struct tif {
	int	(*ti_read)(struct tif *ti, void *buf, int len);
	int	(*ti_write)(struct tif *ti, void *buf, int len);
	int	(*ti_fd)(struct tif *ti);
	char	*(*ti_name)(struct tif *ti);
	int	(*ti_set_mtu)(struct tif *ti, int mtu);
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
extern void ti_close(struct tif *ti);
extern int ti_fd(struct tif *ti);
extern int ti_read(struct tif *ti, void *buf, int len);
extern int ti_write(struct tif *ti, void *buf, int len);
extern int ti_set_mac(struct tif *ti, unsigned char *mac);
extern int ti_set_ip(struct tif *ti, struct in_addr *ip);

#endif /* __AIRCRACK_NG_OSEDEP_H__ */
