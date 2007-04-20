/*-
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * All OS dependent crap should go here.
 *
 */

#ifndef __AIRCRACK_NG_OSEDEP_H__
#define __AIRCRACK_NG_OSEDEP_H__

/* Empty for now.  Could contain antenna, power, rate, etc. */
struct tx_info {
};

struct rx_info {
        int     ri_power;
        int     ri_noise;
        int     ri_channel;
};

/* Normal code should not access this directly.  Only osdep.
 * This structure represents a single interface.  It should be created with
 * wi_open and destroyed with wi_close.
 */
struct wif {
        int     (*wi_read)(struct wif *wi, unsigned char *h80211, int len,
                           struct rx_info *ri);
        int     (*wi_write)(struct wif *wi, unsigned char *h80211, int len,
                            struct tx_info *ti);
        int     (*wi_set_channel)(struct wif *wi, int chan);
        int     (*wi_update_channel)(struct wif *wi);
	void	(*wi_close)(struct wif *wi);
	int	(*wi_fd)(struct wif *wi);
        void    *wi_priv;
        int     channel;
        char    *interface;
        unsigned char mac[6];
};

/* Routines to be used by client code */
/* wi_open should determine the type of card and setup the wif structure
 * appropriately.  There is one per OS.
 */
extern struct wif *wi_open(char *iface);
extern int wi_read(struct wif *wi, unsigned char *h80211, int len,
		   struct rx_info *ri);
extern int wi_write(struct wif *wi, unsigned char *h80211, int len,
		    struct tx_info *ti);
extern int wi_set_channel(struct wif *wi, int chan);
extern int wi_get_channel(struct wif *wi);
extern void wi_close(struct wif *wi);
extern char *wi_get_ifname(struct wif *wi);
extern unsigned char *wi_get_mac(struct wif *wi);

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
/* XXX trivial interface for now.  Perhaps in future we can do something like
 * wif so that client code can change MAC addr of tap, IP addr, and so on.
 */
extern int create_tap(void);

#endif /* __AIRCRACK_NG_OSEDEP_H__ */
