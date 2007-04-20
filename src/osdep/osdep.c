/*-
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * All OS dependent crap should go here.
 *
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "osdep.h"

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
        wi->wi_update_channel(wi);
        return wi->channel;
}

char *wi_get_ifname(struct wif *wi)
{
        return wi->interface;
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

unsigned char *wi_get_mac(struct wif *wi)
{
        return wi->mac;
}
