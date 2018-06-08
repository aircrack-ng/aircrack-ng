 /*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for OpenBSD.
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
#include <sys/types.h>
#include <sys/endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <sys/queue.h>
#include <net/if_var.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_crypto.h>
#include <frame.h>
#include <sys/timeout.h>
#define _KERNEL
#include <machine/intr.h>
#undef _KERNEL
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_proto.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <assert.h>
#include <ifaddrs.h>

#include "osdep.h"

#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS	0x10	/* Frame includes FCS */
#endif

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL	0
#endif

#ifndef le32toh
#define le32toh(x)	htole32(x)
#endif

struct priv_obsd {
	/* iface */
	int				po_fd;

	/* rx */
	int				po_nocrc;

	/* tx */
	unsigned char			po_buf[4096];
	unsigned char			*po_next;
	int				po_totlen;

	/* setchan */
	int				po_s;
	struct ifreq			po_ifr;
	struct ieee80211chanreq		po_ireq;
        int                             po_chan;
};

static void get_radiotap_info(struct priv_obsd *po,
			      struct ieee80211_radiotap_header *rth, int *plen,
			      struct rx_info *ri)
{
        uint32_t present;
	uint8_t rflags = 0;
	int i;
	unsigned char *body = (unsigned char*) (rth+1);
	int dbm_power = 0, db_power = 0;

	/* reset control info */
	if (ri)
		memset(ri, 0, sizeof(*ri));

       	/* get info */
	present = le32toh(rth->it_present);
	for (i = IEEE80211_RADIOTAP_TSFT; i <= IEEE80211_RADIOTAP_EXT; i++) {
		if (!(present & (1 << i)))
			continue;

		switch (i) {
		case IEEE80211_RADIOTAP_TSFT:
			body += sizeof(uint64_t);
			break;

		case IEEE80211_RADIOTAP_FLAGS:
			rflags = *((uint8_t*)body);
			/* fall through */
		case IEEE80211_RADIOTAP_RATE:
			body += sizeof(uint8_t);
			break;

		case IEEE80211_RADIOTAP_CHANNEL:
			if (ri) {
				ri->ri_channel = 1;
			}
			body += sizeof(uint16_t)*2;
			break;

		case IEEE80211_RADIOTAP_FHSS:
			body += sizeof(uint16_t);
			break;

		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			dbm_power = *body++;
			break;

		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			dbm_power -= *body++;
			break;

		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			db_power = *body++;
			break;

		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			db_power -= *body++;
			break;

		default:
			i = IEEE80211_RADIOTAP_EXT+1;
			break;
		}
	}

	/* set power */
	if (ri) {
		if (dbm_power)
			ri->ri_power = dbm_power;
		else
			ri->ri_power = db_power;
	}

        /* XXX cache; drivers won't change this per-packet */
        /* check if FCS/CRC is included in packet */
        if (po->po_nocrc || (rflags & IEEE80211_RADIOTAP_F_FCS)) {
                *plen -= IEEE80211_CRC_LEN;
                po->po_nocrc = 1;
        }
}

static unsigned char *get_80211(struct priv_obsd *po, int *plen,
				struct rx_info *ri)
{
        struct bpf_hdr *bpfh;
        struct ieee80211_radiotap_header *rth;
        void *ptr;
        unsigned char **data;
	int *totlen;

	data = &po->po_next;
	totlen = &po->po_totlen;
	assert(*totlen);

        /* bpf hdr */
        bpfh = (struct bpf_hdr*) (*data);
        assert(bpfh->bh_caplen == bpfh->bh_datalen); /* XXX */
        *totlen -= bpfh->bh_hdrlen;

        /* check if more packets */
        if ((int)bpfh->bh_caplen < *totlen) {
		int tot = bpfh->bh_hdrlen + bpfh->bh_caplen;
		int offset = BPF_WORDALIGN(tot);

                *data = (unsigned char*)bpfh + offset;
		*totlen -= offset - tot; /* take into account align bytes */
	} else if ((int)bpfh->bh_caplen > *totlen)
		abort();

        *plen = bpfh->bh_caplen;
	*totlen -= bpfh->bh_caplen;
	assert(*totlen >= 0);

        /* radiotap */
        rth = (struct ieee80211_radiotap_header*)
              ((char*)bpfh + bpfh->bh_hdrlen);
	get_radiotap_info(po, rth, plen, ri);
        *plen -= rth->it_len;
	assert(*plen > 0);

       	/* data */
	ptr = (char*)rth + rth->it_len;

        return ptr;
}

static int obsd_get_channel(struct wif *wi)
{
	struct priv_obsd *po = wi_priv(wi);
	struct ieee80211chanreq channel;

	memset(&channel, 0, sizeof(channel));
	strlcpy(channel.i_name, wi_get_ifname(wi), sizeof(channel.i_name));

	if(ioctl(po->po_s, SIOCG80211CHANNEL, (caddr_t)&channel) < 0) return -1;

	return channel.i_channel;
}

static int obsd_set_channel(struct wif *wi, int chan)
{
	struct priv_obsd *po = wi_priv(wi);
	struct ieee80211chanreq channel;

	memset(&channel, 0, sizeof(channel));
	strlcpy(channel.i_name, wi_get_ifname(wi), sizeof(channel.i_name));
	channel.i_channel = chan;
	if(ioctl(po->po_s, SIOCS80211CHANNEL, (caddr_t)&channel) < 0) return -1;
	po->po_chan = chan;

	return 0;
}

static int obsd_read(struct wif *wi, unsigned char *h80211, int len,
		     struct rx_info *ri)
{
	struct priv_obsd *po = wi_priv(wi);
	unsigned char *wh;
	int plen;

	assert(len > 0);

	/* need to read more */
	while (po->po_totlen == 0) {
		po->po_totlen = read(po->po_fd, po->po_buf, sizeof(po->po_buf));
		if (po->po_totlen == -1) {
			po->po_totlen = 0;
			return -1;
		}
		po->po_next = po->po_buf;
	}

	/* read 802.11 packet */
	wh = get_80211(po, &plen, ri);
	if (plen > len)
		plen = len;
	assert(plen > 0);
	memcpy(h80211, wh, plen);

        if(ri && !ri->ri_channel)
            ri->ri_channel = wi_get_channel(wi);

	return plen;
}

static int obsd_write(struct wif *wi, unsigned char *h80211, int len,
		      struct tx_info *ti)
{
	struct priv_obsd *po = wi_priv(wi);
	int rc;

	/* XXX make use of ti */
	if (ti) {}

	rc = write(po->po_fd, h80211, len);
	if (rc == -1)
		return rc;

	return 0;
}

static void do_free(struct wif *wi)
{
	assert(wi->wi_priv);
	free(wi->wi_priv);
	wi->wi_priv = 0;
	free(wi);
}

static void obsd_close(struct wif *wi)
{
	struct priv_obsd *po = wi_priv(wi);

	close(po->po_fd);
	close(po->po_s);
	do_free(wi);
}

static int do_obsd_open(struct wif *wi, char *iface)
{
        int i;
        char buf[64];
        int fd = -1;
        struct ifreq ifr;
        unsigned int dlt = DLT_IEEE802_11_RADIO;
        int s;
        unsigned int flags;
        struct ifmediareq ifmr;
        int *mwords;
	struct priv_obsd *po = wi_priv(wi);
	unsigned int size=sizeof(po->po_buf);

	/* basic sanity check */
	if (strlen(iface) >= sizeof(ifr.ifr_name))
		return -1;

        /* open wifi */
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if (s == -1)
		return -1;
	po->po_s = s;

        /* set iface up and promisc */
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
		goto close_sock;

        flags = ifr.ifr_flags;
        flags |= IFF_UP | IFF_PROMISC;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ);
        ifr.ifr_flags = flags & 0xffff;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1)
		goto close_sock;

	/* monitor mode */
        memset(&ifmr, 0, sizeof(ifmr));
        strncpy(ifmr.ifm_name, iface, IFNAMSIZ);
        if (ioctl(s, SIOCGIFMEDIA, &ifmr) == -1)
		goto close_sock;

        assert(ifmr.ifm_count != 0);

        mwords = (int *)malloc(ifmr.ifm_count * sizeof(int));
        if (!mwords)
		goto close_sock;
        ifmr.ifm_ulist = mwords;
        if (ioctl(s, SIOCGIFMEDIA, &ifmr) == -1) {
		free(mwords);
		goto close_sock;
	}
        free(mwords);

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ);
        ifr.ifr_media = ifmr.ifm_current | IFM_IEEE80211_MONITOR;
        if (ioctl(s, SIOCSIFMEDIA, &ifr) == -1)
		goto close_sock;

	/* setup ifreq for chan that may be used in future */
	strncpy(po->po_ireq.i_name, iface, IFNAMSIZ);

	/* same for ifreq [mac addr] */
	strncpy(po->po_ifr.ifr_name, iface, IFNAMSIZ);

        /* open bpf */
        for(i = 0; i < 256; i++) {
                snprintf(buf, sizeof(buf), "/dev/bpf%d", i);

                fd = open(buf, O_RDWR);
                if(fd < 0) {
                        if(errno != EBUSY)
				return -1;
                        continue;
                }
                else
                        break;
        }

        if(fd < 0)
		goto close_sock;

	if (ioctl(fd, BIOCSBLEN, &size) < 0)
		goto close_bpf;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);

        if (ioctl(fd, BIOCSETIF, &ifr) < 0)
		goto close_bpf;

        if (ioctl(fd, BIOCSDLT, &dlt) < 0)
		goto close_bpf;

	if(ioctl(fd, BIOCPROMISC, NULL) < 0)
		goto close_bpf;

        dlt = 1;
        if (ioctl(fd, BIOCIMMEDIATE, &dlt) == -1)
		goto close_bpf;

	return fd;

close_sock:
	close(s);
	return -1;
close_bpf:
	close(fd);
	goto close_sock;
}

static int obsd_fd(struct wif *wi)
{
	struct priv_obsd *po = wi_priv(wi);

	return po->po_fd;
}

static int obsd_get_mac(struct wif *wi, unsigned char *mac)
{
	struct ifaddrs *ifa, *p;
	char *name = wi_get_ifname(wi);
	int rc = -1;
	struct sockaddr_dl* sdp;

	if (getifaddrs(&ifa) == -1)
		return -1;

	p = ifa;
	while (p) {
		if (p->ifa_addr->sa_family == AF_LINK &&
		    strcmp(name, p->ifa_name) == 0) {

		    	sdp = (struct sockaddr_dl*) p->ifa_addr;
			memcpy(mac, sdp->sdl_data + sdp->sdl_nlen, 6);
			rc = 0;
			break;
		}

		p = p->ifa_next;
	}
	freeifaddrs(ifa);

	return rc;
}

static int obsd_get_monitor(struct wif *wi)
{
	if (wi) {} /* XXX unused */

	/* XXX */
	return 0;
}

static int obsd_get_rate(struct wif *wi)
{
	if (wi) {} /* XXX unused */

	/* XXX */
	return 1000000;
}

static int obsd_set_rate(struct wif *wi, int rate)
{
	if (wi || rate) {} /* XXX unused */

	/* XXX */
	return 0;
}

static int obsd_set_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_obsd *po = wi_priv(wi);
	struct ifreq *ifr = &po->po_ifr;

	ifr->ifr_addr.sa_family = AF_LINK;
	ifr->ifr_addr.sa_len = 6;
	memcpy(ifr->ifr_addr.sa_data, mac, 6);

	return ioctl(po->po_s, SIOCSIFLLADDR, ifr);
}

static struct wif *obsd_open(char *iface)
{
	struct wif *wi;
	struct priv_obsd *po;
	int fd;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*po));
	if (!wi)
		return NULL;
	wi->wi_read		= obsd_read;
	wi->wi_write		= obsd_write;
	wi->wi_set_channel	= obsd_set_channel;
	wi->wi_get_channel	= obsd_get_channel;
	wi->wi_close		= obsd_close;
	wi->wi_fd		= obsd_fd;
	wi->wi_get_mac		= obsd_get_mac;
	wi->wi_set_mac		= obsd_set_mac;
	wi->wi_get_rate		= obsd_get_rate;
	wi->wi_set_rate		= obsd_set_rate;
        wi->wi_get_monitor      = obsd_get_monitor;

	/* setup iface */
	fd = do_obsd_open(wi, iface);
	if (fd == -1) {
		do_free(wi);
		return NULL;
	}

	/* setup private state */
	po = wi_priv(wi);
	po->po_fd = fd;

	return wi;
}

struct wif *wi_open_osdep(char *iface)
{
	return obsd_open(iface);
}

int get_battery_state(void)
{
#if defined(__FreeBSD__)
    int value;
    size_t len;

    len = 1;
    value = 0;
    sysctlbyname("hw.acpi.acline", &value, &len, NULL, 0);
    if (value == 0)
    {
            sysctlbyname("hw.acpi.battery.time", &value, &len, NULL, 0);
            value = value * 60;
    }
    else
    {
            value = 0;
    }

    return( value );
#elif defined(_BSD_SOURCE)
    struct apm_power_info api;
    int apmfd;
    if ((apmfd = open("/dev/apm", O_RDONLY)) < 0)
        return 0;
    if (ioctl(apmfd, APM_IOC_GETPOWER, &api) < 0) {
        close(apmfd);
        return 0;
    }
    close(apmfd);
    if (api.battery_state == APM_BATT_UNKNOWN ||
        api.battery_state == APM_BATTERY_ABSENT ||
        api.battery_state == APM_BATT_CHARGING ||
    api.ac_state == APM_AC_ON) {
        return 0;
    }
    return ((int)(api.minutes_left))*60;
#else
    return 0;
#endif
}
