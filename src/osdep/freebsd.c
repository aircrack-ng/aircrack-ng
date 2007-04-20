/*-
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * OS dependent API for FreeBSD.
 *
 */

#include <sys/endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_freebsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <assert.h>
#include <ifaddrs.h>

#include "osdep.h"
#include "network.h"

struct priv_fbsd {
	/* iface */
	int				pf_fd;

	/* rx */
	int				pf_nocrc;

	/* tx */
	unsigned char			pf_buf[4096];
	unsigned char			*pf_next;
	int				pf_totlen;
        struct ieee80211_bpf_params	pf_txparams;

	/* setchan */
	int				pf_s;
	struct ieee80211req		pf_ireq;
        int                             pf_chan;
};

static unsigned char *get_80211(struct priv_fbsd *pf, int *plen,
				struct rx_info *ri)
{
#define BIT(n)  (1<<(n))
        struct bpf_hdr *bpfh;
        struct ieee80211_radiotap_header *rth;
        uint32_t present;
        uint8_t rflags;
        void *ptr;
        unsigned char **data;
	int *totlen;

	data = &pf->pf_next;
	totlen = &pf->pf_totlen;
	assert(*totlen);

        /* bpf hdr */
        bpfh = (struct bpf_hdr*) (*data);
        assert(bpfh->bh_caplen == bpfh->bh_datalen); /* XXX */
        *totlen -= bpfh->bh_hdrlen;

        /* check if more packets */
        if ((int)bpfh->bh_caplen < *totlen) {
		int tot = bpfh->bh_hdrlen + bpfh->bh_caplen;
		int offset = BPF_WORDALIGN(tot);

                *data = (char*)bpfh + offset;
		*totlen -= offset - tot; /* take into account align bytes */
	} else if ((int)bpfh->bh_caplen > *totlen)
		abort();

        *plen = bpfh->bh_caplen;
	*totlen -= bpfh->bh_caplen;
	assert(*totlen >= 0);

        /* radiotap */
        rth = (struct ieee80211_radiotap_header*)
              ((char*)bpfh + bpfh->bh_hdrlen);
        /* XXX cache; drivers won't change this per-packet */
        /* check if FCS/CRC is included in packet */
        present = le32toh(rth->it_present);
        if (present & BIT(IEEE80211_RADIOTAP_FLAGS)) {
                if (present & BIT(IEEE80211_RADIOTAP_TSFT))
                        rflags = ((const uint8_t *)rth)[8];
                else
                        rflags = ((const uint8_t *)rth)[0];
        } else
                rflags = 0;
        *plen -= rth->it_len;
	assert(*plen > 0);

        /* 802.11 CRC */
        if (pf->pf_nocrc || (rflags & IEEE80211_RADIOTAP_F_FCS)) {
                *plen -= IEEE80211_CRC_LEN;
                pf->pf_nocrc = 1;
        }

        ptr = (char*)rth + rth->it_len;

	/* write control info */
	if (ri) {
		memset(ri, 0, sizeof(*ri));
		/* XXX get channel from radiotap */
	}

        return ptr;
#undef BIT
}

static int fbsd_get_channel(struct wif *wi)
{
	struct priv_fbsd *pf = wi_priv(wi);

	if( ioctl(pf->pf_s, SIOCG80211, &pf->pf_ireq) != 0 ) return -1;

	return pf->pf_ireq.i_val;
}

static int fbsd_read(struct wif *wi, unsigned char *h80211, int len,
		     struct rx_info *ri)
{
	struct priv_fbsd *pf = wi_priv(wi);
	unsigned char *wh;
	int plen;

	assert(len > 0);

	/* need to read more */
	if (pf->pf_totlen == 0) {
		pf->pf_totlen = read(pf->pf_fd, pf->pf_buf, sizeof(pf->pf_buf));
		if (pf->pf_totlen == -1) {
			pf->pf_totlen = 0;
			return -1;
		}
		pf->pf_next = pf->pf_buf;
	}

	/* read 802.11 packet */
	wh = get_80211(pf, &plen, ri);
	if (plen > len)
		plen = len;
	assert(plen > 0);
	memcpy(h80211, wh, plen);

        if(!ri->ri_channel)
            ri->ri_channel = wi_get_channel(wi);

	return plen;
}

static int fbsd_write(struct wif *wi, unsigned char *h80211, int len,
		      struct tx_info *ti)
{
        struct iovec iov[2];
	struct priv_fbsd *pf = wi_priv(wi);

	/* XXX make use of ti */
	if (ti) {}

	iov[0].iov_base = &pf->pf_txparams;
	iov[0].iov_len = pf->pf_txparams.ibp_len;

        iov[1].iov_base = h80211;
        iov[1].iov_len = len;

	return writev(pf->pf_fd, iov, 2);
}

static int fbsd_set_channel(struct wif *wi, int chan)
{
	struct priv_fbsd *pf = wi_priv(wi);

	pf->pf_ireq.i_val = chan;
	if( ioctl(pf->pf_s, SIOCS80211, &pf->pf_ireq) != 0 )
            return -1;

	pf->pf_chan = chan;
	return 0;
}

static void do_free(struct wif *wi)
{
	assert(wi->wi_priv);
	free(wi->wi_priv);
	wi->wi_priv = 0;
	free(wi);
}

static void fbsd_close(struct wif *wi)
{
	struct priv_fbsd *pf = wi_priv(wi);

	close(pf->pf_fd);
	close(pf->pf_s);
	do_free(wi);
}

static int do_fbsd_open(struct wif *wi, char *iface)
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
	struct priv_fbsd *pf = wi_priv(wi);

	/* basic sanity check */
	if (strlen(iface) >= sizeof(ifr.ifr_name))
		return -1;

        /* open wifi */
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if (s == -1)
		return -1;
	pf->pf_s = s;

        /* set iface up and promisc */
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
		goto close_sock;

        flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
        flags |= IFF_UP | IFF_PPROMISC;
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface);
        ifr.ifr_flags = flags & 0xffff;
        ifr.ifr_flagshigh = flags >> 16;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1)
		goto close_sock;

	/* monitor mode */
        memset(&ifmr, 0, sizeof(ifmr));
        strcpy(ifmr.ifm_name, iface);
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
        strcpy(ifr.ifr_name, iface);
        ifr.ifr_media = ifmr.ifm_current | IFM_IEEE80211_MONITOR;
        if (ioctl(s, SIOCSIFMEDIA, &ifr) == -1)
		goto close_sock;

	/* setup ifreq for chan that may be used in future */
	strcpy(pf->pf_ireq.i_name, iface);
	pf->pf_ireq.i_type = IEEE80211_IOC_CHANNEL;

        /* open bpf */
        for(i = 0; i < 256; i++) {
                sprintf(buf, "/dev/bpf%d", i);

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

	strcpy(ifr.ifr_name, iface);

        if(ioctl(fd, BIOCSETIF, &ifr) < 0)
		goto close_bpf;

        if (ioctl(fd, BIOCSDLT, &dlt) < 0)
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

static int fbsd_fd(struct wif *wi)
{
	struct priv_fbsd *pf = wi_priv(wi);

	return pf->pf_fd;
}

static int fbsd_get_mac(struct wif *wi, unsigned char *mac)
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

static struct wif *fbsd_open(char *iface)
{
	struct wif *wi;
	struct priv_fbsd *pf;
	int fd;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*pf));
	if (!wi)
		return NULL;
	wi->wi_read		= fbsd_read;
	wi->wi_write		= fbsd_write;
	wi->wi_set_channel	= fbsd_set_channel;
	wi->wi_get_channel	= fbsd_get_channel;
	wi->wi_close		= fbsd_close;
	wi->wi_fd		= fbsd_fd;
	wi->wi_get_mac		= fbsd_get_mac;

	/* setup iface */
	fd = do_fbsd_open(wi, iface);
	if (fd == -1) {
		do_free(wi);
		return NULL;
	}

	/* setup private state */
	pf = wi_priv(wi);
	pf->pf_fd = fd;
        pf->pf_txparams.ibp_vers = IEEE80211_BPF_VERSION;
	pf->pf_txparams.ibp_len = sizeof(struct ieee80211_bpf_params) - 6;
	pf->pf_txparams.ibp_rate1 = 2;         /* 1 MB/s XXX */
	pf->pf_txparams.ibp_try1 = 1;          /* no retransmits */
	pf->pf_txparams.ibp_flags = IEEE80211_BPF_NOACK;
	pf->pf_txparams.ibp_power = 100;       /* nominal max */
	pf->pf_txparams.ibp_pri = WME_AC_VO;   /* high priority */

	return wi;
}

struct wif *wi_open_osdep(char *iface)
{
	struct wif *wi;

	/* XXX move this to wi_open */
	if ((wi = net_open(iface)))
		return wi;
	
	return fbsd_open(iface);
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

int create_tap(void)
{
	int fd;
	struct ifreq if_request;

	fd = open( "/dev/tap", O_RDWR);
	if (fd == -1)
		return -1;

	memset(&if_request, 0, sizeof(if_request));
	strncpy(if_request.ifr_name, "at%d", IFNAMSIZ);
	if_request.ifr_name[IFNAMSIZ-1] = 0;
	if(ioctl(fd, SIOCGIFFLAGS, &if_request ) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}
