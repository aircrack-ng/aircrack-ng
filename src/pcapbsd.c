#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#if defined(__NetBSD__)
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/wi_ieee.h>
#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif 
#endif

#if defined(__OpenBSD__)
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>
#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif 
#endif

#ifdef __FreeBSD__
#include <net/if.h>
#include <net/if_media.h> 
#include <dev/ic/if_wi_ieee.h>
#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif
#endif

#ifdef HAVE_RADIOTAP
// Hack around some headers that don't seem to define all of these
#ifndef IEEE80211_CHAN_TURBO
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#endif
#ifndef IEEE80211_CHAN_CCK
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */
#endif
#ifndef IEEE80211_CHAN_OFDM
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#endif
#ifndef IEEE80211_CHAN_2GHZ
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#endif
#ifndef IEEE80211_CHAN_5GHZ
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#endif
#ifndef IEEE80211_CHAN_PASSIVE
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#endif
#ifndef IEEE80211_CHAN_DYN
#define IEEE80211_CHAN_DYN      0x0400  /* Dynamic CCK-OFDM channel */
#endif
#ifndef IEEE80211_CHAN_GFSK
#define IEEE80211_CHAN_GFSK     0x0800  /* GFSK channel (FHSS PHY) */
#endif
#endif

#include "pcapbsd.h"

int ps;
pcap_t *pd;
char *ifname;
int iftype;

// Pcap error buffer
char errstr[PCAP_ERRBUF_SIZE];

// Pcap global callback structs
struct pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];


/*
 * Convert MHz frequency to IEEE channel number.
 */
/*
static u_int ieee80211_mhz2ieee(u_int freq, u_int flags)
{
    if (flags & IEEE80211_CHAN_2GHZ) {		// 2GHz band
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	else
	    return 15 + ((freq - 2512) / 20);
    } else if (flags & IEEE80211_CHAN_5GHZ) {	// 5Ghz band
	return (freq - 5000) / 5;
    } else {					// either, guess
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	if (freq < 5000)
	    return 15 + ((freq - 2512) / 20);
	return (freq - 5000) / 5;
    }
}
*/

#if (defined(HAVE_RADIOTAP) && (defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)))
bool pcap_open_source()
{
    pd = pcap_open_live(ifname, MAX_PACKET_LEN, 1, 1000, errstr);
    pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	// Hack to re-enable promisc mode since changing the DLT seems to make i
	// drop it on some bsd pcap implementations
    ioctl(pcap_get_selectable_fd(pd), BIOCPROMISC, NULL);
	// Hack to set the fd to IOIMMEDIATE, to solve problems with select() on
	// devices on BSD
    int v = 1;
    ioctl(pcap_get_selectable_fd(pd), BIOCIMMEDIATE, &v);

#ifdef HAVE_PCAP_NONBLOCK
    pcap_setnonblock(pd, 1, errstr);
#endif
    return true;
}

bool pcap_datalink_type()
{
    iftype = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(__FreeBSD__) || defined(__OpenBSD__)) || defined(__NetBSD__)
    if (iftype == DLT_EN10MB) {
        fprintf(stderr, "WARNING:  pcap reports link type of EN10MB but we'll fake "
                "it on BSD.\n"
                "This may not work the way we want it to.\n");
#if (defined(__FreeBSD__) || defined(__NetBSD__) && !defined(HAVE_RADIOTAP))
        fprintf(stderr, "WARNING:  Some Free- and Net- BSD drivers do not report "
                "rfmon packets\n"
                "correctly.  Aircrack-ng suite will probably not run correctly.  For better\n"
                "support, you should upgrade to a version of *BSD with Radiotap.\n");
#endif
        iftype = KDLT_BSD802_11;
    }
#else
    if (iftype == DLT_EN10MB) {
        fprintf(errstr, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", ifname);
        return false;
    }
#endif

    // Little hack to give an intelligent error report for radiotap
#ifndef HAVE_RADIOTAP
    if (iftype == DLT_IEEE802_11_RADIO) {
        fprintf(errstr, "FATAL: Radiotap link type reported but radiotap "
                 "support was not compiled into Aircrack-ng.");
        return false;
    }
#endif
    
    if (iftype != KDLT_BSD802_11 && iftype != DLT_IEEE802_11 &&
        iftype != DLT_PRISM_HEADER &&
        iftype != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "WARNING:  Unknown link type %d reported. Continuing on...", iftype);
    }
    return true;
}

void pcap_callback(u_char *bp, const struct pcap_pkthdr *header, const u_char *in_data)
{
    memcpy(&callback_header, header, sizeof(callback_header));
    memcpy(callback_data, in_data, MAX_PACKET_LEN);
}

int pcap_read_packet(int count)
{
    int ret;
    if ((ret = pcap_dispatch(pd, count, pcap_callback, NULL)) < 0) {
        fprintf(stderr, "Failed to read packet");
	return false;
    }
    return ret;
}

//bool pcap_close_source()
//{
//    pcap_close(pd);
//        return true;
//}
												    
bool open_source(char *if_name)
{
    ifname = strdup(if_name);
    pcap_open_source();

    ps = socket(AF_INET, SOCK_DGRAM, 0);
    if (ps < 0) {
        fprintf(stderr, "Failed to create AF_INET socket");
	return false;
    }
    if (!check_datalink(DLT_IEEE802_11_RADIO)) {
	fprintf(stderr, "No support for radiotap data link");
	return false;
    } else {
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	iftype = DLT_IEEE802_11_RADIO;
	return true;
    }
}

// Check for data link type support
bool check_datalink(int dlt)
{
    bool found = false;
    int i, n, *dl;
    dl = malloc(32);
    n = pcap_list_datalinks(pd, &dl);
    for (i = 0; i < n; i++)
	if (dl[i] == dlt) {
	    found = true;
	    break;
	}
    free(dl);
    return found;
}

int get_channel()
{
    int in_ch=-1;
    if (!get80211(IEEE80211_IOC_CHANNEL, in_ch, 0, NULL)) {
	fprintf(stderr, "failed to get channel");
        return false;
    }
    return in_ch;
}

bool set_channel(int in_ch)
{
    if (!set80211(IEEE80211_IOC_CHANNEL, in_ch, 0, NULL)) {
	fprintf(stderr, "failed to set channel %u", in_ch);
	return false;
    } else
	return true;
}

#endif

bool getmediaopt(int options, int mode)
{
    struct ifmediareq ifmr;

    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

    /*
     * We must go through the motions of reading all
     * supported media because we need to know both
     * the current media type and the top-level type.
     */
    if (ioctl(ps, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
        fprintf(stderr, "cannot get ifmedia");
        return false;
    }
    options = IFM_OPTIONS(ifmr.ifm_current);
    mode = IFM_MODE(ifmr.ifm_current);
    return true;
}

bool setmediaopt(int options, int mode)
{
    struct ifmediareq ifmr;
    struct ifreq ifr;

    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

    /*
     * We must go through the motions of reading all
     * supported media because we need to know both
     * the current media type and the top-level type.
     */
    if (ioctl(ps, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
        fprintf(stderr, "cannot get ifmedia");
        return false;
    }
    if (ifmr.ifm_count == 0) {
        fprintf(stderr, "%s: no media types?", ifname);
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_media = (ifmr.ifm_current &~ IFM_OMASK) | options;
    ifr.ifr_media = (ifr.ifr_media &~ IFM_MMASK) | IFM_MAKEMODE(mode);

    if (ioctl(ps, SIOCSIFMEDIA, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "cannot set ifmedia");
        return false;
    }
    return true;
}

#if defined(__OpenBSD__) || defined(__NetBSD__)

     /* A simple 802.11 ioctl replacement for OpenBSD/NetBSD
        Only used for channel set/get.
        This should be re-written to be *BSD agnostic.  */

int get80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211chanreq channel;

    memset(&channel, 0, sizeof(channel));
    strlcpy(channel.i_name, ifname, sizeof(channel.i_name));
    if (ioctl(ps, SIOCG80211CHANNEL, (caddr_t)&channel) < 0) {
        fprintf(stderr, "SIOCG80211CHANNEL ioctl failed");
        return false;
    }
    return channel.i_channel;
}

bool set80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211chanreq channel;

    strlcpy(channel.i_name, ifname, sizeof(channel.i_name));
    channel.i_channel = (u_int16_t)val;
    if (ioctl(ps, SIOCS80211CHANNEL, (caddr_t)&channel) == -1) {
        fprintf(stderr, "SIOCS80211CHANNEL ioctl failed");
        return false;
    }
    return true;
}

#elif defined(__FreeBSD__) /* FreeBSD has a generic 802.11 ioctl */

int get80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211req ireq;

    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname, sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_len = len;
    ireq.i_data = data;
    if (ioctl(ps, SIOCG80211, &ireq) < 0) {
        fprintf(stderr, "SIOCG80211 ioctl failed");
        return false;
    }
    return ireq.i_val;
}

bool set80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211req ireq;

    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname, sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_val = val;
    ireq.i_len = len;
    ireq.i_data = data;
    return (ioctl(ps, SIOCS80211, &ireq) >= 0);
}

#endif

bool getifflags(int flags)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    ifr.ifr_name[sizeof (ifr.ifr_name)-1] = '\0';
    if (ioctl(ps, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "SIOCGIFFLAGS ioctl failed");
        return false;
    }
#if defined(__FreeBSD__)
    flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    flags = ifr.ifr_flags;
#endif
    return true;
}

bool setifflags(int flags)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
#if defined(__FreeBSD__)
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;
#elif defined(__OpenBSD__) || (__NetBSD__)
    ifr.ifr_flags = flags;
#endif
    if (ioctl(ps, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "SIOCSIFFLAGS ioctl failed");
        return false;
    }
    return true;
}

bool monitor_enable()
{
    int prev_flags = 0;
    int prev_options = 0;
    int prev_mode = 0;
    int prev_chan = 0;

    /*
     * Collect current state.
     */
    getmediaopt(prev_options, prev_mode);
    prev_chan = get80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
    getifflags(prev_flags);
    
    /*
     * Enter monitor mode, set the specified channel,
     * enable promiscuous reception, and force the
     * interface up since otherwise bpf won't work.
     */
    if (!setmediaopt(IFM_IEEE80211_MONITOR, IFM_AUTO)) {
        return false;
    }
#if defined(__FreeBSD__)
    if (!setifflags(prev_flags | IFF_PPROMISC | IFF_UP)) {
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    if (!setifflags(prev_flags | IFF_PROMISC | IFF_UP)) {
#endif
	set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
	setmediaopt(prev_options, prev_mode);
        return false;
    }
    return true;
}

int monitor_bsd()
{
    if(!monitor_enable()) {
	fprintf(stderr, "%s", errstr);
	return false;
    } else {
	return true;
    }
}
