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

#include <curses.h>

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
//#include <sys/socket.h>
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

#ifdef SYS_FREEBSD
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h> 
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

int s;
int prev_flags;
int prev_options;
int prev_mode;
int prev_chan;
char errstr[256];
char *ifname;

pcap_t *pd;
int datalink_type;

int chan;

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

#if (defined(HAVE_RADIOTAP) && (defined(SYS_NETBSD) || defined(SYS_OPENBSD) || defined(SYS_FREEBSD)))
bool PcapOpenSource()
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
}

bool PcapDatalinkType()
{
    datalink_type = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD)) || defined(SYS_NETBSD)
    if (datalink_type == DLT_EN10MB) {
        fprintf(stderr, "WARNING:  pcap reports link type of EN10MB but we'll fake "
                "it on BSD.\n"
                "This may not work the way we want it to.\n");
#if (defined(SYS_FREEBSD) || defined(SYS_NETBSD) && !defined(HAVE_RADIOTAP))
        fprintf(stderr, "WARNING:  Some Free- and Net- BSD drivers do not report "
                "rfmon packets\n"
                "correctly.  Aircrack-ng suite will probably not run correctly.  For better\n"
                "support, you should upgrade to a version of *BSD with Radiotap.\n");
#endif
        datalink_type = KDLT_BSD802_11;
    }
#else
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, 256, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", ifname);
        return false;
    }
#endif

    // Little hack to give an intelligent error report for radiotap
#ifndef HAVE_RADIOTAP
    if (datalink_type == DLT_IEEE802_11_RADIO) {
        snprintf(errstr, 256, "FATAL: Radiotap link type reported but radiotap "
                 "support was not compiled into Aircrack-ng.");
        return false;
    }
#endif
    
    if (datalink_type != KDLT_BSD802_11 && datalink_type != DLT_IEEE802_11 &&
        datalink_type != DLT_PRISM_HEADER &&
        datalink_type != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "WARNING:  Unknown link type %d reported.  Continuing on "
                "blindly...\n", datalink_type);
    }
    return true;
}

void PcapCallback(u_char *bp, const struct pcap_pkthdr *header, const u_char *in_data)
{
    memcpy(&callback_header, header, sizeof(callback_header));
    memcpy(callback_data, in_data, MAX_PACKET_LEN);
}

int PcapFetchPacket()
{
    int ret;

    if ((ret = pcap_dispatch(pd, 1, PcapCallback, NULL)) < 0) {
	// Is the interface still here and just not running?  Lets give a more i
	// error if that looks to be the case.
	//ret = 0;
    }
    return ret;
}

bool PcapCloseSource()
{
    pcap_close(pd);
        return 1;
}
												    
bool OpenSource(char *if_name)
{
    ifname = strdup(if_name);
    PcapOpenSource();

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "Failed to create AF_INET socket");
	return false;
    }
    if (!CheckDatalink(DLT_IEEE802_11_RADIO)) {
	fprintf(stderr, "No support for radiotap data link");
	return false;
    } else {
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	datalink_type = DLT_IEEE802_11_RADIO;
	return true;
    }
}

// Check for data link type support
bool CheckDatalink(int dlt)
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
    int chan;
    if (!get80211(IEEE80211_IOC_CHANNEL, chan, 0, NULL)) {
	fprintf(stderr, "failed to get channel");
        return false;
    }
    return chan;
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
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
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
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
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

    if (ioctl(s, SIOCSIFMEDIA, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "cannot set ifmedia");
        return false;
    }
    return true;
}

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)

     /* A simple 802.11 ioctl replacement for OpenBSD/NetBSD
        Only used for channel set/get.
        This should be re-written to be *BSD agnostic.  */

bool get80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211chanreq channel;

    memset(&channel, 0, sizeof(channel));
    strlcpy(channel.i_name, ifname, sizeof(channel.i_name));
    if (ioctl(s, SIOCG80211CHANNEL, (caddr_t)&channel) < 0) {
        fprintf(stderr, "SIOCG80211CHANNEL ioctl failed");
        return false;
    }
    chan = channel.i_channel;
    return true;
}

bool set80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211chanreq channel;

    strlcpy(channel.i_name, ifname, sizeof(channel.i_name));
    channel.i_channel = (u_int16_t)val;
    if (ioctl(s, SIOCS80211CHANNEL, (caddr_t)&channel) == -1) {
        fprintf(stderr, "SIOCS80211CHANNEL ioctl failed");
        return false;
    }
    return true;
}

#elif defined(SYS_FREEBSD) /* FreeBSD has a generic 802.11 ioctl */

bool get80211(int type, int val, int len, u_int8_t *data)
{
    struct ieee80211req ireq;

    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname, sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_len = len;
    ireq.i_data = data;
    if (ioctl(s, SIOCG80211, &ireq) < 0) {
        fprintf(stderr, "SIOCG80211 ioctl failed");
        return false;
    }
    val = ireq.i_val;
    return true;
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
    return (ioctl(s, SIOCS80211, &ireq) >= 0);
}

#endif

bool getifflags(int flags)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
    ifr.ifr_name[sizeof (ifr.ifr_name)-1] = '\0';
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "SIOCGIFFLAGS ioctl failed");
        return false;
    }
#if defined(SYS_FREEBSD)
    flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
    flags = ifr.ifr_flags;
#endif
    return true;
}

bool setifflags(int flags)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
#if defined(SYS_FREEBSD)
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;
#elif defined(SYS_OPENBSD) || (SYS_NETBSD)
    ifr.ifr_flags = flags;
#endif
    if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        fprintf(stderr, "SIOCSIFFLAGS ioctl failed");
        return false;
    }
    return true;
}

bool monitor_enable(int initch)
{
    /*
     * Collect current state.
     */
    getmediaopt(prev_options, prev_mode);
    get80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
    getifflags(prev_flags);
    prev_chan = chan;
    /*
     * Enter monitor mode, set the specified channel,
     * enable promiscuous reception, and force the
     * interface up since otherwise bpf won't work.
     */
    if (!setmediaopt(IFM_IEEE80211_MONITOR, IFM_AUTO))
        return false;
    if (!set80211(IEEE80211_IOC_CHANNEL, initch, 0, NULL)) {
	fprintf(stderr, "failed to set channel");
	setmediaopt(prev_options, prev_mode);
        return false;
    }
#if defined(SYS_FREEBSD)
    if (!setifflags(prev_flags | IFF_PPROMISC | IFF_UP)) {
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
    if (!setifflags(prev_flags | IFF_PROMISC | IFF_UP)) {
#endif
	set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
	setmediaopt(prev_options, prev_mode);
        return false;
    }
    return true;
}

bool monitor_reset()
{
    setifflags(prev_flags);
    /* NB: reset the current channel before switching modes */
    set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
    setmediaopt(prev_options, prev_mode);
    return true;
}

int monitor_bsd(int in_ch)
{
    if (!monitor_enable(in_ch)) {
	fprintf(stderr, "%s", errstr);
	return false;
    } else {
#ifdef SYS_OPENBSD
    // Temporary hack around OpenBSD drivers not standardising on whether FCS
    // bytes are appended, nor having any method to indicate their presence. 
	if (strncmp(in_dev, "ath", 3) == 0 || strncmp(in_dev, "ural", 4) == 0) {
	    PcapSource *psrc = (PcapSource *) in_ext;
	    psrc->fcsbytes = 4;
	}
#endif
	    return true;
	}
}

int unmonitor_bsd(int in_ch)
{
    if (!monitor_reset(in_ch)) {
	fprintf(stderr, "%s", errstr);
        return false;
    } else {
        return true;
    }
}
