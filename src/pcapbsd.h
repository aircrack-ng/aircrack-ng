#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <pcap.h>
#include <net/bpf.h>
#endif
#if defined(__FreeBSD__)
#include <pcap/pcap.h>
#include <pcap/net/bpf.h>
#endif

// The BSD datalink that doesn't report a sane value
#define KDLT_BSD802_11 -100

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER        119 /* prism header, not defined on some platforms */
#endif

#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	/* 802.11 plus WLAN header */
#endif

// Extension to radiotap header not yet included in all BSD's
#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL 0
#endif

#define MAX_PACKET_LEN 4096	// 10240

#ifndef bool
#define bool char
#endif
#ifndef false
#define false -1
#endif
#ifndef true
#define true 1
#endif

bool monitor_enable();
int monitor_bsd();
bool set_channel(int in_ch);
int get_channel();

bool getmediaopt(int options, int mode);
bool setmediaopt(int options, int mode);
bool getifflags(int flags);
bool setifflags(int value);
int get80211(int type, int val, int len, u_int8_t *data);
bool set80211(int type, int val, int len, u_int8_t *data);

bool pcap_open_source();
bool open_source(char *);
//bool pcap_close_source();
bool check_datalink(int dlt);

int pcap_read_packet(int);
