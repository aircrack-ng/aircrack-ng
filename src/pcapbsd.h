//#ifdef
#include <pcap.h>
//#include <net/bpf.h>
//#else
//#include <pcap/pcap.h>
//#include <pcap/net/bpf.h>

// Custom packet stream headers

// Define this for the max length of a ssid, not counting os-trailing null
#define MAX_SSID_LEN 32

// Define this for wlan-ng DLT_PRISM_HEADER support
#define WLAN_DEVNAMELEN_MAX 16

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

#define bool char
#define false -1
#define true 1

bool monitor_enable(int in_ch);
bool monitor_reset();
bool set_channel(int in_ch);
int get_channel();
int monitor_bsd(int in_ch);
int unmonitor_bsd(int in_ch);

bool getmediaopt(int options, int mode);
bool setmediaopt(int options, int mode);
bool getifflags(int flags);
bool setifflags(int value);
bool get80211(int type, int val, int len, u_int8_t *data);
bool set80211(int type, int val, int len, u_int8_t *data);

bool PcapOpenSource();
bool PcapCloseSource();
bool OpenSource(char *);
bool CheckDatalink(int dlt);
