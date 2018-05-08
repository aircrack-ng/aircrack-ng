#ifndef _OSDEP_NEXMON_CONTROL_H_
#define _OSDEP_NEXMON_CONTROL_H_

#include <stdbool.h>

#ifdef CONFIG_LIBNL
    #include <linux/netlink.h>
    #define NETLINK_USER 31
    #define NEXUDP_IOCTL 0
#endif


#define WLC_GET_MAGIC 0

#define WLC_SET_MONITOR 108
#define WLC_GET_MONITOR 107
#define WLC_IOCTL_MAGIC 0x14e46c77





struct nex_ioctl {
    unsigned int cmd;   	/* common ioctl definition */
    void *buf;  			/* pointer to user buffer */
    unsigned int len;   	/* length of user buffer */
    bool set;   			/* get or set request (optional) */
    unsigned int used;  	/* bytes read or written (optional) */
    unsigned int needed;    /* bytes needed (optional) */
    unsigned int driver;    /* to identify target driver */
};

#ifdef CONFIG_LIBNL

struct nexudp_header {
    char nex[3];
    char type;
    int securitycookie;
} __attribute__((packed));

struct nexudp_ioctl_header {
    struct nexudp_header nexudphdr;
    unsigned int cmd;
    unsigned int set;
    char payload[1];
} __attribute__((packed));

struct nexio {
    unsigned int securitycookie;
	int sock_rx_ioctl;
	int sock_tx;
};

#else /* CONFIG_LIBNL */

struct nexio {
	struct ifreq *ifr;
};

#endif /* CONFIG_LIBNL */


struct nexio * nexmon_init(const char *ifname);
int is_nexmon_monitor_enabled(const char * iface);
int enable_nexmon_monitor_mode(const char * iface);

#endif /* _OSDEP_NEXMON_CONTROL_H_ */