#include "nexmon_control.h"

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <net/if.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

static int nexmon_send_command(struct nexio *nexio, struct nex_ioctl *ioc);

int nexmon_ioctl(struct nexio *nexio, int cmd, void *buf, int len, bool set)
{
    struct nex_ioctl ioc;
    int ret = 0;
    
    if (nexio == NULL || len < 0 || (buf == NULL && len > 0)) {
        return -1;
    }

    /* do it */
    ioc.cmd = cmd;
    ioc.buf = buf;
    ioc.len = len;
    ioc.set = set;
    ioc.driver = WLC_IOCTL_MAGIC;
    ret = nexmon_send_command(nexio, &ioc);

    if (ret < 0 && cmd != WLC_GET_MAGIC) {
        ret = -1;
    }

    return ret;
}

void nexio_free(struct nexio ** n)
{
    if (n == NULL || *n == NULL) {
        return;
    }

    struct nexio * nex = *n;
#ifdef CONFIG_LIBNL    
    if (nex->sock_rx_ioctl != -1) {
        close(nex->sock_rx_ioctl);
        nex->sock_rx_ioctl = -1;
    }
    if (nex->sock_tx != -1) {
        close(nex->sock_tx);
        nex->sock_tx = -1;
    }
#else
    if (nex->ifr) {
        free(nex->ifr);
    }
#endif

    free(nex);
    *n = NULL;
}


int is_nexmon_monitor_enabled(const char * iface)
{
    // Initialize
    struct nexio * nex = nexmon_init(iface);
    if (nex == NULL) {
        return -1;
    }
    
    // Get monitor mode value
    int buf = 0;
    nexmon_ioctl(nex, WLC_GET_MONITOR, &buf, 4, false);
    
    // Free resources
    nexio_free(&nex);
    
    return buf;
}

int enable_nexmon_monitor_mode(const char * iface)
{
    // Initialize
    struct nexio * nex = nexmon_init(iface);
    if (nex == NULL) {
        return -1;
    }

    // Set monitor mode
    int buf = 2; // Radiotap
    int ret = nexmon_ioctl(nex, WLC_SET_MONITOR, &buf, 4, true);

    // Check if it is set correctly
    ret = nexmon_ioctl(nex, WLC_GET_MONITOR, &buf, 4, false);
    
    // Free resources
    nexio_free(&nex);
    
    return ret == 2;
}

#ifdef CONFIG_LIBNL
struct nexio * nexmon_init(const char *ifname)
{
    if (ifname) { }
    int err = 0;
    struct nexio *nexio = (struct nexio *) malloc(sizeof(struct nexio));
    struct sockaddr_nl *snl_tx = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
    struct sockaddr_nl *snl_rx_ioctl = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));

    if (nexio == NULL || snl_tx == NULL || snl_rx_ioctl == NULL) {
        if (nexio) free(nexio);
        if (snl_tx) free(snl_tx);
        if (snl_rx_ioctl) free(snl_rx_ioctl);
        return NULL;
    }

    memset(nexio, 0, sizeof(struct nexio));
    memset(snl_tx, 0, sizeof(struct sockaddr_nl));
    memset(snl_rx_ioctl, 0, sizeof(struct sockaddr_nl));

    snl_tx->nl_family = AF_NETLINK;
    snl_tx->nl_pid = 0; /* For Linux Kernel */
    snl_tx->nl_groups = 0; /* unicast */

    snl_rx_ioctl->nl_family = AF_NETLINK;
    snl_rx_ioctl->nl_pid = getpid();

    nexio->sock_tx = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (nexio->sock_tx < 0) {
        printf("%s: TX socket error (%d: %s)\n", __FUNCTION__, errno, strerror(errno));
        free(nexio);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }
    nexio->sock_rx_ioctl = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (nexio->sock_tx < 0) {
        printf("%s: RX IOCTL socket error (%d: %s)\n", __FUNCTION__, errno, strerror(errno));
        free(nexio);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    // Set 1 second timeout on ioctl receive socket
    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0
    };
    err = setsockopt(nexio->sock_rx_ioctl, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (err == -1) {
        printf("%s: Failed setting socket options on RX IOCTL socket (Error %d: %s)\n", __FUNCTION__, errno, strerror(errno));
        free(nexio);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    err = bind(nexio->sock_rx_ioctl, (struct sockaddr *) snl_rx_ioctl, sizeof(struct sockaddr));
    free(snl_rx_ioctl);
    if (err) {
        printf("%s: Failed binding RX IOCTL socket (Error %d: %s)\n", __FUNCTION__, errno, strerror(errno));
        free(nexio);
        free(snl_tx);
        return NULL;
    }

    err = connect(nexio->sock_tx, (struct sockaddr *) snl_tx, sizeof(struct sockaddr));
    free(snl_tx);
    if (err) {
        printf("%s: Failed connecting (Error %d: %s)\n", __FUNCTION__, errno, strerror(errno));
        free(nexio);
        return NULL;
    }

    return nexio;
}

static int nexmon_send_command(struct nexio *nexio, struct nex_ioctl *ioc)
{
    int frame_len = ioc->len + sizeof(struct nexudp_ioctl_header) - sizeof(char);
    int rx_frame_len = 0;
    struct nexudp_ioctl_header *frame;
    int ret = 0;

    struct nlmsghdr *nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(frame_len));
    if (nlh == NULL) {
        printf("Nexmon: Failed allocating memory for struct nlmsghdr\n");
        return -1;
    }

    memset(nlh, 0, NLMSG_SPACE(frame_len));
    nlh->nlmsg_len = NLMSG_SPACE(frame_len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    frame = (struct nexudp_ioctl_header *) NLMSG_DATA(nlh);

    memcpy(&frame->nexudphdr.nex, "NEX", 3);
    frame->nexudphdr.type = NEXUDP_IOCTL;
    frame->nexudphdr.securitycookie = nexio->securitycookie;

    frame->cmd = ioc->cmd;
    frame->set = ioc->set;

    memcpy(frame->payload, ioc->buf, ioc->len);

    send(nexio->sock_tx, nlh, nlh->nlmsg_len, 0);

    rx_frame_len = recv(nexio->sock_rx_ioctl, nlh, nlh->nlmsg_len, 0);

    if (ioc->set == 0 && rx_frame_len > 0 && frame->cmd == ioc->cmd) {
            memcpy(ioc->buf, frame->payload,
                    (rx_frame_len - sizeof(struct nexudp_ioctl_header) + sizeof(char)) < ioc->len ?
        (rx_frame_len - sizeof(struct nexudp_ioctl_header) + sizeof(char)) : ioc->len);
    }

    free(nlh);

    if (rx_frame_len < 0) {
            ret = -1;
            printf("Nexmon: no valid answer received for command %d (set: %d)\n", ioc->cmd, ioc->set);
    }

    return ret;
}

#else /* USE_NETLINK */

struct nexio * nexmon_init(const char *ifname)
{
    if (ifname == NULL || strlen(ifname) == 0 || strlen(ifname) >= IFNAMSIZ) {
        return NULL;
    }
    
	struct nexio *nexio = (struct nexio *) malloc(sizeof(struct nexio));
    if (nexio == NULL) {
        return NULL;
    }
	memset(nexio, 0, sizeof(struct nexio));

	nexio->ifr = (struct ifreq *) malloc(sizeof(struct ifreq));
    if (nexio->ifr == NULL) {
        free(nexio);
        return NULL
    }
	memset(nexio->ifr, 0, sizeof(struct ifreq));
	snprintf(nexio->ifr->ifr_name, sizeof(nexio->ifr->ifr_name), "%s", ifname);

	return nexio;
}

static int nexmon_send_command(struct nexio *nexio, struct nex_ioctl *ioc)
{
    if (nexio == NULL || nexio->ifr == NULL) {
        return -1;
    }

    int s;
    int ret = 0;

    /* pass ioctl data */
    nexio->ifr->ifr_data = (void *) ioc;

    /* open socket to kernel */
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    ret = ioctl(s, SIOCDEVPRIVATE, nexio->ifr);
    if (ret < 0 && errno != EAGAIN) {
        printf("Nexmon ioctl() failed\n");
        return -1;
    }
    
    /* cleanup */
    close(s);
    return ret;
}

#endif /* USE_NETLINK */