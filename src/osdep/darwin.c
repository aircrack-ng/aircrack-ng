 /*
  *  Copyright (c) 2009, Kyle Fuller <inbox@kylefuller.co.uk>, based upon
  *  freebsd.c by Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for Darwin.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <strings.h> // memcpy
#include <sys/param.h> // MIN

#include "osdep.h"

int darwin_read(struct wif *wi, unsigned char *h80211, int len, struct rx_info *ri) {
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */


    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    //if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //  fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //  return(2);
    //}
    //if (pcap_setfilter(handle, &fp) == -1) {
    //  fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //  return(2);
    //}
    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);

    int min_len = MIN(len,header.len);

    memcpy(h80211, packet, min_len);

    return min_len;
}

int darwin_write(struct wif *wi, unsigned char *h80211, int len, struct tx_info *ti) {
 return 0;
}

int darwin_set_ht_channel(struct wif *wi, int chan, unsigned int htval) {
 return 0;
}

int darwin_set_channel(struct wif *wi, int chan) {
 return 0;
}

int darwin_get_channel(struct wif *wi) {
 return 0;
}

int darwin_set_freq(struct wif *wi, int freq) {
 return 0;
}

int darwin_get_freq(struct wif *wi) {
 return 0;
}

void darwin_close(struct wif *wi) {
 return;
}

int	darwin_fd(struct wif *wi) {
 return 0;
}

int	darwin_get_mac(struct wif *wi, unsigned char *mac) {
 return 0;
}

int	darwin_set_mac(struct wif *wi, unsigned char *mac) {
 return 0;
}

int	darwin_set_rate(struct wif *wi, int rate) {
 return 0;
}

int	darwin_get_rate(struct wif *wi) {
 return 0;
}

int	darwin_set_mtu(struct wif *wi, int mtu) {
 return 0;
}

int	darwin_get_mtu(struct wif *wi) {
 return 0;
}

int darwin_get_monitor(struct wif *wi) {
 return 0;
}

struct wif *wi_open_osdep(char *ifname)
{
	if (ifname) {} /* XXX unused parameter */
    printf("I am on darwin, trying to open the wifi interface\n");

    struct wif* wi = calloc(1, sizeof(struct wif));
    wi->wi_read         = darwin_read;
    wi->wi_write        = darwin_write;
    wi->wi_set_channel  = darwin_set_channel;
    wi->wi_get_channel  = darwin_get_channel;
    wi->wi_set_freq		= darwin_set_freq;
    wi->wi_get_freq		= darwin_get_freq;
    wi->wi_close        = darwin_close;
    wi->wi_fd		    = darwin_fd;
    wi->wi_get_mac		= darwin_get_mac;
    wi->wi_set_mac		= darwin_set_mac;
    wi->wi_get_monitor  = darwin_get_monitor;
    wi->wi_get_rate		= darwin_get_rate;
    wi->wi_set_rate		= darwin_set_rate;
    wi->wi_get_mtu		= darwin_get_mtu;
    wi->wi_set_mtu		= darwin_set_mtu;
	//errno = EOPNOTSUPP;
	return wi;
}

int get_battery_state(void)
{
	errno = EOPNOTSUPP;
	return -1;
}

int create_tap(void)
{
	errno = EOPNOTSUPP;
	return -1;
}
