/*-
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * OS dependent API for using card via network.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "osdep.h"
#include "network.h"

struct priv_net {
	int		pn_s;
};

static int net_send(struct priv_net *pn, int command, void *arg, int len)
{
	struct net_hdr nh;

	memset(&nh, 0, sizeof(nh));
	nh.nh_type	= command;
	nh.nh_len	= htonl(len);

	if (send(pn->pn_s, &nh, sizeof(nh), 0) != sizeof(nh))
		return -1;

	if (send(pn->pn_s, arg, len, 0) != len)
		return -1;
	
	return 0;
}

static int read_exact(struct priv_net *pn, void *arg, int len)
{
	unsigned char *p = arg;
	int rc;

	while (len) {
		rc = recv(pn->pn_s, p, len, 0);
		if (rc == -1)
			return -1;
		p += rc;
		len -= rc;

		assert(rc >= 0);
	}

	return 0;
}

static int net_get(struct priv_net *pn, void *arg, int *len)
{
	struct net_hdr nh;
	int plen;

	if (read_exact(pn, &nh, sizeof(nh)) == -1)
		return -1;

	plen = ntohl(nh.nh_len);
	assert(plen <= *len); /* XXX */

	*len = plen;
	if (read_exact(pn, arg, *len) == -1)
		return -1;

	return nh.nh_type;
}

static int net_cmd(struct priv_net *pn, int command, void *arg, int alen)
{
	uint32_t rc;
	int len;
	int cmd;

	if (!net_send(pn, command, arg, alen))
		return -1;

	len = sizeof(rc);
	cmd = net_get(pn, &rc, &len);
	if (cmd == -1)
		return -1;
	assert(cmd == NET_RC);
	assert(len == sizeof(rc));

	return ntohl(rc);
}

static int net_read(struct wif *wi, unsigned char *h80211, int len,
		    struct rx_info *ri)
{
	struct priv_net *pn = wi_priv(wi);
	unsigned char buf[2048];
	int cmd;
	int sz = sizeof(*ri);
	int l;

	l = sizeof(buf);
	cmd = net_get(pn, buf, &l);
	if (cmd == NET_RC)
		return ntohl(*((uint32_t*)buf));
	assert(cmd == NET_PACKET);

	/* XXX */
	memcpy(ri, buf, sz);
	l -= sz;
	assert(l > 0);
	if (l > len)
		l = len;
	memcpy(h80211, &buf[sz], l);

	return cmd;
}

static int net_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_net *pn = wi_priv(wi);
	unsigned char buf[6];
	int cmd;
	int sz = sizeof(buf);
	
	cmd = net_get(pn, buf, &sz);
	if (cmd == NET_RC)
		return ntohl(*((uint32_t*)buf));
	assert(cmd == NET_MAC);
	assert(sz == sizeof(buf));

	memcpy(mac, buf, 6);

	return 0;
}

static int net_write(struct wif *wi, unsigned char *h80211, int len,
		     struct tx_info *ti)
{
	struct priv_net *pn = wi_priv(wi);
	int sz = sizeof(*ti);
	unsigned char buf[2048];
	unsigned char *ptr = buf;

	/* XXX */
	memcpy(ptr, ti, sz);
	ptr += sz;
	memcpy(ptr, h80211, len);
	sz += len;

	return net_cmd(pn, NET_WRITE, buf, sz);
}

static int net_set_channel(struct wif *wi, int chan)
{
	uint32_t c = htonl(chan);

	return net_cmd(wi_priv(wi), NET_SET_CHAN, &c, sizeof(c));
}

static int net_get_channel(struct wif *wi)
{
	struct priv_net *pn = wi_priv(wi);

	return net_cmd(pn, NET_GET_CHAN, NULL, 0);
}

static void do_net_free(struct wif *wi)
{
	assert(wi->wi_priv);
	free(wi->wi_priv);
	wi->wi_priv = 0;
	free(wi);
}

static void net_close(struct wif *wi)
{
	struct priv_net *pn = wi_priv(wi);

	close(pn->pn_s);
	do_net_free(wi);
}

static int get_ip_port(char *iface, char *ip)
{
	char *host;
	char *ptr;
	int port = -1;
	struct in_addr addr;
	
	host = strdup(iface);
	if (!host)
		return -1;
	
	ptr = strchr(host, ':');
	if (!ptr)
		goto out;

	*ptr++ = 0;

	if (!inet_aton(host, &addr))
		goto out; /* XXX resolve hostname */

	assert(strlen(host) <= 15);
	strcpy(ip, host);
	port = atoi(ptr);

out:
	free(host);
	return port;
}

static int handshake(int s)
{
	if (s) {} /* XXX unused */
	/* XXX do a handshake */
	return 0;
}

static int do_net_open(char *iface)
{
	int s, port;
	char ip[16];
	struct sockaddr_in s_in;

	port = get_ip_port(iface, ip);
	if (port == -1)
		return -1;
	
	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	if (!inet_aton(ip, &s_in.sin_addr))
		return -1;

	if ((s = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1) {
		close(s);
		return -1;
	}

	if (!handshake(s)) {
		close(s);
		return -1;
	}

	return s;
}

static int net_fd(struct wif *wi)
{
	struct priv_net *pn = wi_priv(wi);

	return pn->pn_s;
}

struct wif *net_open(char *iface)
{
	struct wif *wi;
	struct priv_net *pn;
	int s;

	/* setup wi struct */
	wi = wi_alloc(sizeof(*pn));
	if (!wi)
		return NULL;
	wi->wi_read		= net_read;
	wi->wi_write		= net_write;
	wi->wi_set_channel	= net_set_channel;
	wi->wi_get_channel	= net_get_channel;
	wi->wi_close		= net_close;
	wi->wi_fd		= net_fd;
	wi->wi_get_mac		= net_get_mac;

	/* setup iface */
	s = do_net_open(iface);
	if (s == -1) {
		do_net_free(wi);
		return NULL;
	}
	
	/* setup private state */
	pn = wi_priv(wi);
	pn->pn_s = s;

	return wi;
}
