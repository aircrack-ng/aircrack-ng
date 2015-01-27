 /*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for using card via network.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/select.h>
#include <errno.h>

#include "osdep.h"
#include "network.h"

#define QUEUE_MAX 666

struct queue {
	unsigned char	q_buf[2048];
	int		q_len;

	struct queue	*q_next;
	struct queue	*q_prev;
};

struct priv_net {
	int		pn_s;
	struct queue	pn_queue;
	struct queue	pn_queue_free;
	int		pn_queue_len;
};

int net_send(int s, int command, void *arg, int len)
{
	struct net_hdr *pnh;
	char *pktbuf;
	size_t pktlen;

	pktlen = sizeof(struct net_hdr) + len;

	pktbuf = (char*)calloc(sizeof(char), pktlen);
	if (pktbuf == NULL) {
		perror("calloc");
		goto net_send_error;
	}

	pnh = (struct net_hdr*)pktbuf;
	pnh->nh_type = command;
	pnh->nh_len = htonl(len);

	memcpy(pktbuf + sizeof(struct net_hdr), arg, len);

	for (;;) {
		ssize_t rc = send(s, pktbuf, pktlen, 0);

		if ((size_t)rc == pktlen)
			break;

		if (rc == EAGAIN || rc == EWOULDBLOCK || rc == EINTR)
			continue;

		if (rc == ECONNRESET)
			printf("Connection reset while sending packet!\n");

		goto net_send_error;
	}

	free(pktbuf);
	return 0;

net_send_error:
	free(pktbuf);
	return -1;
}

int net_read_exact(int s, void *arg, int len)
{
	ssize_t rc;
	int rlen = 0;
	char *buf = (char*)arg;
	while (rlen < len) {
		rc = recv(s, buf, (len - rlen), 0);

		if (rc < 1) {
			if (rc == -1 && (errno == EAGAIN || errno == EINTR)) {
				usleep(100);
				continue;
			}

			return -1;
		}

		buf += rc;
		rlen += rc;
	}

	return 0;
}

int net_get(int s, void *arg, int *len)
{
	struct net_hdr nh;
	int plen;

	if (net_read_exact(s, &nh, sizeof(nh)) == -1)
        {
		return -1;
        }

	plen = ntohl(nh.nh_len);
	if (!(plen <= *len))
		printf("PLEN %d type %d len %d\n",
			plen, nh.nh_type, *len);
	assert(plen <= *len && plen >= 0);

	*len = plen;
	if ((*len) && (net_read_exact(s, arg, *len) == -1))
        {
            return -1;
        }

	return nh.nh_type;
}

static void queue_del(struct queue *q)
{
	q->q_prev->q_next = q->q_next;
	q->q_next->q_prev = q->q_prev;
}

static void queue_add(struct queue *head, struct queue *q)
{
	struct queue *pos = head->q_prev;

	q->q_prev = pos;
	q->q_next = pos->q_next;
	q->q_next->q_prev = q;
	pos->q_next = q;
}

#if 0
static int queue_len(struct queue *head)
{
	struct queue *q = head->q_next;
	int i = 0;

	while (q != head) {
		i++;
		q = q->q_next;
	}

	return i;
}
#endif

static struct queue *queue_get_slot(struct priv_net *pn)
{
	struct queue *q = pn->pn_queue_free.q_next;

	if (q != &pn->pn_queue_free) {
		queue_del(q);
		return q;
	}

	if (pn->pn_queue_len++ > QUEUE_MAX)
		return NULL;

	return malloc(sizeof(*q));
}

static void net_enque(struct priv_net *pn, void *buf, int len)
{
	struct queue *q;

	q = queue_get_slot(pn);
	if (!q)
		return;

	q->q_len = len;
	assert((int) sizeof(q->q_buf) >= q->q_len);
	memcpy(q->q_buf, buf, q->q_len);
	queue_add(&pn->pn_queue, q);
}

static int net_get_nopacket(struct priv_net *pn, void *arg, int *len)
{
	unsigned char buf[2048];
	int l = sizeof(buf);
	int c;

	while (1) {
		l = sizeof(buf);
		c = net_get(pn->pn_s, buf, &l);

		if (c != NET_PACKET && c > 0)
			break;

                if(c > 0)
                    net_enque(pn, buf, l);
	}

	assert(l <= *len);
	memcpy(arg, buf, l);
	*len = l;

	return c;
}

static int net_cmd(struct priv_net *pn, int command, void *arg, int alen)
{
	uint32_t rc;
	int len;
	int cmd;

	if (net_send(pn->pn_s, command, arg, alen) == -1)
        {
		return -1;
        }

	len = sizeof(rc);
	cmd = net_get_nopacket(pn, &rc, &len);
	if (cmd == -1)
        {
		return -1;
        }
	assert(cmd == NET_RC);
	assert(len == sizeof(rc));

	return ntohl(rc);
}

static int queue_get(struct priv_net *pn, void *buf, int len)
{
	struct queue *head = &pn->pn_queue;
	struct queue *q = head->q_next;

	if (q == head)
		return 0;

	assert(q->q_len <= len);
	memcpy(buf, q->q_buf, q->q_len);

	queue_del(q);
	queue_add(&pn->pn_queue_free, q);

	return q->q_len;
}

static int net_read(struct wif *wi, unsigned char *h80211, int len,
		    struct rx_info *ri)
{
	struct priv_net *pn = wi_priv(wi);
	uint32_t buf[512]; // 512 * 4 = 2048
	unsigned char *bufc = (unsigned char*)buf;
	int cmd;
	int sz = sizeof(*ri);
	int l;
	int ret;

	/* try queue */
	l = queue_get(pn, buf, sizeof(buf));
	if (!l) {
		/* try reading form net */
		l = sizeof(buf);
		cmd = net_get(pn->pn_s, buf, &l);

		if (cmd == -1)
			return -1;
		if (cmd == NET_RC)
		{
			ret = ntohl((buf[0]));
			return ret;
		}
		assert(cmd == NET_PACKET);
	}

	/* XXX */
	if (ri) {
		// re-assemble 64-bit integer
		ri->ri_mactime = __be64_to_cpu(((uint64_t)buf[0] << 32 || buf[1] ));
		ri->ri_power = __be32_to_cpu(buf[2]);
		ri->ri_noise = __be32_to_cpu(buf[3]);
		ri->ri_channel = __be32_to_cpu(buf[4]);
		ri->ri_rate = __be32_to_cpu(buf[5]);
		ri->ri_antenna = __be32_to_cpu(buf[6]);
	}
	l -= sz;
	assert(l > 0);
	if (l > len)
		l = len;
	memcpy(h80211, &bufc[sz], l);

	return l;
}

static int net_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_net *pn = wi_priv(wi);
	uint32_t buf[2]; // only need 6 bytes, this provides 8
	int cmd;
	int sz = 6;

	if (net_send(pn->pn_s, NET_GET_MAC, NULL, 0) == -1)
		return -1;

	cmd = net_get_nopacket(pn, buf, &sz);
	if (cmd == -1)
		return -1;
	if (cmd == NET_RC)
		return ntohl(buf[0]);
	assert(cmd == NET_MAC);
	assert(sz == 6);

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
	if (ti)
		memcpy(ptr, ti, sz);
	else
		memset(ptr, 0, sizeof(*ti));

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

static int net_set_rate(struct wif *wi, int rate)
{
	uint32_t c = htonl(rate);

	return net_cmd(wi_priv(wi), NET_SET_RATE, &c, sizeof(c));
}

static int net_get_rate(struct wif *wi)
{
	struct priv_net *pn = wi_priv(wi);

	return net_cmd(pn, NET_GET_RATE, NULL, 0);
}

static int net_get_monitor(struct wif *wi)
{
	return net_cmd(wi_priv(wi), NET_GET_MONITOR, NULL, 0);
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

static int get_ip_port(char *iface, char *ip, const int ipsize)
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
	strncpy(ip, host, ipsize);
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

	port = get_ip_port(iface, ip, sizeof(ip)-1);
	if (port == -1)
		return -1;

	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	if (!inet_aton(ip, &s_in.sin_addr))
		return -1;

	if ((s = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	printf("Connecting to %s port %d...\n", ip, port);

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1) {
		close(s);

		printf("Failed to connect\n");

		return -1;
	}

	if (handshake(s) == -1) {
		close(s);

		printf("Failed to connect - handshake failed\n");

		return -1;
	}

	printf("Connection successful\n");

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
        wi->wi_set_rate    	= net_set_rate;
	wi->wi_get_rate    	= net_get_rate;
	wi->wi_close		= net_close;
	wi->wi_fd		= net_fd;
	wi->wi_get_mac		= net_get_mac;
	wi->wi_get_monitor	= net_get_monitor;

	/* setup iface */
	s = do_net_open(iface);
	if (s == -1) {
		do_net_free(wi);
		return NULL;
	}

	/* setup private state */
	pn = wi_priv(wi);
	pn->pn_s = s;
	pn->pn_queue.q_next = pn->pn_queue.q_prev = &pn->pn_queue;
	pn->pn_queue_free.q_next = pn->pn_queue_free.q_prev
					= &pn->pn_queue_free;

	return wi;
}
