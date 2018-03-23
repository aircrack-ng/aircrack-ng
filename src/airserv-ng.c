 /*
  *  Server for osdep network driver.  Uses osdep itself!  [ph33r teh recursion]
  *
  *  Copyright (c) 2007-2009  Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  Advanced WEP attacks developed by KoreK
  *  WPA-PSK  attack code developed by Joshua Wright
  *  SHA1 MMX assembly code written by Simon Marechal
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
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>

#ifdef __NetBSD__
	#include <sys/select.h>
#endif

#include "osdep/osdep.h"
#include "osdep/network.h"
#include "version.h"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);

void sighandler( int signum )
{
    if( signum == SIGPIPE )
        printf("broken pipe!\n");
}

struct client {
	int		c_s;
	char		c_ip[16];

	struct client	*c_next;
	struct client	*c_prev;
};

static struct sstate {
	int		ss_s;
	struct wif	*ss_wi;
	struct client	ss_clients;
	int		ss_level;
} _ss;

static struct sstate *get_ss()
{
	return &_ss;
}

static void usage(char *p)
{
	if (p) {}
	char *version_info = getVersion("Airserv-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		"  %s - (C) 2007, 2008, 2009 Andrea Bittau\n"
		"  https://www.aircrack-ng.org\n"
		"\n"
		"  Usage: airserv-ng <options>\n"
		"\n"
		"  Options:\n"
		"\n"
		"       -h         : This help screen\n"
		"       -p  <port> : TCP port to listen on (default:666)\n"
		"       -d <iface> : Wifi interface to use\n"
		"       -c  <chan> : Channel to use\n"
		"       -v <level> : Debug level (1 to 3; default: 1)\n"
		"\n",
		version_info);
	free(version_info);
	exit(1);
}

static void debug(struct sstate *ss, struct client *c, int l, char *fmt, ...)
{
	va_list ap;

	if (ss->ss_level < l)
		return;

	printf("[%s] ", c->c_ip);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

#if 0
static void print_clients(struct sstate *ss)
{
	struct client *c = ss->ss_clients.c_next;
	int i = 1;

	while (c != &ss->ss_clients) {
		printf("Client %d fd %d\n", i++, c->c_s);

		c = c->c_next;
	}
}
#endif

static void client_add(struct sstate *ss, int s, struct sockaddr_in *s_in)
{
	struct client *c;

	if (!(c = calloc(sizeof(struct client), 1)))
		err(1, "calloc()");

	c->c_s = s;
	strncpy(c->c_ip, inet_ntoa(s_in->sin_addr), sizeof(c->c_ip)-1);
	printf("Connect from %s\n", c->c_ip);

	c->c_prev = &ss->ss_clients;
	c->c_next = ss->ss_clients.c_next;
	c->c_next->c_prev = c;
	ss->ss_clients.c_next = c;
}

static void client_kill(struct client *c)
{
	c->c_prev->c_next = c->c_next;
	c->c_next->c_prev = c->c_prev;
	printf("Death from %s\n", c->c_ip);
	free(c);
	c = NULL;
}

static void card_open(struct sstate *ss, char *dev)
{
	struct wif *wi = wi_open(dev);

	if (!wi)
		err(1, "wi_open()");
	ss->ss_wi = wi;
}

static int card_set_chan(struct sstate *ss, int chan)
{
	return wi_set_channel(ss->ss_wi, chan);
}

static int card_get_chan(struct sstate *ss)
{
	return wi_get_channel(ss->ss_wi);
}

static int card_set_rate(struct sstate *ss, int rate)
{
	return wi_set_rate(ss->ss_wi, rate);
}

static int card_get_rate(struct sstate *ss)
{
	return wi_get_rate(ss->ss_wi);
}

static int card_get_monitor(struct sstate *ss)
{
	return wi_get_monitor(ss->ss_wi);
}

static int card_read(struct sstate *ss, void *buf, int len, struct rx_info *ri)
{
	int rc;

	if ((rc = wi_read(ss->ss_wi, buf, len, ri)) == -1)
		err(1, "wi_read()");

	return rc;
}

static int card_write(struct sstate *ss, void *buf, int len, struct tx_info *ti)
{
	return wi_write(ss->ss_wi, buf, len, ti);
}

static int card_get_mac(struct sstate *ss, unsigned char *mac)
{
	return wi_get_mac(ss->ss_wi, mac);
}

static void open_sock(struct sstate *ss, int port)
{
	int s;
	struct sockaddr_in s_in;
	int one = 1;
	memset(&s_in, 0, sizeof(struct sockaddr_in));

	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	s_in.sin_addr.s_addr = INADDR_ANY;

	if ((s = socket(s_in.sin_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");

	ss->ss_s = s;
}

static void open_card_and_sock(struct sstate *ss, char *dev, int port, int chan)
{
	printf("Opening card %s\n", dev);
	card_open(ss, dev);
	printf("Setting chan %d\n", chan);
	if (card_set_chan(ss, chan) == -1)
		err(1, "card_set_chan()");

	printf("Opening sock port %d\n", port);
	open_sock(ss, port);

	printf("Serving %s chan %d on port %d\n", dev, chan, port);
}

static void net_send_kill(struct client *c,
			  int cmd, void *data, int len)
{
	if (net_send(c->c_s, cmd, data, len) == -1)
		client_kill(c);
}

static void handle_set_chan(struct sstate *ss, struct client *c,
			    unsigned char *buf, int len)
{
	uint32_t chan;
	uint32_t rc;

	if (len != sizeof(chan)) {
		client_kill(c);
		return;
	}

	chan = *((uint32_t*)buf);
	chan = ntohl(chan);

	debug(ss, c, 2, "Got setchan %d\n", chan);
	rc = card_set_chan(ss, chan);

	rc = htonl(rc);
	net_send_kill(c, NET_RC, &rc, sizeof(rc));
}

static void handle_set_rate(struct sstate *ss, struct client *c,
			    unsigned char *buf, int len)
{
	uint32_t rate;
	uint32_t rc;

	if (len != sizeof(rate)) {
		client_kill(c);
		return;
	}

	rate = *((uint32_t*)buf);
	rate = ntohl(rate);

	debug(ss, c, 2, "Got setrate %d\n", rate);
	rc = card_set_rate(ss, rate);

	rc = htonl(rc);
	net_send_kill(c, NET_RC, &rc, sizeof(rc));
}

static void handle_get_mac(struct sstate *ss, struct client *c)
{
	unsigned char mac[6];
	int rc;

	rc = card_get_mac(ss, mac);
	if (rc == -1) {
		uint32_t x = htonl(rc);

		net_send_kill(c, NET_RC, &x, sizeof(x));
	} else
		net_send_kill(c, NET_MAC, mac, 6);
}

static void handle_get_chan(struct sstate *ss, struct client *c)
{
	int rc = card_get_chan(ss);
	uint32_t chan;

	chan = htonl(rc);

	net_send_kill(c, NET_RC, &chan, sizeof(chan));
}

static void handle_get_rate(struct sstate *ss, struct client *c)
{
	int rc = card_get_rate(ss);
	uint32_t rate;

	rate = htonl(rc);

	net_send_kill(c, NET_RC, &rate, sizeof(rate));
}

static void handle_get_monitor(struct sstate *ss, struct client *c)
{
	int rc = card_get_monitor(ss);
	uint32_t x;

	x = htonl(rc);

	net_send_kill(c, NET_RC, &x, sizeof(x));
}

static void handle_write(struct sstate *ss, struct client *c,
			 void *buf, int len)
{
	struct tx_info *ti = buf;
	void *hdr = (ti+1);
	int rc;
	uint32_t x;

	len -= sizeof(*ti);

	debug(ss, c, 2, "Relaying %d bytes packet from client\n", len);
	rc = card_write(ss, hdr, len, ti);
	x = htonl(rc);

	net_send_kill(c, NET_RC, &x, sizeof(x));
}

static void handle_client(struct sstate *ss, struct client *c)
{
	unsigned char buf[2048];
	int len = sizeof(buf);
	int cmd;

	cmd = net_get(c->c_s, buf, &len);
	if (cmd == -1) {
		debug(ss, c, 2, "handle_client: net_get()\n");
		client_kill(c);
		return;
	}

	/* figure out command */
	switch (cmd) {
	case NET_SET_CHAN:
		handle_set_chan(ss, c, buf, len);
		break;

	case NET_SET_RATE:
		handle_set_rate(ss, c, buf, len);
		break;

	case NET_GET_MAC:
		handle_get_mac(ss, c);
		break;

	case NET_GET_CHAN:
		handle_get_chan(ss, c);
		break;

	case NET_GET_RATE:
		handle_get_rate(ss, c);
		break;

	case NET_GET_MONITOR:
		handle_get_monitor(ss, c);
		break;

	case NET_WRITE:
		handle_write(ss, c, buf, len);
		break;

	default:
		printf("Unknown request %d\n", cmd);
		client_kill(c);
		break;
	}
}

static void handle_server(struct sstate *ss)
{
	int dude;
	struct sockaddr_in s_in;
	socklen_t len;

	len = sizeof(s_in);
	if ((dude = accept(ss->ss_s, (struct sockaddr*) &s_in, &len)) == -1)
		err(1, "accept()");

	client_add(ss, dude, &s_in);
}

static void client_send_packet(struct sstate *ss, struct client *c,
			       unsigned char *buf, int rd)
{
	/* XXX check if TX will block */
	if (rd == -1) {
		uint32_t rc = htonl(rd);
		debug(ss, c, 3, "Sending result code %d to client\n", rd);

		net_send_kill(c, NET_RC, &rc, sizeof(rc));
	} else {
		debug(ss, c, 3, "Sending %d bytes packet to client\n", rd);

		net_send_kill(c, NET_PACKET, buf, rd);
	}
}

static void handle_card(struct sstate *ss)
{
	unsigned char buf[2048];
	int rd;
	struct rx_info *ri = (struct rx_info*) buf;
	struct client *c;
	struct client *next_c;

	rd = card_read(ss, ri + 1, sizeof(buf) - sizeof(*ri), ri);
	if (rd >= 0)
	    rd += sizeof(*ri);

	ri->ri_mactime = __cpu_to_be64(ri->ri_mactime);
	ri->ri_power = __cpu_to_be32(ri->ri_power);
	ri->ri_noise = __cpu_to_be32(ri->ri_noise);
	ri->ri_channel = __cpu_to_be32(ri->ri_channel);
	ri->ri_rate = __cpu_to_be32(ri->ri_rate);
	ri->ri_antenna = __cpu_to_be32(ri->ri_antenna);
	ri->ri_freq = __cpu_to_be32(ri->ri_freq);

	c = ss->ss_clients.c_next;
	while (c != &ss->ss_clients) {
		next_c = c->c_next;
		client_send_packet(ss, c, buf, rd);
		c = next_c;
	}
}

static void serv(struct sstate *ss, char *dev, int port, int chan)
{
	int max;
	fd_set fds;
	struct client *c;
	struct client *next;
	int card_fd;

	open_card_and_sock(ss, dev, port, chan);
	card_fd = wi_fd(ss->ss_wi);

	while (1) {
		/* server */
		max = ss->ss_s;
		FD_ZERO(&fds);
		FD_SET(max, &fds);

		/* clients */
		c = ss->ss_clients.c_next;
		while (c != &ss->ss_clients) {
			FD_SET(c->c_s, &fds);
			if (c->c_s > max)
				max = c->c_s;

			c = c->c_next;
		}

		/* card */
		FD_SET(card_fd, &fds);
		if (card_fd > max)
			max = card_fd;

		if (select(max+1, &fds, NULL, NULL, NULL) == -1)
			err(1, "select()");

		/* handle clients */
		c = ss->ss_clients.c_next;
		while (c != &ss->ss_clients) {
			next = c->c_next;
			if (FD_ISSET(c->c_s, &fds))
				handle_client(ss, c);

			c = next;
		}

		/* handle server */
		if (FD_ISSET(ss->ss_s, &fds))
			handle_server(ss);

		if (FD_ISSET(card_fd, &fds))
			handle_card(ss);
	}
}

int main(int argc, char *argv[])
{
	char *device = NULL;
	int port = 666;
	int ch;
	int chan = 1;
	struct sstate *ss = get_ss();

	memset(ss, 0, sizeof(*ss));
	ss->ss_clients.c_next = ss->ss_clients.c_prev = &ss->ss_clients;

	while ((ch = getopt(argc, argv, "p:d:hc:v:")) != -1) {
		switch (ch) {
		case 'p':
			port = atoi(optarg);
			break;

		case 'd':
			device = optarg;
			break;

		case 'v':
			ss->ss_level = atoi(optarg);
			break;

		case 'c':
			chan = atoi(optarg);
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}

        signal(SIGPIPE, sighandler);

	if (!device || chan <= 0)
		usage(argv[0]);

	serv(ss, device, port, chan);

	exit(0);
}
