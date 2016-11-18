 /*
  *  Copyright (c) 2007-2009 Andrea Bittau <a.bittau@cs.ucl.ac.uk>
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
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <assert.h>
#include <grp.h>
#include <sys/utsname.h>

#ifdef __NetBSD__
	#include <sys/select.h>
#endif

#include "easside.h"
#include "version.h"

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);

unsigned char ids[8192];
unsigned short last_id;
int wrap;

int is_dup(unsigned short id)
{
	int idx = id/8;
	int bit = id % 8;
	unsigned char mask = (1 << bit);

	if (ids[idx] & mask)
		return 1;

	ids[idx] |= mask;
	return 0;
}

int handle(int s, unsigned char* data, int len, struct sockaddr_in *s_in)
{
	char buf[2048];
	unsigned short *cmd = (unsigned short *)buf;
	int plen;
	struct in_addr *addr = &s_in->sin_addr;
	unsigned short *pid = (unsigned short*) data;

	/* inet check */
	if (len == S_HELLO_LEN && memcmp(data, "sorbo", 5) == 0) {
		unsigned short *id = (unsigned short*) (data+5);
		int x = 2+4+2;

		*cmd = htons(S_CMD_INET_CHECK);
		memcpy(cmd+1, addr, 4);
		memcpy(cmd+1+2, id, 2);

		printf("Inet check by %s %d\n",
		       inet_ntoa(*addr), ntohs(*id));
		if (send(s, buf, x, 0) != x)
			return 1;

		return 0;
	}

	*cmd++ = htons(S_CMD_PACKET);
	*cmd++ = *pid;
	plen = len - 2;
	if (plen < 0)
        	return 0;

	last_id = ntohs(*pid);
	if (last_id > 20000)
		wrap = 1;
	if (wrap && last_id < 100) {
		wrap = 0;
		memset(ids, 0, sizeof(ids));
	}

	printf("Got packet %d %d", last_id, plen);
	if (is_dup(last_id)) {
		printf(" (DUP)\n");
		return 0;
	}
	printf("\n");

	*cmd++ = htons(plen);
	memcpy(cmd, data+2, plen);

	plen += 2 + 2 + 2;
	assert(plen <= (int) sizeof(buf));
	if (send(s, buf, plen, 0) != plen)
		return 1;

	return 0;
}

void handle_dude(int dude, int udp)
{
	unsigned char buf[2048];
	int rc;
	fd_set rfds;
	int maxfd;
	struct sockaddr_in s_in;
	socklen_t len;

	/* handshake */
	rc = recv(dude, buf, 5, 0);
	if (rc != 5) {
		close(dude);
		return;
	}

	if (memcmp(buf, "sorbo", 5) != 0) {
		close(dude);
		return;
	}

	if (send(dude, "sorbox", 6, 0) != 6) {
		close(dude);
		return;
	}

	printf("Handshake complete\n");
	memset(ids, 0, sizeof(ids));
	last_id = 0;
	wrap = 0;

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(udp, &rfds);
		FD_SET(dude, &rfds);

		if (dude > udp)
			maxfd = dude;
		else
			maxfd = udp;

		if (select(maxfd+1, &rfds, NULL, NULL, NULL) == -1)
			err(1, "select()");

		if (FD_ISSET(dude, &rfds))
			break;

		if (!FD_ISSET(udp, &rfds))
			continue;

		len = sizeof(s_in);
		rc = recvfrom(udp, buf, sizeof(buf), 0,
			      (struct sockaddr*) &s_in, &len);
		if (rc == -1)
			err(1, "read()");

		if (handle(dude, buf, rc, &s_in))
			break;
	}
	close(dude);
}

void drop_privs()
{
	if (chroot(".") == -1)
		err(1, "chroot()");

	if (setgroups(0, NULL) == -1)
		err(1, "setgroups()");

	if (setgid(69) == -1)
		err(1, "setgid()");

	if (setuid(69) == -1)
		err(1, "setuid()");
}

void usage()
{
    char *version_info = getVersion("Buddy-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		"  %s - (C) 2007,2008 Andrea Bittau\n"
		"  http://www.aircrack-ng.org\n"
		"\n"
		"  Usage: buddy-ng <options>\n"
		"\n"
		"  Options:\n"
		"\n"
		"       -h        : This help screen\n"
		"       -p        : Don't drop privileges\n"
		"\n",
		version_info);
	free(version_info);

	exit(1);
}

int main(int argc, char *argv[])
{
	struct utsname utsName;
	struct sockaddr_in s_in;
	struct sockaddr_in dude_sin;
	int len, udp, ch, dude, s;
	int port = S_DEFAULT_PORT;
	int drop;

	while ((ch = getopt(argc, argv, "ph")) != -1) {
		switch (ch) {
		case 'p':
			drop = 0;
			break;

		default:
		case 'h':
			usage();
			break;

		}
	}

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_addr.s_addr = INADDR_ANY;
	s_in.sin_port = htons(S_DEFAULT_UDP_PORT);

	udp = socket(s_in.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (udp == -1)
		err(1, "socket(UDP)");
	if (bind(udp, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1)
		err(1, "socket(TCP)");

	drop = 1;

	// Do not drop privileges on Windows (doing it fails).
	if (uname(&utsName) == 0)
	{
		drop = strncasecmp(utsName.sysname, "cygwin", 6);
	}

	if (drop)
		drop_privs();

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_port = htons(port);
	s_in.sin_addr.s_addr = INADDR_ANY;

	len = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &len, sizeof(len)) == -1)
		err(1, "setsockopt(SO_REUSEADDR)");

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");


	while (1) {
		len = sizeof(dude_sin);
		printf("Waiting for connexion\n");
		dude = accept(s, (struct sockaddr*) &dude_sin,
			      (socklen_t*) &len);
		if (dude == -1)
			err(1, "accept()");

		printf("Got connection from %s\n",
		       inet_ntoa(dude_sin.sin_addr));
		handle_dude(dude, udp);
		printf("That was it\n");
	}
	exit(0);
}
