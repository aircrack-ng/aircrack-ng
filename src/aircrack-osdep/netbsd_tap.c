 /*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for NetBSD. TAP routines
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "osdep.h"

struct tip_nbsd {
	int		tn_fd;
	int		tn_ioctls;
	struct ifreq	tn_ifr;
	char		tn_name[MAX_IFACE_NAME];
	int		tn_destroy;
};

static int ti_do_open_nbsd(struct tif *ti, char *name)
{
	int fd;
	char *iface = "/dev/tap";
	struct stat st;
	struct tip_nbsd *priv = ti_priv(ti);
	int s;
	unsigned int flags;
	struct ifreq *ifr;

	/* open tap */
	if (name)
		iface = name;
	else
		priv->tn_destroy = 1; /* we create, we destroy */

	fd = open(iface, O_RDWR);
	if (fd == -1)
		return -1;

	/* get name */
	if(fstat(fd, &st) == -1)
		goto err;
	snprintf(priv->tn_name, sizeof(priv->tn_name)-1, "%s",
		 devname(st.st_rdev, S_IFCHR));

	/* bring iface up */
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		goto err;
	priv->tn_ioctls = s;

	/* get flags */
	ifr = &priv->tn_ifr;
	memset(ifr, 0, sizeof(*ifr));
	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name)-1, "%s", priv->tn_name);
	if (ioctl(s, SIOCGIFFLAGS, ifr) == -1)
		goto err2;
	flags = ifr->ifr_flags;

	/* set flags */
	flags |= IFF_UP;
	ifr->ifr_flags = flags & 0xffff;
	if (ioctl(s, SIOCSIFFLAGS, ifr) == -1)
		goto err2;

	return fd;
err:
	/* XXX destroy */
	close(fd);
	return -1;
err2:
	close(s);
	goto err;
}

static void ti_do_free(struct tif *ti)
{
	struct tip_nbsd *priv = ti_priv(ti);

	free(priv);
	free(ti);
}

static void ti_destroy(struct tip_nbsd *priv)
{
	ioctl(priv->tn_ioctls, SIOCIFDESTROY, &priv->tn_ifr);
}

static void ti_close_nbsd(struct tif *ti)
{
	struct tip_nbsd *priv = ti_priv(ti);

	if (priv->tn_destroy)
		ti_destroy(priv);

	close(priv->tn_fd);
	close(priv->tn_ioctls);
	ti_do_free(ti);
}

static char *ti_name_nbsd(struct tif *ti)
{
	struct tip_nbsd *priv = ti_priv(ti);

	return priv->tn_name;
}

static int ti_set_mtu_nbsd(struct tif *ti, int mtu)
{
	struct tip_nbsd *priv = ti_priv(ti);

	priv->tn_ifr.ifr_mtu = mtu;

	return ioctl(priv->tn_ioctls, SIOCSIFMTU, &priv->tn_ifr);
}

static int ti_set_mac_nbsd(struct tif *ti, unsigned char *mac)
{
	struct tip_nbsd *priv = ti_priv(ti);
	struct ifreq *ifr = &priv->tn_ifr;

	ifr->ifr_addr.sa_family = AF_LINK;
	ifr->ifr_addr.sa_len = 6;
	memcpy(ifr->ifr_addr.sa_data, mac, 6);

	return ioctl(priv->tn_ioctls, SIOCSIFADDR, ifr);
}

static int ti_set_ip_nbsd(struct tif *ti, struct in_addr *ip)
{
	struct tip_nbsd *priv = ti_priv(ti);
	struct ifaliasreq ifra;
	struct sockaddr_in *s_in;

	/* assume same size */
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, priv->tn_ifr.ifr_name, IFNAMSIZ);

	s_in = (struct sockaddr_in *) &ifra.ifra_addr;
	s_in->sin_family = PF_INET;
	s_in->sin_addr = *ip;
	s_in->sin_len = sizeof(*s_in);

	return ioctl(priv->tn_ioctls, SIOCAIFADDR, &ifra);
}

static int ti_fd_nbsd(struct tif *ti)
{
	struct tip_nbsd *priv = ti_priv(ti);

	return priv->tn_fd;
}

static int ti_read_nbsd(struct tif *ti, void *buf, int len)
{
	return read(ti_fd(ti), buf, len);
}

static int ti_write_nbsd(struct tif *ti, void *buf, int len)
{
	return write(ti_fd(ti), buf, len);
}

static struct tif *ti_open_nbsd(char *iface)
{
	struct tif *ti;
	struct tip_nbsd *priv;
	int fd;

	/* setup ti struct */
	ti = ti_alloc(sizeof(*priv));
	if (!ti)
		return NULL;
	ti->ti_name	= ti_name_nbsd;
	ti->ti_set_mtu	= ti_set_mtu_nbsd;
	ti->ti_close	= ti_close_nbsd;
	ti->ti_fd	= ti_fd_nbsd;
	ti->ti_read	= ti_read_nbsd;
	ti->ti_write	= ti_write_nbsd;
	ti->ti_set_mac	= ti_set_mac_nbsd;
	ti->ti_set_ip	= ti_set_ip_nbsd;

	/* setup iface */
	fd = ti_do_open_nbsd(ti, iface);
	if (fd == -1) {
		ti_do_free(ti);
		return NULL;
	}

	/* setup private state */
	priv = ti_priv(ti);
	priv->tn_fd = fd;

	return ti;
}

struct tif *ti_open(char *iface)
{
	return ti_open_nbsd(iface);
}
