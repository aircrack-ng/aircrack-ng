 /*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for Linux. TAP routines
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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "osdep.h"

struct tip_linux {
	int		tl_fd;
	struct ifreq	tl_ifr;
	int		tl_ioctls;
	char		tl_name[MAX_IFACE_NAME];
};

static int ti_do_open_linux(struct tif *ti, char *name)
{
    int fd_tap;
    struct ifreq if_request;
    struct tip_linux *priv = ti_priv(ti);

    fd_tap = open( name ? name : "/dev/net/tun", O_RDWR );
    if(fd_tap < 0 )
    {
        printf( "error opening tap device: %s\n", strerror( errno ) );
        printf( "try \"modprobe tun\"\n");
        return -1;
    }

    memset( &if_request, 0, sizeof( if_request ) );
    if_request.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy( if_request.ifr_name, "at%d", IFNAMSIZ );
    if( ioctl( fd_tap, TUNSETIFF, (void *)&if_request ) < 0 )
    {
        printf( "error creating tap interface: %s\n", strerror( errno ) );
        close( fd_tap );
        return -1;
    }

    strncpy( priv->tl_name, if_request.ifr_name, MAX_IFACE_NAME );
    strncpy(priv->tl_ifr.ifr_name, priv->tl_name,
    	    sizeof(priv->tl_ifr.ifr_name) - 1);

    if ((priv->tl_ioctls = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        priv->tl_ioctls = 0;
    	close(fd_tap);
	return -1;
    }

    return fd_tap;
}

static void ti_do_free(struct tif *ti)
{
	struct tip_fbsd *priv = ti_priv(ti);

	free(priv);
	free(ti);
}

static void ti_close_linux(struct tif *ti)
{
	struct tip_linux *priv = ti_priv(ti);

	close(priv->tl_fd);
	close(priv->tl_ioctls);
	ti_do_free(ti);
}

static char *ti_name_linux(struct tif *ti)
{
	struct tip_linux *priv = ti_priv(ti);

	return priv->tl_name;
}

static int ti_set_mtu_linux(struct tif *ti, int mtu)
{
	struct tip_linux *priv = ti_priv(ti);

	priv->tl_ifr.ifr_mtu = mtu;

	return ioctl(priv->tl_ioctls, SIOCSIFMTU, &priv->tl_ifr);
}

static int ti_get_mtu_linux(struct tif *ti)
{
	int mtu;
	struct tip_linux *priv = ti_priv(ti);

	if (ioctl(priv->tl_ioctls, SIOCSIFMTU, &priv->tl_ifr) != -1){
		mtu = priv->tl_ifr.ifr_mtu;
	}
	else{
		mtu = 1500;	
	}
	
	return mtu;
}

static int ti_set_mac_linux(struct tif *ti, unsigned char *mac)
{
	struct tip_linux *priv = ti_priv(ti);

        memcpy(priv->tl_ifr.ifr_hwaddr.sa_data, mac, 6);
	priv->tl_ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

	return ioctl(priv->tl_ioctls, SIOCSIFHWADDR, &priv->tl_ifr);
}

static int ti_set_ip_linux(struct tif *ti, struct in_addr *ip)
{
        struct tip_linux *priv = ti_priv(ti);
        struct sockaddr_in *s_in;

        s_in = (struct sockaddr_in*) &priv->tl_ifr.ifr_addr;
        s_in->sin_family = AF_INET;
        s_in->sin_addr = *ip;

        return ioctl(priv->tl_ioctls, SIOCSIFADDR, &priv->tl_ifr);
}

static int ti_fd_linux(struct tif *ti)
{
	struct tip_linux *priv = ti_priv(ti);

	return priv->tl_fd;
}

static int ti_read_linux(struct tif *ti, void *buf, int len)
{
	return read(ti_fd(ti), buf, len);
}

static int ti_write_linux(struct tif *ti, void *buf, int len)
{
	return write(ti_fd(ti), buf, len);
}

static struct tif *ti_open_linux(char *iface)
{
	struct tif *ti;
	struct tip_linux *priv;
	int fd;

	/* setup ti struct */
	ti = ti_alloc(sizeof(*priv));
	if (!ti)
		return NULL;
	ti->ti_name	= ti_name_linux;
	ti->ti_set_mtu	= ti_set_mtu_linux;
	ti->ti_get_mtu	= ti_get_mtu_linux;
	ti->ti_close	= ti_close_linux;
	ti->ti_fd	= ti_fd_linux;
	ti->ti_read	= ti_read_linux;
	ti->ti_write	= ti_write_linux;
	ti->ti_set_mac	= ti_set_mac_linux;
	ti->ti_set_ip	= ti_set_ip_linux;

	/* setup iface */
	fd = ti_do_open_linux(ti, iface);
	if (fd == -1) {
		ti_do_free(ti);
		return NULL;
	}

	/* setup private state */
	priv = ti_priv(ti);
	priv->tl_fd = fd;

	return ti;
}

struct tif *ti_open(char *iface)
{
	return ti_open_linux(iface);
}
