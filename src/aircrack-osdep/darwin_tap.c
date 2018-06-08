 /*
  *  Copyright (c) 2009, Kyle Fuller <inbox@kylefuller.co.uk>, based upon 
  *  freebsd_tap.c by Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for Darwin. TAP routines
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

#define MAX_TAP_DEVS 16

struct tip_darwin {
    int        tf_fd;
    int        tf_ioctls;
    struct ifreq    tf_ifr;
    char        tf_name[MAX_IFACE_NAME];
    int        tf_destroy;
};

static int ti_do_open_darwin(struct tif *ti, char *name) {
    int fd = -1;
    char iface[12];
    struct stat st;
    struct tip_darwin *priv = ti_priv(ti);
    int s;
    unsigned int flags;
    struct ifreq *ifr;
    int i;

    /* open tap */
    if (name) {
        fd = open(name, O_RDWR);
    } else {
        priv->tf_destroy = 1; /* we create, we destroy */
        
        for (i = 0; i < MAX_TAP_DEVS; i++) {
            snprintf(iface, sizeof(iface), "/dev/tap%d", i);
            fd = open(iface, O_RDWR);
            
            if (fd != -1) {
                break;
            }
        }
    }
    
    if (fd == -1) {
        return -1;
    }
    
    /* get name */
    if(fstat(fd, &st) == -1)
        goto err;
    snprintf(priv->tf_name, sizeof(priv->tf_name)-1, "%s",
         devname(st.st_rdev, S_IFCHR));

    /* bring iface up */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s == -1)
        goto err;
    priv->tf_ioctls = s;

    /* get flags */
    ifr = &priv->tf_ifr;
    memset(ifr, 0, sizeof(*ifr));
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name)-1, "%s", priv->tf_name);
    if (ioctl(s, SIOCGIFFLAGS, ifr) == -1)
        goto err2;
    flags = (ifr->ifr_flags & 0xffff);

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

static void ti_do_free(struct tif *ti) {
    struct tip_darwin *priv = ti_priv(ti);

    free(priv);
    free(ti);
}

static void ti_destroy(struct tip_darwin *priv) {
    ioctl(priv->tf_ioctls, SIOCIFDESTROY, &priv->tf_ifr);
}

static void ti_close_darwin(struct tif *ti) {
    struct tip_darwin *priv = ti_priv(ti);

    if (priv->tf_destroy)
        ti_destroy(priv);

    close(priv->tf_fd);
    close(priv->tf_ioctls);
    ti_do_free(ti);
}

static char *ti_name_darwin(struct tif *ti) {
    struct tip_darwin *priv = ti_priv(ti);

    return priv->tf_name;
}

static int ti_set_mtu_darwin(struct tif *ti, int mtu) {
    struct tip_darwin *priv = ti_priv(ti);

    priv->tf_ifr.ifr_mtu = mtu;

    return ioctl(priv->tf_ioctls, SIOCSIFMTU, &priv->tf_ifr);
}

static int ti_set_mac_darwin(struct tif *ti, unsigned char *mac) {
    struct tip_darwin *priv = ti_priv(ti);
    struct ifreq *ifr = &priv->tf_ifr;

    ifr->ifr_addr.sa_family = AF_LINK;
    ifr->ifr_addr.sa_len = 6;
    memcpy(ifr->ifr_addr.sa_data, mac, 6);

    return ioctl(priv->tf_ioctls, SIOCSIFLLADDR, ifr);
}

static int ti_set_ip_darwin(struct tif *ti, struct in_addr *ip) {
    struct tip_darwin *priv = ti_priv(ti);
    struct ifaliasreq ifra;
    struct sockaddr_in *s_in;

    /* assume same size */
    memset(&ifra, 0, sizeof(ifra));
    strcpy(ifra.ifra_name, priv->tf_ifr.ifr_name);

    s_in = (struct sockaddr_in *) &ifra.ifra_addr;
    s_in->sin_family = PF_INET;
    s_in->sin_addr = *ip;
    s_in->sin_len = sizeof(*s_in);

    return ioctl(priv->tf_ioctls, SIOCAIFADDR, &ifra);
}

static int ti_fd_darwin(struct tif *ti) {
    struct tip_darwin *priv = ti_priv(ti);

    return priv->tf_fd;
}

static int ti_read_darwin(struct tif *ti, void *buf, int len) {
    return read(ti_fd(ti), buf, len);
}

static int ti_write_darwin(struct tif *ti, void *buf, int len) {
    return write(ti_fd(ti), buf, len);
}

static struct tif *ti_open_darwin(char *iface) {
    struct tif *ti;
    struct tip_darwin *priv;
    int fd;

    /* setup ti struct */
    ti = ti_alloc(sizeof(*priv));
    if (!ti)
        return NULL;
    ti->ti_name    = ti_name_darwin;
    ti->ti_set_mtu    = ti_set_mtu_darwin;
    ti->ti_close    = ti_close_darwin;
    ti->ti_fd    = ti_fd_darwin;
    ti->ti_read    = ti_read_darwin;
    ti->ti_write    = ti_write_darwin;
    ti->ti_set_mac    = ti_set_mac_darwin;
    ti->ti_set_ip    = ti_set_ip_darwin;

    /* setup iface */
    fd = ti_do_open_darwin(ti, iface);
    if (fd == -1) {
        ti_do_free(ti);
        return NULL;
    }

    /* setup private state */
    priv = ti_priv(ti);
    priv->tf_fd = fd;

    return ti;
}

struct tif *ti_open(char *iface) {
    return ti_open_darwin(iface);
}
