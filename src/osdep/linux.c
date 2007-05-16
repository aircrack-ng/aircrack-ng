/*
 *  OS dependent APIs for Linux
 *
 *  Copyright (C) 2006,2007 Thomas d'Otreppe
 *  Copyright (C) 2004,2005 Christophe Devine
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
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>

#include "osdep.h"
#include "pcap.h"

#define uchar unsigned char

/*
 * XXX need to have a different read/write/open function for each Linux driver.
 */

struct priv_linux {
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
    int is_madwifing;
    int is_bcm43xx;
    int is_orinoco;
    int is_zd1211rw;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;

    int sysfs_inject;
    int channel;
    char *wlanctlng; /* XXX never set */
    char *iwpriv;
    char *iwconfig;
    char *wl;
    char *main_if;
    unsigned char pl_mac[6];
    int inject_wlanng;
};

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef NULL_MAC
#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#endif

//Check if the driver is ndiswrapper */
static int is_ndiswrapper(const char * iface, const char * path)
{
        int n,pid;
        if ((pid=fork())==0)
        {
                close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
                execl(path, "iwpriv",iface, "ndis_reset", NULL);
                exit( 1 );
        }

        waitpid( pid, &n, 0 );
        return ( ( WIFEXITED(n) && WEXITSTATUS(n) == 0 ));
}

/* Search a file recursively */
static char * searchInside(const char * dir, const char * filename)
{
        char * ret;
        char * curfile;
        struct stat sb;
        int len, lentot;
        DIR *dp;
        struct dirent *ep;

        len = strlen(filename);
        lentot = strlen(dir) + 256 + 2;
        curfile = (char *)calloc(1, lentot);
        dp = opendir(dir);
        if (dp == NULL)
                return NULL;
        while ((ep = readdir(dp)) != NULL)
        {

                memset(curfile, 0, lentot);
                sprintf(curfile, "%s/%s", dir, ep->d_name);

                //Checking if it's the good file
                if ((int)strlen( ep->d_name) == len && !strcmp(ep->d_name, filename))
                {
                        (void)closedir(dp);
                        return curfile;
                }
                lstat(curfile, &sb);

                //If it's a directory and not a link, try to go inside to search
                if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
                {
                        //Check if the directory isn't "." or ".."
                        if (strcmp(".", ep->d_name) && strcmp("..", ep->d_name))
                        {
                                //Recursive call
                                ret = searchInside(curfile, filename);
                                if (ret != NULL)
                                {
                                        (void)closedir(dp);
                                        return ret;
                                }
                        }
                }
        }
        (void)closedir(dp);
        return NULL;
}

/* Search a wireless tool and return its path */
static char * wiToolsPath(const char * tool)
{
        char * path;
        int i, nbelems;
        static const char * paths [] = {
                "/sbin",
                "/usr/sbin",
                "/usr/local/sbin",
                "/bin",
                "/usr/bin",
                "/usr/local/bin",
                "/tmp"
        };

        nbelems = sizeof(paths) / sizeof(char *);

        for (i = 0; i < nbelems; i++)
        {
                path = searchInside(paths[i], tool);
                if (path != NULL)
                        return path;
        }

        return NULL;
}

static int linux_get_channel(struct wif *wi)
{
    struct priv_linux *dev = wi_priv(wi);
    struct iwreq wrq;

    memset( &wrq, 0, sizeof( struct iwreq ) );

    if(dev->main_if)
        strncpy( wrq.ifr_name, dev->main_if, IFNAMSIZ );
    else
        strncpy( wrq.ifr_name, wi_get_ifname(wi), IFNAMSIZ );

    if( ioctl( dev->fd_in, SIOCGIWFREQ, &wrq ) < 0 )
    {
        return( -1 );
    }

    if(wrq.u.freq.m > 1000)
        return ((wrq.u.freq.m - 241200000)/500000)+1;

    return wrq.u.freq.m;
}

static int linux_read(struct wif *wi, unsigned char *buf, int count,
		      struct rx_info *ri)
{
    struct priv_linux *dev = wi_priv(wi);
    unsigned char tmpbuf[4096];

    int caplen, n = 0;

    if((unsigned)count > sizeof(tmpbuf))
        return( -1 );

    if( ( caplen = read( dev->fd_in, tmpbuf, count ) ) < 0 )
    {
        if( errno == EAGAIN )
            return( 0 );

        perror( "read failed" );
        return( -1 );
    }

    if( dev->is_madwifi && !(dev->is_madwifing) )
        caplen -= 4;    /* remove the FCS */

    memset( buf, 0, sizeof( buf ) );

    /* XXX */
    if (ri)
    	memset(ri, 0, sizeof(*ri));

    if( dev->arptype_in == ARPHRD_IEEE80211_PRISM )
    {
        /* skip the prism header */
        if( tmpbuf[7] == 0x40 )
        {
            /* prism54 uses a different format */
            if(ri)
                ri->ri_power = tmpbuf[0x33];

            n = 0x40;
        }
        else
        {
            if(ri)
            {
                ri->ri_power = *(int *)( tmpbuf + 0x5C );

//                if( ! memcmp( iface[i], "ath", 3 ) )
                if( dev->is_madwifi )
                    ri->ri_power -= *(int *)( tmpbuf + 0x68 );
            }

            n = *(int *)( tmpbuf + 4 );
        }

        if( n < 8 || n >= caplen )
            return( 0 );
    }

    if( dev->arptype_in == ARPHRD_IEEE80211_FULL )
    {
        if( tmpbuf[0] != 0 )
            return 0;
        /* skip the radiotap header */

        n = *(unsigned short *)( tmpbuf + 2 );

        if(ri)
        {
            /* ipw2200 1.0.7 */
            if( *(int *)( tmpbuf + 4 ) == 0x0000082E )
                ri->ri_power = tmpbuf[14];

            /* ipw2200 1.2.0 */
            if( *(int *)( tmpbuf + 4 ) == 0x0000086F )
                ri->ri_power = tmpbuf[15];

            /* zd1211rw-patched */
            if(dev->is_zd1211rw && *(int *)( tmpbuf + 4 ) == 0x0000006E )
                ri->ri_power = tmpbuf[14];
        }

        if( n <= 0 || n >= caplen )
            return( 0 );
    }

    caplen -= n;

    memcpy( buf, tmpbuf + n, caplen );

    if(ri)
        ri->ri_channel = wi_get_channel(wi);

    return( caplen );
}

static int linux_write(struct wif *wi, unsigned char *buf, int count,
		       struct tx_info *ti)
{
    struct priv_linux *dev = wi_priv(wi);
    unsigned char maddr[6];
    int ret;
    unsigned char tmpbuf[4096];

    if((unsigned) count > sizeof(tmpbuf)-22) return -1;

    /* XXX honor ti */
    if (ti) {}

    if( dev->is_wlanng && count >= 24 )
    {
		/* Wlan-ng isn't able to inject on kernel > 2.6.11 */
		if( dev->inject_wlanng == 0 )
		{
			perror( "write failed" );
			return( -1 );
		}

		if (count >= 24)
		{
			/* for some reason, wlan-ng requires a special header */

			if( ( ((unsigned char *) buf)[1] & 3 ) != 3 )
			{
				memcpy( tmpbuf, buf, 24 );
				memset( tmpbuf + 24, 0, 22 );

				tmpbuf[30] = ( count - 24 ) & 0xFF;
				tmpbuf[31] = ( count - 24 ) >> 8;

				memcpy( tmpbuf + 46, buf + 24, count - 24 );

				count += 22;
			}
			else
			{
				memcpy( tmpbuf, buf, 30 );
				memset( tmpbuf + 30, 0, 16 );

				tmpbuf[30] = ( count - 30 ) & 0xFF;
				tmpbuf[31] = ( count - 30 ) >> 8;

				memcpy( tmpbuf + 46, buf + 30, count - 30 );

				count += 16;
			}

			buf = tmpbuf;
		}
    }

    if( ( dev->is_wlanng || dev->is_hostap ) &&
        ( ((uchar *) buf)[1] & 3 ) == 2 )
    {
        /* Prism2 firmware swaps the dmac and smac in FromDS packets */

        memcpy( maddr, buf + 4, 6 );
        memcpy( buf + 4, buf + 16, 6 );
        memcpy( buf + 16, maddr, 6 );
    }

    ret = write( dev->fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    return( ret );
}

static int linux_set_channel(struct wif *wi, int channel)
{
    struct priv_linux *dev = wi_priv(wi);
    char s[32];
    int pid, status;
    struct iwreq wrq;

    memset( s, 0, sizeof( s ) );

    if( dev->is_wlanng)
    {
        snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( dev->wlanctlng, "wlanctl-ng", wi_get_ifname(wi),
                    "lnxreq_wlansniff", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );

        if( WIFEXITED(status) )
        {
            dev->channel=channel;
            return( WEXITSTATUS(status) );
        }
        else
            return( 1 );
    }

    if( dev->is_orinoco)
    {
        snprintf( s,  sizeof( s ) - 1, "%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execlp( dev->iwpriv, "iwpriv", wi_get_ifname(wi),
                    "monitor", "1", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );
        dev->channel = channel;
        return 0;
    }

    if( dev->is_zd1211rw)
    {
        snprintf( s,  sizeof( s ) - 1, "%d", channel );

        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execlp(dev->iwconfig, "iwconfig", wi_get_ifname(wi),
                    "channel", s, NULL );
            exit( 1 );
        }

        waitpid( pid, &status, 0 );
        dev->channel = channel;
        return 0;
    }

    memset( &wrq, 0, sizeof( struct iwreq ) );
    strncpy( wrq.ifr_name, wi_get_ifname(wi), IFNAMSIZ );
    wrq.u.freq.m = (double) channel;
    wrq.u.freq.e = (double) 0;

    if( ioctl( dev->fd_in, SIOCSIWFREQ, &wrq ) < 0 )
    {
        usleep( 10000 ); /* madwifi needs a second chance */

        if( ioctl( dev->fd_in, SIOCSIWFREQ, &wrq ) < 0 )
        {
/*          perror( "ioctl(SIOCSIWFREQ) failed" ); */
            return( 1 );
        }
    }

    dev->channel = channel;

    return( 0 );
}

static int opensysfs(struct priv_linux *dev, char *iface, int fd) {
    int fd2;
    char buf[256];

    snprintf(buf, 256, "/sys/class/net/%s/device/inject", iface);
    fd2 = open(buf, O_WRONLY);
    if (fd2 == -1)
        return -1;

    dup2(fd2, fd);
    close(fd2);

    dev->sysfs_inject=1;
    return 0;
}

int set_monitor( struct priv_linux *dev, char *iface, int fd )
{
    int pid, status;
    struct iwreq wrq;

    if( strcmp(iface,"prism0") == 0 )
    {
        dev->wl = wiToolsPath("wl");
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execl( dev->wl, "wl", "monitor", "1", NULL);
            exit( 1 );
        }
        waitpid( pid, &status, 0 );
        if( WIFEXITED(status) )
            return( WEXITSTATUS(status) );
        return( 1 );
    }
    else if (strncmp(iface, "rtap", 4) == 0 )
    {
        return 0;
    }
    else
    {
        if( dev->is_wlanng )
        {
//            snprintf( s,  sizeof( s ) - 1, "channel=%d", channel );
            if( ( pid = fork() ) == 0 )
            {
                close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
                execl( dev->wlanctlng, "wlanctl-ng", iface,
                        "lnxreq_wlansniff", "enable=true",
                        "prismheader=true", "wlanheader=false",
                        "stripfcs=true", "keepwepflags=true",
                        "6", NULL );
                exit( 1 );
            }

            waitpid( pid, &status, 0 );

            if( WIFEXITED(status) )
                return( WEXITSTATUS(status) );
            return( 1 );
        }

        memset( &wrq, 0, sizeof( struct iwreq ) );
        strncpy( wrq.ifr_name, iface, IFNAMSIZ );
        wrq.u.mode = IW_MODE_MONITOR;

        if( ioctl( fd, SIOCSIWMODE, &wrq ) < 0 )
        {
            perror( "ioctl(SIOCSIWMODE) failed" );
            return( 1 );
        }

    }

    /* couple of iwprivs to enable the prism header */

    if( ! fork() )  /* hostap */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "monitor_type", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* r8180 */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    if( ! fork() )  /* prism54 */
    {
        close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
        execlp( "iwpriv", "iwpriv", iface, "set_prismhdr", "1", NULL );
        exit( 1 );
    }
    wait( NULL );

    return( 0 );
}


static int openraw(struct priv_linux *dev, char *iface, int fd, int *arptype,
		   uchar *mac)
{
    struct ifreq ifr;
    struct packet_mreq mr;
    struct sockaddr_ll sll;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if( dev->is_wlanng )
        sll.sll_protocol = htons( ETH_P_80211_RAW );
    else
        sll.sll_protocol = htons( ETH_P_ALL );

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL)
    {
        if (set_monitor( dev, iface, fd ))
        {
            printf("Error setting monitor mode on %s\n",iface);
            return( 1 );
        }
    }

    /* Is interface st to up, broadcast & running ? */
    if((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING) != ifr.ifr_flags)
    {
        /* Bring interface up*/
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
        {
            perror( "ioctl(SIOCSIFFLAGS) failed" );
            return( 1 );
        }
    }

    /* bind the raw socket to the interface */

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        printf("Interface %s: \n", iface);
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    memcpy( mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

    *arptype = ifr.ifr_hwaddr.sa_family;

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL )
    {
                /* try sysfs instead (ipw2200) */
                if (opensysfs(dev, iface, fd) == 0)
            return 0;

        if( ifr.ifr_hwaddr.sa_family == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     ifr.ifr_hwaddr.sa_family );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\nSysfs injection support was not "
                         "found either.\n\n", iface, iface );
        return( 1 );
    }

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}

/*
 * Open the interface and set mode monitor
 * Return 1 on failure and 0 on success
 */
static int do_linux_open(struct wif *wi, char *iface)
{
	int kver;
	struct utsname checklinuxversion;
    struct priv_linux *dev = wi_priv(wi);
    char *iwpriv;
    char strbuf[512];
    FILE *f;
    char athXraw[] = "athXraw";
    pid_t pid;
    int n;
    DIR *net_ifaces;
    struct dirent *this_iface;
    FILE *acpi;
    char r_file[128], buf[128];

    dev->inject_wlanng = 1;

    /* open raw socks */
    if( ( dev->fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

        /* Check iwpriv existence */

    iwpriv = wiToolsPath("iwpriv");
    dev->iwpriv = iwpriv;
    dev->iwconfig = wiToolsPath("iwconfig");

    if (! iwpriv )
    {
        fprintf(stderr, "Can't find wireless tools, exiting.\n");
        goto close_in;
    }

    /* Exit if ndiswrapper : check iwpriv ndis_reset */

    if ( is_ndiswrapper(iface, iwpriv ) )
    {
		fprintf(stderr, "Ndiswrapper doesn't support monitor mode.\n");
		goto close_in;
    }

    if( ( dev->fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        goto close_in;
    }
    /* figure out device type */

    /* check if wlan-ng or hostap or r8180 */
    if( strlen(iface) == 5 &&
        memcmp(iface, "wlan", 4 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "wlancfg show %s 2>/dev/null | "
                  "grep p2CnfWEPFlags >/dev/null",
                  iface);

        if( system( strbuf ) == 0 )
        {
			if (uname( & checklinuxversion ) >= 0)
			{
				/* uname succeeded */
				if (strncmp(checklinuxversion.release, "2.6.", 4) == 0
					&& strncasecmp(checklinuxversion.sysname, "linux", 5) == 0)
				{
					/* Linux kernel 2.6 */
					kver = atoi(checklinuxversion.release + 4);

					if (kver > 11)
					{
						/* That's a kernel > 2.6.11, cannot inject */
						dev->inject_wlanng = 0;
					}
				}
			}
            dev->is_wlanng = 1;
		}

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep antsel_rx >/dev/null",
                  iface);

        if( system( strbuf ) == 0 )
            dev->is_hostap = 1;
    }

    /* enable injection on ralink */

    if( strcmp( iface, "ra0" ) == 0 ||
        strcmp( iface, "ra1" ) == 0 ||
        strcmp( iface, "rausb0" ) == 0 ||
        strcmp( iface, "rausb1" ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s rfmontx 1 >/dev/null 2>/dev/null",
                  iface );
        system( strbuf );
    }

    /* check if newer athXraw interface available */

    if( ( strlen( iface ) == 4 || strlen( iface ) == 5 )
        && memcmp( iface, "ath", 3 ) == 0 )
    {
        dev->is_madwifi = 1;
        memset( strbuf, 0, sizeof( strbuf ) );

        snprintf(strbuf, sizeof( strbuf ) -1,
                  "/proc/sys/net/%s/%%parent", iface);

        f = fopen(strbuf, "r");

        if (f != NULL)
        {
            // It is madwifi-ng
            dev->is_madwifing = 1;
            fclose( f );

            /* should we force prism2 header? */

            sprintf((char *) strbuf, "/proc/sys/net/%s/dev_type", iface);
            f = fopen( (char *) strbuf,"w");
            if (f != NULL) {
                fprintf(f, "802\n");
                fclose(f);
            }

            /* Force prism2 header on madwifi-ng */
        }
        else
        {
            // Madwifi-old
            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "sysctl -w dev.%s.rawdev=1 >/dev/null 2>/dev/null",
                      iface );

            if( system( strbuf ) == 0 )
            {

                athXraw[3] = iface[3];

                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                          "ifconfig %s up", athXraw );
                system( strbuf );

#if 0 /* some people reported problems when prismheader is enabled */
                memset( strbuf, 0, sizeof( strbuf ) );
                snprintf( strbuf,  sizeof( strbuf ) - 1,
                         "sysctl -w dev.%s.rawdev_type=1 >/dev/null 2>/dev/null",
                         iface );
                system( strbuf );
#endif

                iface = athXraw;
            }
        }
    }

    /* open the replay interface */
    dev->is_madwifi = ( memcmp(iface, "ath", 3 ) == 0 );

    /* test if orinoco */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_port3", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            dev->is_orinoco = 1;
    }

    /* test if zd1211rw */

    if( memcmp( iface, "eth", 3 ) == 0 )
    {
        if( ( pid = fork() ) == 0 )
        {
            close( 0 ); close( 1 ); close( 2 ); chdir( "/" );
            execlp( "iwpriv", "iwpriv", iface, "get_regdomain", NULL );
            exit( 1 );
        }

        waitpid( pid, &n, 0 );

        if( WIFEXITED(n) && WEXITSTATUS(n) == 0 )
            dev->is_zd1211rw = 1;
    }

    /* test if rtap interface and try to find real interface */
    if( memcmp( iface, "rtap", 4) == 0 )
    {
        net_ifaces = opendir("/sys/class/net");
        if ( net_ifaces != NULL )
        {
            while (net_ifaces != NULL && ((this_iface = readdir(net_ifaces)) != NULL))
            {
                if (this_iface->d_name[0] == '.')
                    continue;

                snprintf(r_file, sizeof(r_file),
                    "/sys/class/net/%s/device/rtap_iface", this_iface->d_name);
                if ((acpi = fopen(r_file, "r")) == NULL)
                    continue;
                if (acpi != NULL)
                {
                    fgets(buf, 128, acpi);
                    if (strncmp(buf, iface, 5) == 0)
                    {
                        fclose(acpi);
                        if (net_ifaces != NULL)
                        {
                            closedir(net_ifaces);
                            net_ifaces = NULL;
                        }
                        dev->main_if = (char*) malloc(strlen(this_iface->d_name)+1);
                        strcpy(dev->main_if, this_iface->d_name);
                        break;
                    }
                    fclose(acpi);
                }
            }
            if (net_ifaces != NULL)
                closedir(net_ifaces);
        }
    }

    if (openraw(dev, iface, dev->fd_out, &dev->arptype_out, dev->pl_mac) != 0) {
		goto close_out;
    }

    dev->fd_in = dev->fd_out;
    dev->arptype_in = dev->arptype_out;

    return 0;
close_in:
    close(dev->fd_in);
    return 1;
close_out:
    close(dev->fd_out);
    goto close_in;
}

static void do_free(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	if(pl->main_if)
            free(pl->main_if);
	free(pl);
	free(wi);
}

static void linux_close(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	if (pl->fd_in)
		close(pl->fd_in);
	if (pl->fd_out)
		close(pl->fd_out);

	do_free(wi);
}

static int linux_fd(struct wif *wi)
{
	struct priv_linux *pl = wi_priv(wi);

	return pl->fd_in;
}

static int linux_get_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_linux *pl = wi_priv(wi);
	struct ifreq ifr;
	int fd;

	fd = wi_fd(wi);
	/* find the interface index */

	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

	if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFINDEX) failed" );
		return( 1 );
	}


	if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFHWADDR) failed" );
		return( 1 );
	}

	memcpy( pl->pl_mac, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

	/* XXX */
	memcpy(mac, pl->pl_mac, 6);
	return 0;
}

static int linux_set_mac(struct wif *wi, unsigned char *mac)
{
	struct priv_linux *pl = wi_priv(wi);
	struct ifreq ifr;
	int fd, ret;

	fd = wi_fd(wi);
	/* find the interface index */

	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, wi_get_ifname(wi), sizeof( ifr.ifr_name ) - 1 );

	if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
	{
		printf("Interface %s: \n", wi_get_ifname(wi));
		perror( "ioctl(SIOCGIFINDEX) failed" );
		return( 1 );
	}

// 	ifr.ifr_hwaddr.sa_family = LINKTYPE_ETHERNET;
//	ifr.ifr_hwaddr.sa_len = 6;
	memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
	memcpy(pl->pl_mac, mac, 6);

        //if down
//         ifr.ifr_flags &= ~IFF_UP;
//
//         if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
//         {
//             perror( "ioctl(SIOCSIFFLAGS) failed" );
//             return( 1 );
//         }

        //set mac
	ret = ioctl(wi_fd(wi), SIOCSIFHWADDR, ifr);

        //if up
//         ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;
//
//         if( ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 )
//         {
//             perror( "ioctl(SIOCSIFFLAGS) failed" );
//             return( 1 );
//         }
        return ret;
}

static struct wif *linux_open(char *iface)
{
	struct wif *wi;
	struct priv_linux *pl;

	wi = wi_alloc(sizeof(*pl));
	if (!wi)
		return NULL;
        wi->wi_read             = linux_read;
        wi->wi_write            = linux_write;
        wi->wi_set_channel      = linux_set_channel;
        wi->wi_get_channel      = linux_get_channel;
        wi->wi_close            = linux_close;
	wi->wi_fd		= linux_fd;
	wi->wi_get_mac		= linux_get_mac;
	wi->wi_set_mac		= linux_set_mac;

	if (do_linux_open(wi, iface)) {
		do_free(wi);
		return NULL;
	}

	return wi;
}

struct wif *wi_open_osdep(char *iface)
{
        return linux_open(iface);
}

int get_battery_state(void)
{
    char buf[128];
    int batteryTime = 0;
    FILE *apm;
    int flag;
    char units[32];
    int ret;
    static int linux_apm = 1;
    static int linux_acpi = 1;

    if (linux_apm == 1)
    {
        if ((apm = fopen("/proc/apm", "r")) != NULL ) {
            if ( fgets(buf, 128,apm) != NULL ) {
                int charging, ac;
                fclose(apm);

                ret = sscanf(buf, "%*s %*d.%*d %*x %x %x %x %*d%% %d %s\n", &ac,
                                                        &charging, &flag, &batteryTime, units);

                                if(!ret) return 0;

                if ((flag & 0x80) == 0 && charging != 0xFF && ac != 1 && batteryTime != -1) {
                    if (!strncmp(units, "min", 32))
                        batteryTime *= 60;
                }
                else return 0;
                linux_acpi = 0;
                return batteryTime;
            }
        }
        linux_apm = 0;
    }
    if (linux_acpi && !linux_apm)
    {
        DIR *batteries, *ac_adapters;
        struct dirent *this_battery, *this_adapter;
        FILE *acpi, *info;
        char battery_state[128];
        char battery_info[128];
        int rate = 1, remain = 0, current = 0;
        static int total_remain = 0, total_cap = 0;
        int batno = 0;
        static int info_timer = 0;
        int batt_full_capacity[3];
        linux_apm=0;
        linux_acpi=1;
        ac_adapters = opendir("/proc/acpi/ac_adapter");
        if ( ac_adapters == NULL )
            return 0;

        while (ac_adapters != NULL && ((this_adapter = readdir(ac_adapters)) != NULL)) {
            if (this_adapter->d_name[0] == '.')
                continue;
            /* safe overloaded use of battery_state path var */
            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/ac_adapter/%s/state", this_adapter->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            if (acpi != NULL) {
                while(fgets(buf, 128, acpi)) {
                    if (strstr(buf, "on-line") != NULL) {
                        fclose(acpi);
                        if (ac_adapters != NULL)
                            closedir(ac_adapters);
                        return 0;
                    }
                }
                fclose(acpi);
            }
        }
        if (ac_adapters != NULL)
            closedir(ac_adapters);

        batteries = opendir("/proc/acpi/battery");

        if (batteries == NULL) {
            closedir(batteries);
            return 0;
        }

        while (batteries != NULL && ((this_battery = readdir(batteries)) != NULL)) {
            if (this_battery->d_name[0] == '.')
                continue;

            snprintf(battery_info, sizeof(battery_info), "/proc/acpi/battery/%s/info", this_battery->d_name);
            info = fopen(battery_info, "r");
            batt_full_capacity[batno] = 0;
            if ( info != NULL ) {
                while (fgets(buf, sizeof(buf), info) != NULL)
                    if (sscanf(buf, "last full capacity:      %d mWh", &batt_full_capacity[batno]) == 1)
                        continue;
                fclose(info);
            }


            snprintf(battery_state, sizeof(battery_state),
                "/proc/acpi/battery/%s/state", this_battery->d_name);
            if ((acpi = fopen(battery_state, "r")) == NULL)
                continue;
            while (fgets(buf, 128, acpi)) {
                if (strncmp(buf, "present:", 8 ) == 0) {
                                /* No information for this battery */
                    if (strstr(buf, "no" ))
                        continue;
                }
                else if (strncmp(buf, "charging state:", 15) == 0) {
                                /* the space makes it different than discharging */
                    if (strstr(buf, " charging" )) {
                        fclose( acpi );
                        return 0;
                    }
                }
                else if (strncmp(buf, "present rate:", 13) == 0)
                    rate = atoi(buf + 25);
                else if (strncmp(buf, "remaining capacity:", 19) == 0) {
                    remain = atoi(buf + 25);
                    total_remain += remain;
                }
                else if (strncmp(buf, "present voltage:", 17) == 0)
                    current = atoi(buf + 25);
            }
            total_cap += batt_full_capacity[batno];
            fclose(acpi);
            batteryTime += (int) (( ((float)remain) /rate ) * 3600);
            batno++;
        }
        info_timer++;

        if (batteries != NULL)
            closedir(batteries);
    }
    return batteryTime;
}
