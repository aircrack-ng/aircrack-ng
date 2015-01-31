  /*
   *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
   *
   *  OS dependent API for cygwin. TAP routines
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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "osdep.h"

#include <windows.h>
#include <winioctl.h>
#include <ipexport.h>
#include <iptypes.h>
#include <setupapi.h>
#include <devguid.h>

#include "network.h"
#include "tap-win32/common.h"

extern DWORD WINAPI GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo,PULONG pOutBufLen);
extern DWORD WINAPI AddIPAddress(IPAddr Address,IPMask IpMask,DWORD IfIndex,PULONG NTEContext,PULONG NTEInstance);
extern DWORD WINAPI DeleteIPAddress(ULONG NTEContext);

extern int cygwin_read_reader(int fd, int plen, void *dst, int len);
static void *ti_reader(void *arg);

struct tip_cygwin {
	char		tc_name[MAX_IFACE_NAME];
	HANDLE		tc_h;
	pthread_t	tc_reader;
	volatile int	tc_running;
	int		tc_pipe[2]; /* reader -> parent */
	pthread_mutex_t	tc_mtx;
	HKEY		tc_key;
	char		tc_guid[256];
};

/**
 * Stop the reader thread (if it is running)
 * @return 0 if stopped or -1 if it failed to stop it
 */
static int stop_reader(struct tip_cygwin *priv)
{
	if (priv->tc_running == 1) {
		int tries = 3;

		priv->tc_running = 0;
		while ((priv->tc_running != -1) && tries--)
			sleep(1);

		if (tries <= 0)
			return -1;
	}

	return 0;
}

/**
 * Start reader thread
 * @return -1 if failed to start thread or 0 if it is successful
 */
static int start_reader(struct tip_cygwin *priv)
{
	priv->tc_running = 2;
	if (pthread_create(&priv->tc_reader, NULL, ti_reader, priv))
		return -1;

	priv->tc_running = 1;

	return 0;
}

/**
 * Change status (enable/disable) of the device
 */
static int ti_media_status(struct tip_cygwin *priv, int on)
{
	ULONG s = on;
	DWORD len;

	if (!DeviceIoControl(priv->tc_h, TAP_IOCTL_SET_MEDIA_STATUS, &s,
			     sizeof(s), &s, sizeof(s), &len, NULL))
		return -1;

	return 0;
}

/**
 * Try opening device
 */
static int ti_try_open(struct tip_cygwin *priv, char *guid)
{
	int any = priv->tc_guid[0] == 0;
	char device[256];
	HANDLE h;

	if (!any && strcmp(priv->tc_guid, guid) != 0)
		return 0;

	/* open the device */
	snprintf(device, sizeof(device), "%s%s%s",
		 USERMODEDEVICEDIR, guid, TAPSUFFIX);
	h = CreateFile(device, GENERIC_READ | GENERIC_WRITE, 0, 0,
		       OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM
		       | FILE_FLAG_OVERLAPPED, 0);
	if (h == INVALID_HANDLE_VALUE) {
		if (any)
			return 0;
		else
			return -1;
	}
	priv->tc_h = h;

	/* XXX check tap version */

	/* bring iface up */
	if (ti_media_status(priv, 1) == -1)
		return -1;

	/* XXX grab printable name */
	snprintf(priv->tc_name, sizeof(priv->tc_name)-1, "%s", guid);

	if (any)
		snprintf(priv->tc_guid, sizeof(priv->tc_guid), "%s", guid);

	return 1;
}

/**
 * Read registry value
 * @param key Registry key
 * @return 0 if successful, -1 if it failed
 */
static int ti_read_reg(struct tip_cygwin *priv, char *key, char *res, int len)
{
	DWORD dt, l = len;

	if (RegQueryValueEx(priv->tc_key, key, NULL, &dt,
	    (unsigned char*) res, &l) != ERROR_SUCCESS)
		return -1;

	if (dt != REG_SZ)
		return -1;

	if ((int)l > len)
		return -1;

	return 0;
}

static int ti_get_devs_component(struct tip_cygwin *priv, char *name)
{
	char key[256];
	int rc = 0;

	snprintf(key, sizeof(key)-1, "%s\\%s", ADAPTER_KEY, name);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WRITE,
			 &priv->tc_key) != ERROR_SUCCESS)
		return -1;

	if (ti_read_reg(priv, "ComponentId", key, sizeof(key)) == -1)
		goto out;

	/* make sure component id matches */
	if (strcmp(key, TAP_COMPONENT_ID) != 0)
		goto out;

	/* get guid */
	if (ti_read_reg(priv, "NetCfgInstanceId", key, sizeof(key)) == -1)
		goto out;

	rc = ti_try_open(priv, key);

out:
	if (rc != 1) {
		RegCloseKey(priv->tc_key);
		priv->tc_key = 0;
	}

	return rc;
}

static int ti_do_open_cygwin(struct tip_cygwin *priv)
{
	int rc = -1;
	HKEY ak47;
	int i;
	char name[256];
	DWORD len;

	/* open network driver key */
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &ak47)
	    != ERROR_SUCCESS)
		return -1;

	/* find tap */
	for (i = 0;; i++) {
		len = sizeof(name);
		if (RegEnumKeyEx(ak47, i, name, &len, NULL, NULL, NULL, NULL)
		    != ERROR_SUCCESS)
			break;

		rc = ti_get_devs_component(priv, name);
		if (rc)
			break;
		rc = -1;
	}

	RegCloseKey(ak47);

	if (rc == 1)
		rc = 0;

	return rc;
}

static void ti_do_free(struct tif *ti)
{
	struct tip_cygwin *priv = ti_priv(ti);

	/* stop reader */
	stop_reader(priv);

	if (priv->tc_pipe[0]) {
		close(priv->tc_pipe[0]);
		close(priv->tc_pipe[1]);
	}

	/* close card */
	if (priv->tc_h) {
		ti_media_status(priv, 0);
		CloseHandle(priv->tc_h);
	}

	if (priv->tc_key)
		RegCloseKey(priv->tc_key);

	free(priv);
	free(ti);
}

static void ti_close_cygwin(struct tif *ti)
{
	ti_do_free(ti);
}

static char *ti_name_cygwin(struct tif *ti)
{
	struct tip_cygwin *priv = ti_priv(ti);

	return priv->tc_name;
}

/* XXX */
static int ti_is_us(struct tip_cygwin *priv, HDEVINFO *hdi,
		    SP_DEVINFO_DATA *did)
{
	char buf[256];
	DWORD len = sizeof(buf), dt;

	if (priv) {} /* XXX unused */

	if (!SetupDiGetDeviceRegistryProperty(*hdi, did, SPDRP_DEVICEDESC, &dt,
					      (unsigned char*)buf, len, &len))
		return 0;

	if (dt != REG_SZ)
		return 0;

	return strstr(buf, "TAP-Win32") != NULL;
}

static int ti_reset_state(HDEVINFO *hdi, SP_DEVINFO_DATA *did, DWORD state)
{
	SP_PROPCHANGE_PARAMS parm;

	parm.ClassInstallHeader.cbSize = sizeof(parm.ClassInstallHeader);
	parm.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	parm.Scope = DICS_FLAG_GLOBAL;
	parm.StateChange = state;

	if (!SetupDiSetClassInstallParams(*hdi, did, (SP_CLASSINSTALL_HEADER*)
					  &parm, sizeof(parm)))
		return -1;

	if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, *hdi, did))
		return -1;

	return 0;
}

/**
 * Reset the device
 * @return 0 if successful, -1 if it failed
 */
static int ti_do_reset(HDEVINFO *hdi, SP_DEVINFO_DATA *did)
{
	int rc;

	rc = ti_reset_state(hdi, did, DICS_DISABLE);
	if (rc)
		return rc;

	return ti_reset_state(hdi, did, DICS_ENABLE);
}

static int ti_restart(struct tip_cygwin *priv)
{
	/* kill handle to if */
	if (priv->tc_h)
		CloseHandle(priv->tc_h);

	/* stop reader */
	if (stop_reader(priv))
		return -1;

	/* reopen dev */
	if (ti_do_open_cygwin(priv))
		return -1;

	return start_reader(priv);
}

static int ti_reset(struct tip_cygwin *priv)
{
	HDEVINFO hdi;
	SP_DEVINFO_DATA did;
	int i;
	int rc = -1;

	hdi = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL,
			  DIGCF_PRESENT);
	if (hdi == INVALID_HANDLE_VALUE)
		return -1;

	/* find device */
	for (i = 0;; i++) {
		did.cbSize = sizeof(did);
		if (!SetupDiEnumDeviceInfo(hdi, i, &did))
			break;

		if (!ti_is_us(priv, &hdi, &did))
			continue;

		rc = ti_do_reset(&hdi, &did);
		if (rc)
			break;

		rc = ti_restart(priv);
		break;
	}

	SetupDiDestroyDeviceInfoList(hdi);

	return rc;
}

static int ti_set_mtu_cygwin(struct tif *ti, int mtu)
{
	struct tip_cygwin *priv = ti_priv(ti);
	char m[16];
	char mold[sizeof(m)];
	char *key = "MTU";

	/* check if reg remains unchanged to avoid reset */
	snprintf(m, sizeof(m)-1, "%d", mtu);
	if (ti_read_reg(priv, key, mold, sizeof(mold)) != -1) {
		if (strcmp(m, mold) == 0)
			return 0;
	}

	/* change */
	if (RegSetValueEx(priv->tc_key, key, 0, REG_SZ,
			  (unsigned char *) m, strlen(m)+1) != ERROR_SUCCESS)
		return -1;

	if (ti_reset(priv) == -1)
		return -1;

	return 0;
}

/**
 * Set device MAC address
 * @param mac New MAC address
 * @return -1 if it failed, 0 on success
 */
static int ti_set_mac_cygwin(struct tif *ti, unsigned char *mac)
{
	struct tip_cygwin *priv = ti_priv(ti);
	char str[2*6+1];
	char strold[sizeof(str)];
	int i;
	char *key = "MAC";

	/* convert */
	str[0] = 0;
	for (i = 0; i < 6; i++) {
		char tmp[3];

		if (sprintf(tmp, "%.2X", *mac++) != 2)
			return -1;
		strcat(str, tmp);
	}

	/* check if changed */
	if (ti_read_reg(priv, key, strold, sizeof(strold)) != -1) {
		if (strcmp(str, strold) == 0)
			return 0;
	}

	/* own */
	if (RegSetValueEx(priv->tc_key, key, 0, REG_SZ, (unsigned char *)str,
			  strlen(str)+1) != ERROR_SUCCESS)
		return -1;

	if (ti_reset(priv) == -1)
		return -1;

	return 0;
}

/**
 * Set device IP address
 * @param ip New IP address
 * @return -1 if it failed, 0 on success
 */
static int ti_set_ip_cygwin(struct tif *ti, struct in_addr *ip)
{
	struct tip_cygwin *priv = ti_priv(ti);
	ULONG ctx, inst;
	IP_ADAPTER_INFO ai[16];
	DWORD len = sizeof(ai);
	PIP_ADAPTER_INFO p;
	PIP_ADDR_STRING ips;

	if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS)
		return -1;

	p = ai;
	while (p) {
		if (strcmp(priv->tc_guid, p->AdapterName) != 0) {
			p = p->Next;
			continue;
		}

		/* delete ips */
		ips = &p->IpAddressList;
		while (ips) {
			DeleteIPAddress(ips->Context);
			ips = ips->Next;
		}

		/* add ip */
		if (AddIPAddress(ip->s_addr, htonl(0xffffff00),
			 p->Index, &ctx, &inst) != NO_ERROR)
			return -1;

		break;
	}

	return 0;
}

static int ti_fd_cygwin(struct tif *ti)
{
	struct tip_cygwin *priv = ti_priv(ti);

	return priv->tc_pipe[0];
}

static int ti_read_cygwin(struct tif *ti, void *buf, int len)
{
	struct tip_cygwin *priv = ti_priv(ti);
	int plen;

	if (priv->tc_running != 1)
		return -1;

	/* read len */
	if (net_read_exact(priv->tc_pipe[0], &plen, sizeof(plen)) == -1)
		return -1;

	return cygwin_read_reader(priv->tc_pipe[0], plen, buf, len);
}

static int ti_wait_complete(struct tip_cygwin *priv, OVERLAPPED *o)
{
	DWORD sz;

	if (!GetOverlappedResult(priv->tc_h, o, &sz, TRUE))
		return -1;

	return sz;
}

static int ti_do_io(struct tip_cygwin *priv, void *buf, int len,
		    OVERLAPPED *o, int wr)
{
	BOOL rc;
	DWORD sz;
	int err;

	/* setup overlapped */
	memset(o, 0, sizeof(*o));

	/* do io */
	if (wr)
		rc = WriteFile(priv->tc_h, buf, len, &sz, o);
	else
		rc = ReadFile(priv->tc_h, buf, len, &sz, o);

	/* done */
	if (rc)
		return sz;

	if ((err = GetLastError()) != ERROR_IO_PENDING)
		return -1;

	return 0; /* pending */
}

static int ti_do_io_lock(struct tip_cygwin *priv, void *buf, int len,
			 OVERLAPPED *o, int wr)
{
	int rc;

	if (pthread_mutex_lock(&priv->tc_mtx))
		return -1;

	rc = ti_do_io(priv, buf, len, o, wr);

	if (pthread_mutex_unlock(&priv->tc_mtx))
		return -1;

	/* done */
	if (rc)
		return rc;

	return ti_wait_complete(priv, o);
}

static int ti_write_cygwin(struct tif *ti, void *buf, int len)
{
	struct tip_cygwin *priv = ti_priv(ti);
	OVERLAPPED o;

	return ti_do_io_lock(priv, buf, len, &o, 1);
}

static int ti_read_packet(struct tip_cygwin *priv, void *buf, int len)
{
	OVERLAPPED o;
	int rc;

	while (priv->tc_running) {
		rc = ti_do_io_lock(priv, buf, len, &o, 0);
		if (rc)
			return rc;
	}

	return -1;
}

static void *ti_reader(void *arg)
{
	struct tip_cygwin *priv = arg;
	unsigned char buf[2048];
	int len;

	while (priv->tc_running) {
		/* read a packet */
		if ((len = ti_read_packet(priv, buf, sizeof(buf))) == -1)
			break;

		assert(len > 0);

		/* write it's length */
		if (write(priv->tc_pipe[1], &len, sizeof(len)) != sizeof(len))
			break;

		/* write payload */
		if (write(priv->tc_pipe[1], buf, len) != len)
			break;
	}

	priv->tc_running = -1;

	return NULL;
}

static struct tif *ti_open_cygwin(char *iface)
{
	struct tif *ti;
	struct tip_cygwin *priv;

	/* setup ti struct */
	ti = ti_alloc(sizeof(*priv));
	if (!ti)
		return NULL;
	priv = ti_priv(ti);

	ti->ti_name	= ti_name_cygwin;
	ti->ti_set_mtu	= ti_set_mtu_cygwin;
	ti->ti_close	= ti_close_cygwin;
	ti->ti_fd	= ti_fd_cygwin;
	ti->ti_read	= ti_read_cygwin;
	ti->ti_write	= ti_write_cygwin;
	ti->ti_set_mac	= ti_set_mac_cygwin;
	ti->ti_set_ip	= ti_set_ip_cygwin;

	/* setup iface */
	if (iface)
		snprintf(priv->tc_guid, sizeof(priv->tc_guid), "%s", iface);
	if (ti_do_open_cygwin(priv) == -1)
		goto err;

	/* setup reader */
	if (pipe(priv->tc_pipe) == -1)
		goto err;

	if (pthread_mutex_init(&priv->tc_mtx, NULL))
		goto err;

	/* launch reader */
	if (start_reader(priv))
		goto err;

	return ti;
err:
	ti_do_free(ti);
	return NULL;
}

struct tif *ti_open(char *iface)
{
	return ti_open_cygwin(iface);
}
