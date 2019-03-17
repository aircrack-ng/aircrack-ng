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
  *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>

#include "osdep.h"

struct wif * wi_open_osdep(char * iface)
{
	if (iface)
	{
	} /* XXX unused parameter */

	errno = EOPNOTSUPP;
	return NULL;
}

EXPORT int get_battery_state(void)
{
	errno = EOPNOTSUPP;
	return -1;
}

int create_tap(void)
{
	errno = EOPNOTSUPP;
	return -1;
}
