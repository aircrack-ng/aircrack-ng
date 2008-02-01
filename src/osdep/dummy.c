 /*
  *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for unsupported APIs.
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

#include <errno.h>
#include <stdio.h>

#include "osdep.h"

struct wif *wi_open_osdep(char *iface)
{
	if (iface) {} /* XXX unused parameter */

	errno = EOPNOTSUPP;
	return NULL;
}

int get_battery_state(void)
{
	errno = EOPNOTSUPP;
	return -1;
}

int create_tap(void)
{
	errno = EOPNOTSUPP;
	return -1;
}
