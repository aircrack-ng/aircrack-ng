/*- 
 * Copyright (c) 2007, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * OS dependent API for unsupported APIs.
 *
 */

#include <errno.h>
#include <stdio.h>

#include "osdep.h"

struct wif *wi_open(char *iface)
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
