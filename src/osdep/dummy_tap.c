#include <stdio.h>
#include <stdlib.h>

#include "osdep.h"

static struct tif *ti_open_dummy(char *iface)
{
	if (iface) {} /* XXX unused parameter */

	return NULL;
}

struct tif *ti_open(char *iface)
{
	return ti_open_dummy(iface);
}
