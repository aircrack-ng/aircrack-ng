#include "battery.h"
#include "get_string_time_from_seconds.h"
#include "aircrack-ng/defs.h"
#include "aircrack-ng/osdep/osdep.h"

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

char const * getBatteryString(void)
{
	int batt_time;
	char const * batt_string;

	batt_time = get_battery_state();

	if (batt_time <= 60)
	{
		batt_string = strdup("");
	}
	else
	{
		batt_string = getStringTimeFromSec((double) batt_time);
	}

	ALLEGE(batt_string != NULL);

	return batt_string;
}
