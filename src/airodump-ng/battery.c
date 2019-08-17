#include "battery.h"
#include "get_string_time_from_seconds.h"
#include "aircrack-ng/defs.h"
#include "aircrack-ng/osdep/osdep.h"

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

static char * getBatteryString(void)
{
    int batt_time;
    char * ret;
    char * batt_string;

    batt_time = get_battery_state();

    if (batt_time <= 60)
    {
        ret = calloc(2, sizeof *ret);
        ALLEGE(ret != NULL);
        ret[0] = ']';
        return ret;
    }

    batt_string = getStringTimeFromSec((double)batt_time);
    ALLEGE(batt_string != NULL);

    ret = calloc(256, sizeof *ret);
    ALLEGE(ret != NULL);

    snprintf(ret, 256, "][ BAT: %s ]", batt_string);

    free(batt_string);

    return (ret);
}

void update_battery_string(char * * const old_state)
{
    free(*old_state);
    *old_state = getBatteryString();
}


