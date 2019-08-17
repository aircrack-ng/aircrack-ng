#include "get_string_time_from_seconds.h"
#include "aircrack-ng/defs.h"

#include <stdlib.h>
#include <stddef.h>

char * getStringTimeFromSec(double const seconds)
{
    int hour[3];
    char * ret;
    char * HourTime;
    char * MinTime;

    if (seconds < 0)
        return (NULL);

    ret = calloc(256, sizeof *ret);
    ALLEGE(ret != NULL);

    HourTime = calloc(128, sizeof *HourTime);
    ALLEGE(HourTime != NULL);
    MinTime = calloc(128, sizeof MinTime);
    ALLEGE(MinTime != NULL);

    hour[0] = (int)(seconds);
    hour[1] = hour[0] / 60;
    hour[2] = hour[1] / 60;
    hour[0] %= 60;
    hour[1] %= 60;

    if (hour[2] != 0)
        snprintf(
            HourTime, 128, "%d %s", hour[2], (hour[2] == 1) ? "hour" : "hours");
    if (hour[1] != 0)
        snprintf(
            MinTime, 128, "%d %s", hour[1], (hour[1] == 1) ? "min" : "mins");

    if (hour[2] != 0 && hour[1] != 0)
        snprintf(ret, 256, "%s %s", HourTime, MinTime);
    else
    {
        if (hour[2] == 0 && hour[1] == 0)
            snprintf(ret, 256, "%d s", hour[0]);
        else
            snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime);
    }

    free(MinTime);
    free(HourTime);

    return (ret);
}

