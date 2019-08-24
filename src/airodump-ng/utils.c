#include "utils.h"
#include "aircrack-ng/defs.h"

#include <string.h>

char * time_as_string(time_t const time)
{
    char * const string = strdup(ctime(&time));

    ALLEGE(string != NULL);

    /* Remove the new line that is included by ctime(). 
     * Cripes why wouldn't it just provide the time, and not assume 
     * that it goes at the end of a line? 
     */
    if (strlen(string) > 0)
    {
        string[strlen(string) - 1] = '\0';
    }

    return string;
}


