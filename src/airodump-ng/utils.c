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

char const * create_output_filename(
    char * const buffer,
    size_t const buffer_size,
    char const * const prefix,
    int const index,
    char const * const suffix)
{
    if (index < 0)
    {
        snprintf(buffer,
                 buffer_size,
                 "%s.%s",
                 prefix,
                 suffix);
    }
    else
    {
        snprintf(buffer,
                 buffer_size,
                 "%s-%02d.%s",
                 prefix,
                 index,
                 suffix);
    }

    return buffer;
}


