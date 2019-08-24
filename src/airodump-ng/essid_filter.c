#include "essid_filter.h"
#include "aircrack-ng/defs.h"

#define ESSID_LENGTH 32

bool is_filtered_essid(
    struct essid_filter_context_st const * const context,
    uint8_t const * const essid)
{
    bool is_filtered = false;
    REQUIRE(essid != NULL);

    /* FIXME - Remove the dependency on lopt.
     * This is called by dump routines, so can't be static as it
     * stands.
     */
    if (context->f_essid != NULL)
    {
        for (size_t i = 0; i < context->f_essid_count; i++)
        {
            if (strncmp((char *)essid, context->f_essid[i], ESSID_LENGTH) == 0)
            {
                is_filtered = false;
                goto done;
            }
        }

        /* Some filters are configured but no match was found. so 
         * this will be filtered unless the pcre exec finds a match. 
         */
        is_filtered = true;
    }

#ifdef HAVE_PCRE
    if (context->f_essid_regex != NULL)
    {
        is_filtered = pcre_exec(context->f_essid_regex,
                                NULL,
                                (char *)essid,
                                (int)strnlen((char *)essid, ESSID_LENGTH),
                                0,
                                0,
                                NULL,
                                0)
            < 0;
    }
#endif

done:
    return is_filtered;
}


