#ifndef __ESSID_FILTER_H__
#define __ESSID_FILTER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

struct essid_filter_context_st
{
    char * * f_essid;
    size_t f_essid_count;
#ifdef HAVE_PCRE
    pcre * f_essid_regex;
#endif
}; 

bool is_filtered_essid(
    struct essid_filter_context_st const * const context,
    uint8_t const * const essid);

#endif

