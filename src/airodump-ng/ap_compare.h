#ifndef __AP_COMPARE_H__
#define __AP_COMPARE_H__

#include "aircrack-ng/defs.h"
#include "airodump-ng.h"
#include "aircrack-ng/support/communications.h"

typedef enum ap_sort_type_t
{
    SORT_FIRST,
    SORT_DEFAULT = SORT_FIRST,
    SORT_BY_NOTHING,
    SORT_BY_BSSID,
    SORT_BY_POWER,
    SORT_BY_BEACON,
    SORT_BY_DATA,
    SORT_BY_PRATE,
    SORT_BY_CHAN,
    SORT_BY_MBIT,
    SORT_BY_ENC,
    SORT_BY_CIPHER,
    SORT_BY_AUTH,
    SORT_BY_ESSID,
    SORT_MAX
} ap_sort_type_t; 

typedef struct ap_sort_info_st ap_sort_info_st;

struct ap_sort_context_st
{
    int sort_direction;
    ap_sort_info_st const * sort_method;
};

char const * ap_sort_context_description(
    struct ap_sort_context_st const * const context);

int ap_sort_compare(
    struct ap_sort_context_st const * const context,
    struct AP_info const * const a,
    struct AP_info const * const b); 

void ap_sort_context_initialise(
    struct ap_sort_context_st * const context,
    ap_sort_type_t const sort_method);

bool ap_sort_context_invert_direction(
    struct ap_sort_context_st * const context);

void ap_sort_context_assign_sort_method(
    struct ap_sort_context_st * const context,
    ap_sort_type_t const sort_method);

void ap_sort_context_next_sort_method(
    struct ap_sort_context_st * const context); 

#endif /*  __AP_COMPARE_H__ */

