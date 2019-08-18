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

ap_sort_info_st const * ap_sort_method_assign(ap_sort_type_t const sort_method);

ap_sort_info_st const * ap_sort_method_assign_next(ap_sort_info_st const * current);

char const * ap_sort_method_description(ap_sort_info_st const * const sort_info);

int ap_sort_compare(
    ap_sort_info_st const * const sort_info,
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction); 

#endif /*  __AP_COMPARE_H__ */

