#include "ap_sort.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/defs.h"

static int sort_bssid(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result =
        MAC_ADDRESS_COMPARE(&a->bssid, &b->bssid) * sort_direction;

    return result;
}

static int sort_power(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->avg_power - b->avg_power) * sort_direction;

    return result;
}

static int sort_beacon(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->nb_bcn < b->nb_bcn) && (sort_direction > 0) ? -1 : 1;

    return result;
}

static int sort_data(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->nb_data < b->nb_data) && (sort_direction > 0) ? -1 : 1;

    return result;
}

static int sort_packet_rate(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->nb_dataps - b->nb_dataps) * sort_direction;

    return result;
}

static int sort_channel(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->channel - b->channel) * sort_direction;

    return result;
}

static int sort_mbit(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = (a->max_speed - b->max_speed) * sort_direction;

    return result;
}

static int sort_enc(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result =
        ((int)(a->security & STD_FIELD) - (int)(a->security & STD_FIELD))
        * sort_direction;

    return result;
}

static int sort_cipher(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result =
        ((int)(a->security & ENC_FIELD) - (int)(a->security & ENC_FIELD))
        * sort_direction;

    return result;
}

static int sort_auth(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result =
        ((int)(a->security & AUTH_FIELD) - (int)(a->security & AUTH_FIELD))
        * sort_direction;

    return result;
}

static int sort_essid(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result =
        strncasecmp((char *)a->essid, (char *)b->essid, ESSID_LENGTH)
        * sort_direction;

    return result;
}

static int sort_default(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    int const result = a->avg_power - b->avg_power;

    return result;
}

static int sort_nothing(
    struct AP_info const * const a,
    struct AP_info const * const b,
    int const sort_direction)
{
    return 0;
}


static ap_sort_info_st const ap_sort_infos[SORT_MAX] =
{
    [SORT_DEFAULT] =
    {
        .description = "avg pwr",
        .ap_sort = sort_default
    },
    [SORT_BY_NOTHING] =
    {
        .description = "first seen",
        .ap_sort = sort_nothing
    },
    [SORT_BY_BSSID] =
    {
        .description = "bssid",
        .ap_sort = sort_bssid
    },
    [SORT_BY_POWER] =
    {
        .description = "power level",
        .ap_sort = sort_power
    },
    [SORT_BY_BEACON] =
    {
        .description = "beacon number",
        .ap_sort = sort_beacon
    },
    [SORT_BY_DATA] =
    {
        .description = "number of data packets",
        .ap_sort = sort_data
    },
    [SORT_BY_PRATE] =
    {
        .description = "packet rate",
        .ap_sort = sort_packet_rate
    },
    [SORT_BY_CHAN] =
    {
        .description = "channel",
        .ap_sort = sort_channel
    },
    [SORT_BY_MBIT] =
    {
        .description = "max data rate",
        .ap_sort = sort_mbit
    },
    [SORT_BY_ENC] =
    {
        .description = "encryption",
        .ap_sort = sort_enc
    },
    [SORT_BY_CIPHER] =
    {
        .description = "cipher",
        .ap_sort = sort_cipher
    },
    [SORT_BY_AUTH] =
    {
        .description = "authentication",
        .ap_sort = sort_auth
    },
    [SORT_BY_ESSID] =
    {
        .description = "ESSID",
        .ap_sort = sort_essid
    }
};

ap_sort_info_st const * ap_sort_method_assign(ap_sort_type_t const sort_method_in)
{
    ap_sort_info_st const * sort_info;
    ap_sort_type_t sort_method = sort_method_in;

    if (sort_method < 0 || sort_method >= SORT_MAX)
    {
        sort_method = SORT_FIRST;
    }

    sort_info = &ap_sort_infos[sort_method];

    return sort_info;
}

ap_sort_info_st const * ap_sort_method_assign_next(ap_sort_info_st const * current)
{
    ALLEGE(current != NULL);

    size_t const current_method_index = current - ap_sort_infos;
    size_t const next_method_index = current_method_index + 1;

    return ap_sort_method_assign(next_method_index);
}


