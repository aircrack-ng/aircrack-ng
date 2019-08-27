#include "ap_filter.h"

static bool ap_has_required_security(
    unsigned int ap_security,
    unsigned int required_security)
{
    bool const has_required =
        ap_security == 0
        || required_security == 0
        || (ap_security & required_security) != 0;

    return has_required;
}

bool ap_has_required_security_and_essid(
    struct AP_info const * const ap_cur,
    unsigned int const encryption_filter,
    struct essid_filter_context_st const * const essid_filter)
{
    bool is_ok;

    if (!ap_has_required_security(ap_cur->security, encryption_filter))
    {
        is_ok = false;
        goto done;
    }

    if (is_filtered_essid(essid_filter, ap_cur->essid))
    {
        is_ok = false;
        goto done;
    }

    is_ok = true;

done:
    return is_ok;
}

bool ap_should_be_logged(
    struct AP_info const * const ap_cur,
    int const max_age_seconds,
    unsigned int encryption_filter,
    struct essid_filter_context_st const * const essid_filter,
    bool const check_for_broadcast,
    unsigned long const min_packets)
{
    bool should_be_logged;

    REQUIRE(ap_cur != NULL);

    if ((time(NULL) - ap_cur->tlast) > max_age_seconds)
    {
        should_be_logged = false;
        goto done;
    }

    if (ap_cur->nb_pkt < min_packets)
    {
        should_be_logged = false;
        goto done;
    }

    if (check_for_broadcast && MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
    {
        should_be_logged = false;
        goto done;
    }

    if (!ap_has_required_security_and_essid(ap_cur,
                                            encryption_filter,
                                            essid_filter))
    {
        should_be_logged = false;
        goto done;
    }

    should_be_logged = true;

done:
    return should_be_logged;
}


