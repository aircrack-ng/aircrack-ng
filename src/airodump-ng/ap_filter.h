#ifndef __AP_FILTER_H__
#define __AP_FILTER_H__

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "essid_filter.h"
#include "aircrack-ng/support/station.h"

#include <stdbool.h>

bool ap_has_required_security_and_essid(
	struct AP_info const * const ap_cur,
	unsigned int const encryption_filter,
	struct essid_filter_context_st const * const essid_filter);

bool ap_should_be_logged(
	struct AP_info const * const ap_cur,
	int const maximum_age_seconds,
	unsigned int encryption_filter,
	struct essid_filter_context_st const * const essid_filter,
	bool const check_for_broadcast,
	unsigned long const min_packets);

#endif /* __AP_FILTER_H__ */
