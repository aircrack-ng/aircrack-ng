#ifndef __PROBE_REQUEST_H__
#define __PROBE_REQUEST_H__

#include "aircrack-ng/osdep/osdep.h"

#include <stddef.h>

void send_probe_requests(struct wif * * const wi, size_t num_cards);

#endif /* __PROBE_REQUEST_H__ */
