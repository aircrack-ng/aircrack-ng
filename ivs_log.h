#ifndef __IVS_LOG_H__
#define __IVS_LOG_H__

#include "aircrack-ng/osdep/mac_header.h"

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

bool ivs_log_wpa_hdsk(
    FILE * const fp,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    void const * const data,
    size_t const data_size);

bool ivs_log_essid(
    FILE * const fp,
    bool * const already_logged,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    void const * const data,
    size_t const data_size);

bool ivs_log_keystream(
    FILE * const fp,
    mac_address const * const bssid,
    mac_address * const previous_bssid,
    uint16_t const type,
    void const * const data,
    size_t const data_size,
    void const * const data2,
    size_t const data2_length);

#endif /* __IVS_LOG_H__ */
