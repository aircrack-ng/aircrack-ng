#ifndef __UTILS_H__
#define __UTILS_H__

#include "aircrack-ng/osdep/mac_header.h"

#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

char * time_as_string(time_t const time);

char const * create_output_filename(
    char * const buffer,
    size_t const buffer_size,
    char const * const prefix,
    int const index,
    char const * const suffix);

int wait_proc(pid_t in, pid_t * out);

void make_printable(uint8_t * const buf, size_t const buf_size);

bool bssid_is_filtered(
    mac_address const * const bssid,
    mac_address const * const f_bssid,
    mac_address const * const f_netmask);

char * parse_timestamp(unsigned long long timestamp);

bool essid_has_control_chars(
    uint8_t const * const essid, 
    size_t const essid_length);

#endif /* __UTILS_H__ */
