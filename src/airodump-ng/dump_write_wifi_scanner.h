#ifndef __DUMP_WRITE_WIFI_SCANNER_H__
#define __DUMP_WRITE_WIFI_SCANNER_H__

#include "dump_write.h"

#include <time.h>
#include <stdbool.h>

bool wifi_scanner_dump_open(
    dump_context_st * const dump,
    char const * const filename,
    char const * const sys_name,
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds);

#endif /* __DUMP_WRITE_WIFI_SCANNER_H__ */
