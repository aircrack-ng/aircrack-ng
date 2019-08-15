#ifndef __DUMP_WRITE_WIFI_SCANNER_H__
#define __DUMP_WRITE_WIFI_SCANNER_H__

#include <time.h>

struct dump_context_st * wifi_scanner_dump_open(
    char const * const filename,
    char const * const sys_name,
    char const * const location_name,
    time_t const filter_seconds,
    int const file_reset_seconds);

#endif /* __DUMP_WRITE_WIFI_SCANNER_H__ */
