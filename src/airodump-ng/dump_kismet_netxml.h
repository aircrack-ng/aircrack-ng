#ifndef __DUMP_KISMET_NETXML_H__
#define __DUMP_KISMET_NETXML_H__

#include "dump_write.h"

#include <stdbool.h>

bool kismet_netxml_dump_open(
    dump_context_st * const dump,
    char const * const filename,
    char const * const airodump_start_time,
    bool const use_gpsd);

#endif /* __DUMP_KISMET_NETXML_H__ */
