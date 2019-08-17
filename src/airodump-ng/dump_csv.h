#ifndef __DUMP_CSV_H__
#define __DUMP_CSV_H__

#include "dump_write.h"

#include <stdbool.h>

bool csv_dump_open(
    dump_context_st * const dump,
    char const * const filename);

#endif /* __DUMP_CSV_H__ */
