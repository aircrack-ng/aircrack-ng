#ifndef __UTILS_H__
#define __UTILS_H__

#include <time.h>
#include <unistd.h>

char * time_as_string(time_t const time);

char const * create_output_filename(
    char * const buffer,
    size_t const buffer_size,
    char const * const prefix,
    int const index,
    char const * const suffix);

int wait_proc(pid_t in, pid_t * out);

#endif /* __UTILS_H__ */
