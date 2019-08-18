#ifndef __GPS_TRACKER_H__
#define __GPS_TRACKER_H__

#define _GNU_SOURCE
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct gps_tracker_context_st gps_tracker_context_st;
struct gps_tracker_context_st
{
    pthread_t gps_tid;
    float gps_loc[8]; /* gps coordinates      */
    int save_gps; /* keep gps file flag   */
    int gps_valid_interval_seconds; /* how many seconds until we consider the GPS data invalid if we dont get new data */
    char * batt; /* Battery string (Used with GPS only.) */
    struct tm gps_time; /* the timestamp from the gps data */
    char const * dump_prefix;
    int f_index;
    FILE * fp;
    volatile int * do_exit;
}; 

void gps_tracker_initialise(
    gps_tracker_context_st * const gps_context,
    char const * const dump_prefix,
    int const f_index,
    FILE * fp,
    volatile int * do_exit);

void gps_tracker_update(gps_tracker_context_st * const gps_context);

bool gps_tracker_start(gps_tracker_context_st * const gps_context);

void gps_tracker_stop(gps_tracker_context_st * const gps_context);


#endif /* __GPS_TRACKER_H__ */
