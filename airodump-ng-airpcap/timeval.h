/* adapted from timeval.h by Wu Yongwei */

#ifndef _TIMEVAL_H
#define _TIMEVAL_H

#ifdef _WIN32

#include <windows.h>

#define EPOCHFILETIME (116444736000000000i64)

__inline int gettimeofday( struct timeval *tv, void *tz )
{
    FILETIME ft;
    LARGE_INTEGER li;
    __int64 t;

    if( tv != NULL )
    {
        GetSystemTimeAsFileTime( &ft );

        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;

        t  = li.QuadPart;       /* In 100-nanosecond intervals */
        t -= EPOCHFILETIME;     /* Offset to the Epoch time */
        t /= 10;                /* In microseconds */

        tv->tv_sec  = (long) ( t / 1000000 );
        tv->tv_usec = (long) ( t % 1000000 );
    }

    return 0;
}

#else
#include <sys/time.h>
#endif

#endif /* timeval.h */