#ifndef _COMMON_H_
#define _COMMON_H_

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

#define SWAP32(x)       \
    x = ( ( ( x >> 24 ) & 0x000000FF ) | \
          ( ( x >>  8 ) & 0x0000FF00 ) | \
          ( ( x <<  8 ) & 0x00FF0000 ) | \
          ( ( x << 24 ) & 0xFF000000 ) );

#define PCT { struct tm *lt; time_t tc = time( NULL ); \
              lt = localtime( &tc ); printf( "%02d:%02d:%02d  ", \
              lt->tm_hour, lt->tm_min, lt->tm_sec ); }

#ifndef MAX
	#define MAX(x,y) ( (x)>(y) ? (x) : (y) )
#endif

#ifndef MIN
	#define MIN(x,y) ( (x)>(y) ? (y) : (x) )
#endif

#ifndef ABS
	#define ABS(a)          ((a)>=0?(a):(-(a)))
#endif

// For later use in aircrack-ng
#define CPUID_MMX_AVAILABLE 1
#define CPUID_SSE2_AVAILABLE 2
#define CPUID_NOTHING_AVAILABLE 0

#if defined(__i386__) || defined(__x86_64__)
	#define CPUID() shasse2_cpuid()
#else
	#define CPUID() CPUID_NOTHING_AVAILABLE
#endif

#endif
