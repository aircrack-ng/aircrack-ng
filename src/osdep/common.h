#ifndef _OSDEP_COMMON_H_
#define _OSDEP_COMMON_H_

int getFrequencyFromChannel(int channel);
int getChannelFromFrequency(int frequency);

/*
// For later use, because aircrack-ng doesn't compile with MS compilers
#if defined(WIN32) || defined(__WIN__)
#define ftruncate(a, b) _chsize(a,b)
#endif
*/

#endif
