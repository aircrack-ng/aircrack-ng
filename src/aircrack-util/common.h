/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
#ifndef _COMMON_H_
#define _COMMON_H_

#if defined(__CYGWIN32__) && !defined(__CYGWIN64__)
int fseeko64(FILE *fp, int64_t offset, int whence);
int64_t ftello64(FILE *fp);
#undef fseek
#define fseek fseeko64
#undef ftello
#define ftello ftello64
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#undef rand
#define rand lrand48
#undef srand
#define srand srand48
#endif

#include <time.h>

#define SWAP(x, y)                                                             \
	{                                                                          \
		unsigned char tmp = x;                                                 \
		x = y;                                                                 \
		y = tmp;                                                               \
	}

#define SWAP32(x)                                                              \
	x = (((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00)                    \
		 | ((x << 8) & 0x00FF0000)                                             \
		 | ((x << 24) & 0xFF000000));

#define PCT                                                                    \
	{                                                                          \
		struct tm *lt;                                                         \
		time_t tc = time(NULL);                                                \
		lt = localtime(&tc);                                                   \
		printf("%02d:%02d:%02d  ", lt->tm_hour, lt->tm_min, lt->tm_sec);       \
	}

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

#ifndef ABS
#define ABS(a) ((a) >= 0 ? (a) : (-(a)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned char ZERO[33];

extern void calctime(time_t t, float calc);

/// Retrieves the working directory.
extern char *get_current_working_directory(void);

/// Trim excess whitespace from the right-most of \a line.
extern void rtrim(char *line);

extern int is_string_number(const char *str);

extern int get_ram_size(void);

extern char *getVersion(const char *progname,
						const unsigned int maj,
						const unsigned int min,
						const unsigned int submin,
						const char *rev,
						const unsigned int beta,
						const unsigned int rc);

/// Returns the number of CPU/cores available and online.
extern int get_nb_cpus(void);

extern int maccmp(unsigned char *mac1, unsigned char *mac2);

extern char *mac2string(unsigned char *mac_address);

extern int hexCharToInt(unsigned char c);

extern int
hexStringToArray(char *in, int in_length, unsigned char *out, int out_length);

/// Return the mac address bytes (or null if it's not a mac address)
extern int getmac(const char *macAddress, const int strict, unsigned char *mac);

/// Read a line of characters inputted by the user
extern int readLine(char line[], int maxlength);

extern int hexToInt(char s[], int len);

extern void rtrim(char *line);

extern int string_has_suffix(const char *str, const char *suf);

// Returns 1 if the current process is running in the background, 0 otherwise
extern int is_background(void);

#ifdef __cplusplus
};
#endif

#endif
