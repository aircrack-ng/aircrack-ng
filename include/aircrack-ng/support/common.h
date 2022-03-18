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

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <aircrack-ng/defs.h>

#if defined(__CYGWIN32__) && !defined(__CYGWIN64__)
int fseeko64(FILE * fp, int64_t offset, int whence);
int64_t ftello64(FILE * fp);
//-V:fseek:1059
//-V:ftello:1059
#undef fseek
#define fseek fseeko64
#undef ftello
#define ftello ftello64
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
//-V:rand:1059
//-V:srand:1059
#undef rand
#define rand lrand48
#undef srand
#define srand srand48
#endif

#define SWAP(x, y)                                                             \
	{                                                                          \
		unsigned char tmp = x;                                                 \
		x = y;                                                                 \
		y = tmp;                                                               \
	}

#define SWAP32(x)                                                              \
	x = ((((x) >> 24u) & 0x000000FFu) | (((x) >> 8u) & 0x0000FF00u)            \
		 | (((x) << 8u) & 0x00FF0000u)                                         \
		 | (((x) << 24u) & 0xFF000000u))

#define PCT                                                                    \
	{                                                                          \
		struct tm * lt;                                                        \
		time_t tc = time(NULL);                                                \
		lt = localtime(&tc);                                                   \
		REQUIRE(lt != NULL);                                                   \
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

static const unsigned char ZERO[33] = "\x00\x00\x00\x00\x00\x00\x00\x00"
									  "\x00\x00\x00\x00\x00\x00\x00\x00"
									  "\x00\x00\x00\x00\x00\x00\x00\x00"
									  "\x00\x00\x00\x00\x00\x00\x00\x00";

void calctime(time_t t, float calc);

/// Retrieves the working directory.
char * get_current_working_directory(void);

int is_string_number(const char * str);

int get_ram_size(void);

char * getVersion(const char * progname,
				  const unsigned int maj,
				  const unsigned int min,
				  const unsigned int submin,
				  const char * rev,
				  const unsigned int beta,
				  const unsigned int rc);

/// Returns the number of CPU/cores available and online.
int get_nb_cpus(void);

int maccmp(unsigned char * mac1, unsigned char * mac2);

static inline void mac2str(char * str, uint8_t * m, size_t macsize)
{
	REQUIRE(str != NULL);
	REQUIRE(m != NULL);

	snprintf(str,
			 macsize,
			 "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			 m[0],
			 m[1],
			 m[2],
			 m[3],
			 m[4],
			 m[5]);
}

#define MAC_ADDRESS_STRING_LEN 18

/// Converts a mac address in a human-readable format.
static inline char * mac2string(unsigned char * mac_address)
{
	REQUIRE(mac_address != NULL);

	char * mac_string = (char *) malloc(MAC_ADDRESS_STRING_LEN);
	ALLEGE(mac_string != NULL);

	mac2str(mac_string, mac_address, MAC_ADDRESS_STRING_LEN);

	return (mac_string);
}

static inline int str2mac(uint8_t * mac, const char * str)
{
	REQUIRE(mac != NULL);
	REQUIRE(str != NULL);

	unsigned int macf[6] = {0};

	if (sscanf(str,
			   "%x:%x:%x:%x:%x:%x",
			   &macf[0],
			   &macf[1],
			   &macf[2],
			   &macf[3],
			   &macf[4],
			   &macf[5])
		!= 6)
		return (-1);

	for (int i = 0; i < 6; i++) *mac++ = (uint8_t) macf[i];

	return (0);
}

int hexCharToInt(unsigned char c);

int hexStringToArray(char * in,
					 int in_length,
					 unsigned char * out,
					 int out_length);

/// Return the mac address bytes (or null if it's not a mac address)
int getmac(const char * macAddress, const int strict, unsigned char * mac);

/// Read a line of characters inputted by the user
int readLine(char line[], int maxlength);

int hexToInt(char s[], int len);

int string_has_suffix(const char * str, const char * suf);

// Returns 1 if the current process is running in the background, 0 otherwise
int is_background(void);

static inline int time_diff(struct timeval * past, struct timeval * now)
{
	REQUIRE(past != NULL);
	REQUIRE(now != NULL);

	time_t p = 0, n = 0;

	if (now->tv_sec > past->tv_sec)
		n = (now->tv_sec - past->tv_sec) * 1000 * 1000;
	else
		p = (past->tv_sec - now->tv_sec) * 1000 * 1000;

	n += now->tv_usec;
	p += past->tv_usec;

	return (int) (n - p);
}

static inline int elapsed_time_diff(struct timeval * past, struct timeval * now)
{
	REQUIRE(past != NULL);
	REQUIRE(now != NULL);

	time_t el = now->tv_sec - past->tv_sec;

	if (el == 0)
	{
		el = now->tv_usec - past->tv_usec;
	}
	else
	{
		el = (el - 1) * 1000 * 1000;
		el += 1000 * 1000 - past->tv_usec;
		el += now->tv_usec;
	}

	if (el < 0) return (666 * 1000 * 1000);
	return (int) (el);
}

#define msec_diff(past, now) (time_diff((past), (now)) / 1000)

/// Return \a str with all leading whitespace removed.
static inline void ltrim(char * str)
{
	REQUIRE(str != NULL);

	size_t i;
	size_t begin = 0u;
	size_t end = strlen(str) - 1u;

	while (isspace((int) str[begin])) begin++;

	// Shift all characters back to the start of the string array.
	for (i = begin; i <= end; i++) str[i - begin] = str[i];

	// Ensure the string is null terminated.
	str[i - begin] = '\0';
}

/// Return \a str with all trailing whitespace removed.
static inline void rtrim(char * str)
{
	REQUIRE(str != NULL);

	size_t end = strlen(str) - 1u;

	while ((end != 0) && isspace((int) str[end])) end--;

	// Ensure the string is null terminated.
	str[end + 1] = '\0';
}

/// Return \a str with all leading and trailing whitespace removed.
static inline void trim(char * str)
{
	REQUIRE(str != NULL);

	ltrim(str);
	rtrim(str);
}

/* See if a string contains a character in the first "n" bytes.
 *
 * Returns a pointer to the first occurrence of the character, or NULL
 * if the character is not present in the string.
 *
 * Breaks the str* naming convention to avoid a name collision if we're
 * compiling on a system that has strnchr()
 */
static inline char * strchr_n(char * str, int c, size_t n)
{
	size_t count = 0;

	if (str == NULL || n == 0)
	{
		return (NULL);
	}

	while (*str != c && *str != '\0' && count < n)
	{
		str++;
		count++;
	}

	return (*str == c) ? (str) : (NULL);
}

/* Remove a newline-terminated block of data from a buffer, replacing
 * the newline with a '\0'.
 *
 * Returns the number of characters left in the buffer, or -1 if the
 * buffer did not contain a newline.
 */
static inline ssize_t
get_line_from_buffer(char * buffer, size_t size, char * line)
{
	char * cursor = strchr_n(buffer, 0x0A, size);

	if (NULL != cursor)
	{
		*cursor = '\0';
		cursor++;
		strlcpy(line, buffer, size);
		memmove(buffer, cursor, size - (strlen(line) + 1));

		return (size - (strlen(line) + 1));
	}

	return (-1);
}

int station_compare(const void * a, const void * b);

/// Initialize standard C random number generator.
static inline void rand_init(void)
{
	srand(time(NULL)); // NOLINT(cert-msc32-c,cert-msc51-cpp)
}

/// Initialize standard C random number generator with specific seed.
static inline void rand_init_with(int seed)
{
	srand(seed); // NOLINT(cert-msc32-c,cert-msc51-cpp)
}

/// Acquire a random unsigned char, from the standard C random number generator.
static inline uint8_t rand_u8(void)
{
	// coverity[dont_call]
	return (uint8_t)(
		rand()
		& 0xFFU); // NOLINT(cert-msc30-c,cert-msc50-cpp,hicpp-signed-bitwise)
}

/// Acquire a random unsigned short, from the standard C random number generator.
static inline uint16_t rand_u16(void)
{
	// coverity[dont_call]
	return (uint16_t)(
		rand()
		& 0xFFFFU); // NOLINT(cert-msc30-c,cert-msc50-cpp,hicpp-signed-bitwise)
}

/// Acquire a random unsigned long, from the standard C random number generator.
static inline uint32_t rand_u32(void)
{
	// coverity[dont_call]
	return (uint32_t)(
		rand()
		& 0xFFFFFFFFUL); // NOLINT(cert-msc30-c,cert-msc50-cpp,hicpp-signed-bitwise)
}

/// Acquire a random float, from the standard C random number generator.
static inline float rand_f32(void)
{
	// coverity[dont_call]
	return ((float) rand() / (float) RAND_MAX);
}

/// Saturated add for unsigned, 32-bit integers.
static inline uint32_t adds_u32(uint32_t a, uint32_t b)
{
	uint32_t c = a + b;
	if (unlikely(c < a)) /* can only happen due to overflow */
		c = -1;
	return (c);
}

/// Saturated add for unsigned, machine word integers.
static inline uintptr_t adds_uptr(uintptr_t a, uintptr_t b)
{
	uintptr_t c = a + b;
	if (unlikely(c < a)) /* can only happen due to overflow */
		c = -1;
	return (c);
}

/// Saturated subtraction for unsigned, 64-bit integers.
static inline uint64_t subs_u64(uint64_t x, uint64_t y)
{
	uint64_t res = x - y;

	res &= -(res <= x); //-V732

	return (res);
}

#ifdef __cplusplus
};
#endif

#endif
