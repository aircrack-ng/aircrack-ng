/*
 * Based on John the Ripper and modified to integrate with aircrack
 *
 * 	John the Ripper copyright and license.
 *
 * John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * As a special exception to the GNU General Public License terms,
 * permission is hereby granted to link the code of this program, with or
 * without modification, with any version of the OpenSSL library and/or any
 * version of unRAR, and to distribute such linked combinations.  You must
 * obey the GNU GPL in all respects for all of the code used other than
 * OpenSSL and unRAR.  If you modify this program, you may extend this
 * exception to your version of the program, but you are not obligated to
 * do so.  (In other words, you may release your derived work under pure
 * GNU GPL version 2 or later as published by the FSF.)
 *
 * (This exception from the GNU GPL is not required for the core tree of
 * John the Ripper, but arguably it is required for -jumbo.)
 *
 * 	Relaxed terms for certain components.
 *
 * In addition or alternatively to the license above, many components are
 * available to you under more relaxed terms (most commonly under cut-down
 * BSD license) as specified in the corresponding source files.
 *
 * For more information on John the Ripper licensing please visit:
 *
 * http://www.openwall.com/john/doc/LICENSE.shtml
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Miscellaneous routines.
 */

#ifndef _MISC_H
#define _MISC_H

#include <stdio.h>

#if (__MINGW32__ && !__MINGW64__) || _MSC_VER
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
#define LLu "%I64u"
#define LLd "%I64d"
#define LLx "%I64x"
#define Zu "%u"
#define Zd "%d"
#else
#define LLu "%llu"
#define LLd "%lld"
#define LLx "%llx"
#define Zu "%zu"
#define Zd "%zd"
#endif

#if !AC_BUILT
#include <string.h>
#ifndef _MSC_VER
#include <strings.h>
#endif
#else
#include "autoconfig.h"
#if STRING_WITH_STRINGS
#include <string.h>
#include <strings.h>
#elif HAVE_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif
#endif

/*
 * Exit on error. Logs the event, closes john.pot and the log file, and
 * terminates the process with non-zero exit status.
 */
extern void real_error(char * file, int line)
#ifdef __GNUC__
	__attribute__((__noreturn__));
#else
	;
#endif

#define error(...) real_error(__FILE__, __LINE__)

/*
 * Exit on error with message.  Will call real_error to do
 * the final exiting, after printing error message.
 */
extern void real_error_msg(char * file, int line, char * format, ...)
#ifdef __GNUC__
	__attribute__((__noreturn__)) __attribute__((format(printf, 3, 4)));
#else
	;
#endif

#define error_msg(...) perror(__VA_ARGS__)

/*
 * Similar to perror(), but supports formatted output, and calls error().
 */
extern void real_pexit(char * file, int line, char * format, ...)
#ifdef __GNUC__
	__attribute__((__noreturn__)) __attribute__((format(printf, 3, 4)));
#else
	;
#endif

#define pexit(...)                                                             \
	{                                                                          \
		perror(__VA_ARGS__);                                                   \
		exit(1);                                                               \
	}

/*
 * Attempts to write all the supplied data. Returns the number of bytes
 * written, or -1 on error.
 */
extern int write_loop(int fd, const char * buffer, int count);

/*
 * Similar to fgets(), but doesn't leave the newline character in the buffer,
 * and skips to the end of long lines. Handles both Unix and DOS style text
 * files correctly.
 */
extern char * fgetl(char * s, int size, FILE * stream);

/*
 * Similar to strncpy(), but terminates with only one NUL if there's room
 * instead of padding to the supplied size like strncpy() does.
 */
extern char * strnfcpy(char * dst, const char * src, int size);

/*
 * Similar to the above, but always NUL terminates the string.
 */
extern char * strnzcpy(char * dst, const char * src, int size);

/*
 * Similar to the strnzcpy, but returns the length of the string.
 */
extern int strnzcpyn(char * dst, const char * src, int size);

/*
 * Similar to strncat(), but total buffer size is supplied, and always NUL
 * terminates the string.
 */
extern char * strnzcat(char * dst, const char * src, int size);

/*
 * Similar to atoi(), but properly handles unsigned int.  Do not use
 * atoi() for unsigned data if the data can EVER be over MAX_INT.
 */
extern unsigned atou(const char * src);

/*
 * Similar to strtok(), but properly handles adjacent delmiters as
 * empty strings.  strtok() in the CRTL merges adjacent delimiters
 * and sort of 'skips' them. This one also returns 'empty' tokens
 * for any leading or trailing delims. strtok() strips those off
 * also.
 */
char * strtokm(char * s1, const char * delimit);

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if /* is ASAN enabled? */                                                     \
	__has_feature(address_sanitizer) /* Clang */                               \
	|| defined(__SANITIZE_ADDRESS__) /* GCC 4.8.x */
#define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS                                   \
	__attribute__((no_address_safety_analysis)) __attribute__((noinline))
#define WITH_ASAN
#else
#define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS
#endif

#endif
