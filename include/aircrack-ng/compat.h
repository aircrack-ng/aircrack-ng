/**
 * Copyright (C) 2020-2022 Joseph Benden <joe@benden.us>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 **/

#ifndef AIRCRACK_NG_COMPAT_H
#define AIRCRACK_NG_COMPAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif

#if !defined(HAVE_STRLCAT) && !defined(__APPLE__) && !defined(__MACH__)
/**
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 */
API_IMPORT size_t strlcat(char * restrict dst,
						  const char * restrict src,
						  size_t dsize);
#endif

#if !defined(HAVE_STRLCPY) && !defined(__APPLE__) && !defined(__MACH__)
/**
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
API_IMPORT size_t strlcpy(char * restrict dst,
						  const char * restrict src,
						  size_t dsize);
#endif

#ifdef __cplusplus
}
#endif

#endif
