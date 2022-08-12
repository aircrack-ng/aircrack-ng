/**
 * Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
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

#ifndef AIRCRACK_NG_DEFS_H
#define AIRCRACK_NG_DEFS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

// PVS-Studio warning opt-outs:
//-V:ALLEGE:547
//-V:REQUIRE:547
//-V:ENSURE:547
//-V:INVARIANT:547

// NOTE(jbenden): These macros violates MISRA C:2012. 20.10 - The #
// and ## preprocessor operators should not be used.
#define ALLEGE(c)                                                              \
	do                                                                         \
	{                                                                          \
		if (!(c))                                                              \
		{                                                                      \
			fprintf(stderr, "FAILED:%s:%d: %s\n", __FILE__, __LINE__, #c);     \
			abort();                                                           \
		}                                                                      \
	} while (0)
#define REQUIRE(c)                                                             \
	do                                                                         \
	{                                                                          \
		if (!(c))                                                              \
		{                                                                      \
			fprintf(stderr, "Pre-condition Failed: %s\n", #c);                 \
			abort();                                                           \
		}                                                                      \
	} while (0)
#define ENSURE(c)                                                              \
	do                                                                         \
	{                                                                          \
		if (!(c))                                                              \
		{                                                                      \
			fprintf(stderr, "Post-condition Failed: %s\n", #c);                \
			abort();                                                           \
		}                                                                      \
	} while (0)
#define INVARIANT(c)                                                           \
	do                                                                         \
	{                                                                          \
		if (!(c))                                                              \
		{                                                                      \
			fprintf(stderr, "Invariant Failed: %s\n", #c);                     \
			abort();                                                           \
		}                                                                      \
	} while (0)

#ifdef NDEBUG
#undef REQUIRE
#define REQUIRE(c)
#undef ENSURE
#define ENSURE(c)
#undef INVARIANT
#define INVARIANT(c)
#endif

#if defined(_MSC_VER)
//  Microsoft
#define API_EXPORT __declspec(dllexport)
#define API_IMPORT __declspec(dllimport)
#elif defined(__GNUC__) || defined(__llvm__) || defined(__clang__)             \
	|| defined(__INTEL_COMPILER)
#define API_EXPORT __attribute__((visibility("default")))
#define API_IMPORT
#else
//  do nothing and hope for the best?
#define API_EXPORT
#define API_IMPORT
#pragma warning Unknown dynamic link import / export semantics.
#endif

#define STATIC_ASSERT(COND, MSG)                                               \
	typedef char static_assertion_##MSG[(!!(COND)) * 2 - 1]
// token pasting madness:
#define COMPILE_TIME_ASSERT3(X, L)                                             \
	STATIC_ASSERT(X, static_assertion_at_line_##L)
#define COMPILE_TIME_ASSERT2(X, L) COMPILE_TIME_ASSERT3(X, L)
#define COMPILE_TIME_ASSERT(X) COMPILE_TIME_ASSERT2(X, __LINE__)

#if defined(__GNUC__) || defined(__llvm__) || defined(__clang__)               \
	|| defined(__INTEL_COMPILER)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#if defined(HAS_ATTRIBUTE)
#undef HAS_ATTRIBUTE
#endif
#if defined(__has_attribute)
#define HAS_ATTRIBUTE(attribute) __has_attribute(attribute)
#else
#define HAS_ATTRIBUTE(attribute) (0)
#endif

#if defined(fallthrough)
#undef fallthrough
#endif
#if defined(__GNUC__) && __GNUC__ >= 11 && !defined(__INTEL_COMPILER)       \
		&& !defined(__llvm__) && !defined(__clang__)
#define fallthrough __attribute__((fallthrough))
#elif HAS_ATTRIBUTE(fallthrough)                                                 \
	|| (defined(__GNUC__) && __GNUC__ >= 7 && !defined(__INTEL_COMPILER)       \
		&& !defined(__llvm__)                                                  \
		&& !defined(__clang__))
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough
#endif

#define UNUSED_PARAM(x) (void) x

#ifdef UNUSED
#elif defined(__GNUC__)
#define UNUSED(x) UNUSED_##x __attribute__((unused))
#elif defined(__LCLINT__)
#define UNUSED(x) /*@unused@*/ x
#else
#define UNUSED(x) x
#endif

#define ArrayCount(a) (sizeof((a)) / sizeof((a)[0]))

#define THREAD_ENTRY(fn) void * __attribute__((noinline)) fn(void * arg)

#define IGNORE_LTZ(c)                                                          \
	do                                                                         \
	{                                                                          \
		int __rc = (c);                                                        \
		if (__rc < 0)                                                          \
		{                                                                      \
			fprintf(stderr,                                                    \
					"%s:%d:Function failed(%d:%d): %s\n",                      \
					__FILE__,                                                  \
					__LINE__,                                                  \
					__rc,                                                      \
					errno,                                                     \
					#c);                                                       \
		}                                                                      \
	} while (0)

#define IGNORE_NZ(c)                                                           \
	do                                                                         \
	{                                                                          \
		int __rc = (c);                                                        \
		if (__rc != 0)                                                         \
		{                                                                      \
			fprintf(stderr,                                                    \
					"%s:%d:Function failed(%d:%d): %s\n",                      \
					__FILE__,                                                  \
					__LINE__,                                                  \
					__rc,                                                      \
					errno,                                                     \
					#c);                                                       \
		}                                                                      \
	} while (0)

#define IGNORE_ZERO(c)                                                         \
	do                                                                         \
	{                                                                          \
		if ((c) == 0)                                                          \
		{                                                                      \
			fprintf(stderr,                                                    \
					"%s:%d:Function failed(%d): %s\n",                         \
					__FILE__,                                                  \
					__LINE__,                                                  \
					errno,                                                     \
					#c);                                                       \
		}                                                                      \
	} while (0)

#if __STDC_VERSION__ >= 199901L
#define DO_PRAGMA(x) _Pragma(#x)
#else
#define DO_PRAGMA(x)
#endif

#if defined(__clang_major__) && __clang_major__ >= 4
#define UNROLL_LOOP_N_TIME(n) DO_PRAGMA(clang loop unroll_count(n))
#elif defined(__GNUC__) && __GNUC__ >= 8
#define UNROLL_LOOP_N_TIME(n) DO_PRAGMA(GCC unroll n)
#else
#define UNROLL_LOOP_N_TIME(n)
#endif

#include <aircrack-ng/compat.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline size_t ustrlen(const uint8_t * s1)
{
	return strlen((const char *) s1);
}

#define destroy(var, fn)                                                       \
	__extension__({                                                            \
		if ((var) != NULL)                                                     \
		{                                                                      \
			fn((__typeof__(var))(var));                                        \
                                                                               \
			(var) = NULL;                                                      \
		}                                                                      \
	})

#ifdef __cplusplus
}
#endif

#endif
