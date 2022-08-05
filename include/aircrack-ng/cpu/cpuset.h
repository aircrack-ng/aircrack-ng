/*
 * Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
 *
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

#ifndef AIRCRACK_UTIL_CPUSET_H
#define AIRCRACK_UTIL_CPUSET_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ac_cpuset;
typedef struct ac_cpuset ac_cpuset_t;

/// Allocate a new cpuset module handle.
ac_cpuset_t * ac_cpuset_new(void);

/// Deallocate a cpuset module handle.
void ac_cpuset_free(ac_cpuset_t * cset);

/// Initialize the cpuset module handle.
void ac_cpuset_init(ac_cpuset_t * cset);

/// Destroy the cpuset module handle.
void ac_cpuset_destroy(ac_cpuset_t * cset);

/// Distribute \a count threads over all available CPUs.
void ac_cpuset_distribute(ac_cpuset_t * cset, size_t count);

/// Bind \a tid to the CPU stored at the \a idx index position.
void ac_cpuset_bind_thread_at(ac_cpuset_t * cset, pthread_t tid, size_t idx);

#ifdef __cplusplus
}
#endif

#endif
