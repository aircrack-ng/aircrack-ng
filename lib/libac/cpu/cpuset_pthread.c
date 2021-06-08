/*
 * Copyright (C) 2018 Joseph Benden <joe@benden.us>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>

#if defined(__DragonFly__)
#include <pthread_np.h>
#endif

#include "aircrack-ng/defs.h"
#include "aircrack-ng/cpu/cpuset.h"

struct ac_cpuset
{
	size_t nbThreads;
};

ac_cpuset_t * ac_cpuset_new(void) { return malloc(sizeof(struct ac_cpuset)); }

void ac_cpuset_free(ac_cpuset_t * cpuset) { free(cpuset); }

void ac_cpuset_init(ac_cpuset_t * cpuset)
{
	assert(cpuset != NULL);

	cpuset->nbThreads = 0;
}

void ac_cpuset_destroy(ac_cpuset_t * cpuset) { assert(cpuset != NULL); }

void ac_cpuset_distribute(ac_cpuset_t * cpuset, size_t count)
{
	assert(cpuset != NULL);

	cpuset->nbThreads = count;
}

void ac_cpuset_bind_thread_at(ac_cpuset_t * cpuset, pthread_t tid, size_t idx)
{
	assert(cpuset != NULL);

	if (idx > cpuset->nbThreads) return;

#if defined(HAVE_PTHREAD_AFFINITY_NP) && HAVE_PTHREAD_AFFINITY_NP
	// set affinity to a specific processor, for the specified thread.
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(idx, &set);
	pthread_setaffinity_np(tid, sizeof(cpu_set_t), &set);
#else
	UNUSED_PARAM(tid);
	UNUSED_PARAM(idx);
#endif
}
