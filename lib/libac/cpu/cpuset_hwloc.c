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

#include <hwloc.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>

#include "aircrack-ng/cpu/cpuset.h"

struct ac_cpuset
{
	size_t nbThreads;

	hwloc_topology_t topology;
	hwloc_cpuset_t * hwloc_cpusets;
};

ac_cpuset_t * ac_cpuset_new(void) { return malloc(sizeof(struct ac_cpuset)); }

void ac_cpuset_free(ac_cpuset_t * cset) { free(cset); }

void ac_cpuset_init(ac_cpuset_t * cset)
{
	assert(cset != NULL);

	cset->nbThreads = 0;
	cset->hwloc_cpusets = NULL;

	hwloc_topology_init(&cset->topology);
	hwloc_topology_load(cset->topology);
}

void ac_cpuset_destroy(ac_cpuset_t * cset)
{
	assert(cset != NULL);

	if (cset->hwloc_cpusets != NULL)
	{
		free(cset->hwloc_cpusets);
		cset->hwloc_cpusets = NULL;
	}

	hwloc_topology_destroy(cset->topology);
}

void ac_cpuset_distribute(ac_cpuset_t * cset, size_t count)
{
	assert(cset != NULL);

	cset->nbThreads = count;
	cset->hwloc_cpusets = calloc(count, sizeof(hwloc_cpuset_t));

	if (!cset->hwloc_cpusets) return;

	hwloc_obj_t root = hwloc_get_root_obj(cset->topology);

#if defined(HWLOC_API_VERSION) && HWLOC_API_VERSION > 0x00010800
	hwloc_distrib(cset->topology,
				  &root,
				  1u,
				  cset->hwloc_cpusets,
				  (unsigned int) count,
				  INT_MAX,
				  0u);
#else
	hwloc_distributev(cset->topology,
					  &root,
					  1u,
					  cset->hwloc_cpusets,
					  (unsigned int) count,
					  INT_MAX);
#endif
}

#ifdef CYGWIN
struct tid_to_handle
{
	ptrdiff_t vtbl;
	uint32_t magic;
	HANDLE h;
};
#endif

void ac_cpuset_bind_thread_at(ac_cpuset_t * cset, pthread_t tid, size_t idx)
{
	assert(cset != NULL);

	if (idx > cset->nbThreads) return;

	hwloc_bitmap_singlify(cset->hwloc_cpusets[idx]);

	if (hwloc_set_thread_cpubind(
			cset->topology,
#ifdef CYGWIN
			// WARNING: This is a HACK into `class pthread` of Cygwin.
			*((HANDLE *) ((char *) tid + offsetof(struct tid_to_handle, h))),
#else
			tid,
#endif
			cset->hwloc_cpusets[idx],
			HWLOC_CPUBIND_THREAD))
	{
		char * str;
		int error = errno;
		hwloc_bitmap_asprintf(&str, cset->hwloc_cpusets[idx]);
		fprintf(stderr,
				"Couldn't bind thread to cpuset %s: %s\n",
				str,
				strerror(error));
		free(str);
	}
}
