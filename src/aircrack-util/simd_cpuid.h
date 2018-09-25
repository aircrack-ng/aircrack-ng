/*
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

#ifndef AIRCRACK_NG_CPUID_H
#define AIRCRACK_NG_CPUID_H

#ifdef __cplusplus
extern "C" {
#endif

struct _cpuinfo
{
	int simdsize; /* SIMD size		*/
	char * flags; /* Feature Flags	*/
	char * model; /* CPU Model		*/
	int cores; /* Real CPU cores       */
	int coreperid; /* Max cores per id     */
	int htt; /* Hyper-Threading      */
	int maxlogic; /* Max addressible lCPU */
	int hv; /* Hypervisor detected  */
	int cpufreq_cur; /* CPUfreq Current	*/
	int cpufreq_max; /* CPUfreq Maximum	*/
	float coretemp; /* CPU Temperature	*/
	char * cputemppath; /* Linux CPU Sensor Path */
};

/**
 * Retrieve the number of 32-bit integers able to be packed into a single
 * vector register.
 *
 * This value is dependent on the running machine, and may not reflect what
 * the source code is able to process. PROGRAMMER BEWARE!
 *
 * @return int Number of 32-bit integers able to pack in one vector register.
 */
extern int cpuid_simdsize(int);

/// Populates the \a cpuinfo with detected information about the running
/// machine.
extern int cpuid_getinfo(void);

/// Structure containing information about the running machine. The
/// function \a cpuid_getinfo must be called first!
extern struct _cpuinfo cpuinfo;

#ifdef __cplusplus
};
#endif

#endif // AIRCRACK_NG_CPUID_H
