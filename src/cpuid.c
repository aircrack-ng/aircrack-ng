/*
 * CPU/SIMD identification routines by Len White <lwhite@nrw.ca>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif
#include "aircrack-ng.h"

struct _cpuinfo cpuinfo = { 0, NULL, NULL, 0, 0, 0, 0, 0 };

//
// Until better support for other arch's is added an ifdef is needed
//
#if defined(__i386__) || defined(__x86_64__)
unsigned long getRegister(const unsigned int val, const char from, const char to) {
	unsigned long mask = (1<<(to+1)) - 1;

	if (to == 31)
		return val >> from;

	return (val & mask) >> from;
}

//
// Return maximum SIMD size for the CPU.
// AVX2		  = 8 / 256 bit
// SSE2-4.2 + AVX = 4 / 128 bit
//
int cpuid_simdsize(int viewmax) {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int max_level = __get_cpuid_max(0, NULL);

	if (max_level >= 7) {
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		if (ebx & (1 << 5)) { // AVX2
#ifndef JOHN_AVX2
			// If we're not compiled for AVX2, and we're simply displaying CPU capabilities
			// return the maximum the processor supports, otherwise fallback to avoid
			// a performance regression from overfilling the buffers.
			if (viewmax == 1)
#else
			if (viewmax) {}
#endif
				return 8;
		}
	}

	__cpuid(1, eax, ebx, ecx, edx);

	if (edx & (1 << 26)) // SSE2
		return 4;

	// MMX or CPU Fallback
	return 1;
}

char* cpuid_vendor() {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;

	__cpuid(0, eax, ebx, ecx, edx);

	if ((ebx == 0x756E6547) && (edx == 0x49656E69))
		return "Intel";
	else if ((ebx == 0x68747541) || (ebx == 0x69444D41))
		return "AMD";
	else if (ebx == 0x746E6543)
		return "Centaur (VIA)";
	else if (ebx == 0x69727943)
		return "Cyrix";
	else if ((ebx == 0x6E617254) || ((ebx == 0x756E6547) && (edx == 0x54656E69)))
		return "Transmeta";
	else if (ebx == 0x646F6547)
		return "Geode by NSC (AMD)";
	else if (ebx == 0x4778654E)
		return "NexGen";
	else if (ebx == 0x65736952)
		return "Rise";
	else if (ebx == 0x20536953)
		return "SiS";
	else if (ebx == 0x20434D55)
		return "UMC";
	else if (ebx == 0x20414956)
		return "VIA";
	else if (ebx == 0x74726F56)
		return "Vortex86 SoC";
	else if (ebx == 0x4B4D564B)
		return "KVM (Virtual Machine)";
	else if (ebx == 0x7263694D)
		return "Microsoft Hyper-V or Virtual PC";
	else if (ebx == 0x70726C20)
		return "Parallels (Virtual Machine)";
	else if (ebx == 0x61774D56)
		return "VMware";
	else if (ebx == 0x566E6558)
		return "Xen HVM (Virtual Machine)";

	return "Unknown CPU";
}

void sprintcat(char *dest, const char *src, size_t len) {
	if (strlen(dest))
		(void)strncat(dest, ",", len);

	(void)strncat(dest, src, len);
}

char* cpuid_featureflags() {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	char flags[64] = {0};
	unsigned int max_level = __get_cpuid_max(0, NULL);

	__cpuid(1, eax, ebx, ecx, edx);

	if (edx & (1 << 23))
		sprintcat((char *)&flags, "MMX", sizeof(flags));

	if (edx & (1 << 25))
		sprintcat((char *)&flags, "SSE", sizeof(flags));

	if (edx & (1 << 26))
		sprintcat((char *)&flags, "SSE2", sizeof(flags));

	if (ecx & (1 << 0))
		sprintcat((char *)&flags, "SSE3", sizeof(flags));

	if (ecx & (1 << 9))
		sprintcat((char *)&flags, "SSSE3", sizeof(flags));

	if (ecx & (1 << 19))
		sprintcat((char *)&flags, "SSE4.1", sizeof(flags));

	if (ecx & (1 << 20))
		sprintcat((char *)&flags, "SSE4.2", sizeof(flags));

	if (ecx & (1 << 25))
		sprintcat((char *)&flags, "AES-NI", sizeof(flags));

	// Don't set this if we got it from a higher topology previously.
	if (cpuinfo.maxlogic == 0)	// Maximum addressable logical CPUs per pkg/socket.
		cpuinfo.maxlogic = (ebx >> 16) & 0xFF;

	if (edx & (1 << 28))		// Hyper-threading
		cpuinfo.htt = 1;

	if (ecx & (1 << 28))		// AVX
		sprintcat((char *)&flags, "AVX", sizeof(flags));

	if (ecx & (1 << 31))		// Hypervisor
		cpuinfo.hv = 1;

	if (max_level >= 7) {
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		if (ebx & (1 << 5))	// AVX2
			sprintcat((char *)&flags, "AVX2", sizeof(flags));
	}

	return strdup(flags);
}

char* cpuid_modelinfo() {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	int bi = 2, broff = 0;
	char *tmpmodel = calloc(1, (sizeof(unsigned) * 4) * 5);
	char *pm, *model = NULL;

	if (tmpmodel == NULL) {
		fprintf(stderr, "ERROR: calloc() failed to allocate memory for cpuid_modelinfo(): %s\n", strerror(errno));
		return "Unknown";
	}

	for (; bi < 5; bi++, broff += 16) {
		__cpuid(0x80000000+bi, eax, ebx, ecx, edx);

       		memcpy(tmpmodel+broff, &eax, sizeof(unsigned));
	        memcpy(tmpmodel+broff+4, &ebx, sizeof(unsigned));
        	memcpy(tmpmodel+broff+8, &ecx, sizeof(unsigned));
	        memcpy(tmpmodel+broff+12, &edx, sizeof(unsigned));
	}

	pm = tmpmodel;

	// Clean up the empty spaces in the model name on some intel's because they let their engineers fall asleep on the space bar
	if (*pm == ' ')
		while (*pm == ' ') {
				pm++;
		}

	model = strdup(pm);

	if (model == NULL) {
		fprintf(stderr, "ERROR: strdup() failed to allocate memory for cpuid_modelinfo(): %s\n", strerror(errno));
	  free(tmpmodel);
		return "Unknown";
	}

	free(tmpmodel);
	tmpmodel = NULL;

	return model;
}

int cpuid_getinfo() {
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int max_level = __get_cpuid_max(0, NULL);
	int topologyLevel = 0, topologyType;
	int cpu_count = get_nb_cpus();
#ifdef DEBUG
	int topologyShift;
#endif

	// Attempt higher level topology scan first.
	do {
		__cpuid_count(11, topologyLevel, eax, ebx, ecx, edx);

		// if EBX ==0 then this subleaf is not valid, and the processor doesn't support this.
		if (ebx == 0)
			break;

		topologyType = getRegister(ecx,8,15);
#ifdef DEBUG
		topologyShift = getRegister(eax,0,4);
#endif

		if ((topologyType == 2) && ((int)eax != 0 && (int)ebx != 0)) {
			cpuinfo.cores		= (int)eax;
			cpuinfo.maxlogic	= (int)ebx;
		}
#ifdef DEBUG
		printf("%u %u %u %u\n",eax,ebx,ecx,edx);
		printf("type %d, shift = %d\n", topologyType, topologyShift);
#endif
		topologyLevel++;
	} while (topologyLevel < 5);

#ifdef DEBUG
	__cpuid(1, eax, ebx, ecx, edx);

	printf("Family: %d", (eax >> 8) & 0xF);
	printf("\t\tStepping %d\t\t", eax & 0xF);
	printf("Model %d\n", (eax >> 4) & 0xF);
	printf("Processor type %d\t", (eax >> 12) & 0x3);
	printf("Extended model %d\t", (eax >> 16) & 0xF);
	printf("Extended family %d\n", (eax >> 20) & 0xFF);
#endif

	printf("Vendor          = %s\n", cpuid_vendor());

	if (max_level >= 4) {
		__cpuid(4, eax, ebx, ecx, edx);

		if (topologyLevel == 0) {
			if (eax >> 26)
				cpuinfo.coreperid = (eax >> 26) + 1;
			else	// This processor only supports level1 topology. :'(
				cpuinfo.coreperid = 1;
		}

		cpuinfo.model = cpuid_modelinfo();
		printf("Model           = %s\n", cpuinfo.model);
	} else
		cpuinfo.coreperid = 1;

	cpuinfo.flags = cpuid_featureflags();

	printf("Features        = %s\n", cpuinfo.flags);

#ifdef DEBUG
	printf("cpuinfo.coreperid = %d, cpuinfo.cores = %d, maxlogic = %d (tlevel %d)\n", cpuinfo.coreperid, cpuinfo.cores, cpuinfo.maxlogic, topologyLevel);
#endif

	if ((cpuinfo.cores == 0) && (cpuinfo.coreperid != 0)) {
		// On lower topology processors we have to caclulate the cores from max cores per id (pkg/socket) by max addressable
		cpuinfo.cores = (cpuinfo.maxlogic / cpuinfo.coreperid);
	}

	// this shouldn't happen but prepare for the worst.
	if (cpuinfo.cores == 0)
		cpuinfo.cores = cpu_count;

	// If our max logic matches our cores, we don't have HT even if the proc says otherwise.
	if (cpuinfo.cores == cpuinfo.maxlogic)
		cpuinfo.htt = 0;

	printf("Hyper-Threading = %s\n", cpuinfo.htt?"Yes":"No");

	if (cpuinfo.hv)
		printf("Hypervisor      = Yes (Virtualization detected)\n");

	// This inaccuracy can happen when running under a hypervisor, correct it.
	if (cpuinfo.cores > cpuinfo.maxlogic)
		cpuinfo.maxlogic = cpuinfo.cores;

	if (cpuinfo.htt)
		printf("Logical CPUs    = %d\n", cpuinfo.maxlogic);

	printf("CPU cores       = %d", cpuinfo.cores);

	if (cpuinfo.maxlogic != cpu_count) {
		if (cpu_count > cpuinfo.maxlogic)
			printf(" (%d total, %d sockets)", cpu_count, (cpu_count / cpuinfo.maxlogic));
		else
			printf(" (%d total)", cpu_count);
	}

	cpuinfo.simdsize = cpuid_simdsize(1);

	printf("\nSIMD size       = %d ", cpuinfo.simdsize);

	if (cpuinfo.simdsize == 1)
		printf("(64 bit)\n");
	else if (cpuinfo.simdsize == 4)
		printf("(128 bit)\n");
	else
		printf("(256 bit)\n");

#ifndef JOHN_AVX2
	if (cpuinfo.simdsize == 8) {
		printf("NOTE: Your processor is capable of AVX2 but AVX2 support was not compiled in!\n");
		printf("Please send a copy of this output to the aircrack team to improve autodetection.\n");
	}
#endif

	free(cpuinfo.flags);
	cpuinfo.flags = NULL;
	free(cpuinfo.model);
	cpuinfo.model = NULL;

	return 0;
}
#endif
