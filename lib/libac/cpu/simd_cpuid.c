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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#if defined(__i386__) || defined(__x86_64__)
#define _X86 1
#include <cpuid.h>
#elif defined(__arm__) || defined(__aarch64__)
#ifdef HAS_AUXV
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#endif /* __arm__ */
#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/sysctl.h>
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/user.h>
#include <sys/sysctl.h>
#endif
#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/sysctl.h>
#endif
#include <dirent.h>

#include "aircrack-ng/cpu/simd_cpuid.h"
#include "aircrack-ng/support/common.h"

#ifdef __linux__
#define CPUFREQ_CPU0C "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
#define CPUFREQ_CPU0M "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
#define CORETEMP_PATH "/sys/devices/platform/coretemp.0/"
static int cpuid_readsysfs(const char * file);
static int cpuid_findcpusensorpath(const char * path);
#endif

struct _cpuinfo cpuinfo = {0, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0.0, NULL};

//
// Until better support for other arch's is added an ifdef is needed
//
static unsigned long
getRegister(const unsigned int val, const char from, const char to)
{
	unsigned long mask = (1ul << (to + 1ul)) - 1ul;

	if (to == 31) return val >> from;

	return (val & mask) >> from;
}

#if defined(_X86) || defined(__arm__) || defined(__aarch64__)
static void sprintcat(char * restrict dest, const char * restrict src, size_t len)
{
	if (*dest != '\0') (void) strncat(dest, ",", len - strlen(dest) - 1);

	(void) strncat(dest, src, len - strlen(dest) - 1);
}
#endif

int is_dir(const char * dir)
{
	struct stat sb;

	if (!stat(dir, &sb)) return S_ISDIR(sb.st_mode);

	return 0;
}

unsigned long GetCacheTotalLize(unsigned ebx, unsigned ecx)
{
	unsigned long LnSz, SectorSz, WaySz, SetSz;
	LnSz = getRegister(ebx, 0, 11) + 1;
	SectorSz = getRegister(ebx, 12, 21) + 1;
	WaySz = getRegister(ebx, 22, 31) + 1;
	SetSz = getRegister(ecx, 0, 31) + 1;
	return (SetSz * WaySz * SectorSz * LnSz);
}

//
// Return maximum SIMD size for the CPU.
// AVX512F		  		= 16 / 512 bit
// AVX2		  		= 8 / 256 bit
// SSE2-4.2 + AVX / NEON	= 4 / 128 bit
// MMX / CPU Fallback		= 1 /  64 bit
//
int cpuid_simdsize(int viewmax)
{
#ifdef _X86
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int max_level = __get_cpuid_max(0, NULL);

	if (max_level >= 7)
	{
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		if (ebx & (1 << 16))
		{ // AVX512F
			return 16;
		}
		else if (ebx & (1 << 5))
		{ // AVX2
			return 8;
		}
	}

	__cpuid(1, eax, ebx, ecx, edx);

	if (edx & (1 << 26)) // SSE2
		return 4;

#elif (defined(__arm__) || defined(__aarch64__)) && defined(HAS_AUXV)
	long hwcaps = getauxval(AT_HWCAP);

	if (hwcaps & (1 << 12)) // NEON
		return 4;
#if defined(__aarch64__)
	if (hwcaps & (1 << 1)) // ASIMD
		return 4;
#endif
#elif defined(__aarch64__) && !defined(HAS_AUXV)
	return 4; // ASIMD is required on AARCH64
#endif
	(void) viewmax;

	// MMX or CPU Fallback
	return 1;
}

#ifdef _X86
static char * cpuid_vendor(void)
{
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
	else if ((ebx == 0x6E617254)
			 || ((ebx == 0x756E6547) && (edx == 0x54656E69)))
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
#endif

static char * cpuid_featureflags(void)
{
	char flags[64] = {0};
#ifdef _X86
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int max_level = __get_cpuid_max(0, NULL);

	__cpuid(1, eax, ebx, ecx, edx);

	if (edx & (1 << 23)) sprintcat((char *) &flags, "MMX", sizeof(flags));

	if (edx & (1 << 25)) sprintcat((char *) &flags, "SSE", sizeof(flags));

	if (edx & (1 << 26)) sprintcat((char *) &flags, "SSE2", sizeof(flags));

	if (ecx & (1 << 0)) sprintcat((char *) &flags, "SSE3", sizeof(flags));

	if (ecx & (1 << 9)) sprintcat((char *) &flags, "SSSE3", sizeof(flags));

	if (ecx & (1 << 19)) sprintcat((char *) &flags, "SSE4.1", sizeof(flags));

	if (ecx & (1 << 20)) sprintcat((char *) &flags, "SSE4.2", sizeof(flags));

	if (ecx & (1 << 25)) sprintcat((char *) &flags, "AES-NI", sizeof(flags));

	if (edx & (1 << 28)) // Hyper-threading
		cpuinfo.htt = 1;

	if (ecx & (1 << 28)) // AVX
		sprintcat((char *) &flags, "AVX", sizeof(flags));

	if (ecx & (1 << 31)) // Hypervisor
		cpuinfo.hv = 1;

	if (max_level >= 7)
	{
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		if (ebx & (1 << 5)) // AVX2
			sprintcat((char *) &flags, "AVX2", sizeof(flags));

		if (ebx & (1 << 16)) // AVX512F
			sprintcat((char *) &flags, "AVX512F", sizeof(flags));
	}
#elif (defined(__arm__) || defined(__aarch64__)) && defined(HAS_AUXV)
	long hwcaps = getauxval(AT_HWCAP);

#if defined(__aarch64__)
	if (hwcaps & (1 << 1)) sprintcat((char *) &flags, "ASIMD", sizeof(flags));
#else
	if (hwcaps & (1 << 12)) sprintcat((char *) &flags, "NEON", sizeof(flags));

	if (hwcaps & (1 << 1)) sprintcat((char *) &flags, "HALF", sizeof(flags));

	if (hwcaps & (1 << 2)) sprintcat((char *) &flags, "THUMB", sizeof(flags));

	if (hwcaps & (1 << 11))
		sprintcat((char *) &flags, "THUMBEE", sizeof(flags));

	if (hwcaps & (1 << 6)) sprintcat((char *) &flags, "VFP", sizeof(flags));

	if ((hwcaps & (1 << 13)) || (hwcaps & (1 << 14)))
		sprintcat((char *) &flags, "VFPv3", sizeof(flags));

	if (hwcaps & (1 << 16)) sprintcat((char *) &flags, "VFPv4", sizeof(flags));

	if (hwcaps & (1 << 15)) sprintcat((char *) &flags, "TLS", sizeof(flags));

	if (hwcaps & (1 << 10)) sprintcat((char *) &flags, "CRUNCH", sizeof(flags));

	if (hwcaps & (1 << 9)) sprintcat((char *) &flags, "iwMMXt", sizeof(flags));

	if ((hwcaps & (1 << 17)) || (hwcaps & (1 << 18)))
		sprintcat((char *) &flags, "IDIV", sizeof(flags));
#endif
#elif defined(__aarch64__) && !defined(HAS_AUXV)
	sprintcat((char *) &flags, "ASIMD", sizeof(flags));
#endif
	return strdup(flags);
}

static float cpuid_getcoretemp(void)
{
#ifdef __FreeBSD__
	int tempval = 0;
	size_t len = sizeof(tempval);

	if (sysctlbyname("dev.cpu.0.temperature", &tempval, &len, NULL, 0) == -1)
		return 0;

	cpuinfo.coretemp = (tempval - 2732) / 10.0f;
#elif __linux__
	if (cpuinfo.cputemppath != NULL)
	{
		cpuinfo.coretemp
			= (float) cpuid_readsysfs((const char *) cpuinfo.cputemppath)
			  / 1000.0f;
	}
#else
	return 0;
#endif
	return cpuinfo.coretemp;
}

#ifdef __linux__
//
// Locate the primary temp input on the coretemp sysfs
//
static int cpuid_findcpusensorpath(const char * path)
{
#define MAX_SENSOR_PATHS 16
	DIR * dirp;
	struct dirent * dp;
	char tbuf[MAX_SENSOR_PATHS][32] = {{0}};
	int cnt = 0, i = 0, sensorx = 0;
	char sensor[8] = {0};

	dirp = opendir(path);

	if (dirp == NULL) return -1;

	snprintf(sensor, sizeof(sensor), "temp%d", sensorx);

	while (cnt < (MAX_SENSOR_PATHS - 1) && (dp = readdir(dirp)) != NULL)
	{
		if (!strncmp(dp->d_name, sensor, 5))
		{
			(void) closedir(dirp);
			if (asprintf(&cpuinfo.cputemppath,
						 "%stemp%d_input",
						 CORETEMP_PATH,
						 sensorx)
				== -1)
			{
				perror("asprintf");
			}
			return sensorx;
		}
		else if (!strncmp(dp->d_name, "temp", 4))
		{
			ALLEGE(strlcpy(tbuf[cnt], dp->d_name, 32) < 32);
			if (cnt < (MAX_SENSOR_PATHS - 1)) ++cnt; //-V547
		}
	}

	(void) closedir(dirp);

	// Hopefully we found the ID on the first pass, but Linux is its infinite
	// wisdom
	// sometimes starts the sensors at 2-6+
	for (sensorx = 1; sensorx < 8; sensorx++)
		for (i = 0; i < cnt; i++)
		{
			snprintf(sensor, sizeof(sensor), "temp%d", sensorx);

			if (!strncasecmp(tbuf[i], sensor, strlen(sensor)))
			{
				if (asprintf(&cpuinfo.cputemppath,
							 "%stemp%d_input",
							 CORETEMP_PATH,
							 sensorx)
					== -1)
				{
					perror("asprintf");
				}
				return sensorx;
			}
		}

	return -1;
}

static int cpuid_readsysfs(const char * file)
{
	int fd, ival = 0;
	char buf[16] = {0};

	fd = open(file, O_RDONLY);

	if (fd == -1) return -1;

	if (read(fd, &buf, sizeof(buf)) > 0)
	{
		ival = atoi(buf);
	}

	close(fd);

	return ival;
}

//
// Return CPU frequency from scaling governor when supported
//
static int cpuid_getfreq(int type)
{
	int fd, ifreq = 0;
	char freq[16] = {0}, *fptr;

	fptr = (type == 1 ? CPUFREQ_CPU0C : CPUFREQ_CPU0M);

	fd = open(fptr, O_RDONLY);

	if (fd == -1) return 0;

	if (read(fd, &freq, sizeof(freq)) > 0) ifreq = atoi(freq) / 1000;

	close(fd);

	return ifreq;
}
#endif

static char * cpuid_modelinfo(void)
{
#ifdef _X86
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	int bi = 2, broff = 0;
	char * tmpmodel = calloc(1, (size_t)((sizeof(unsigned) * 4ul) * 5ul));
#elif __linux__
	FILE * cfd;
	char *line = NULL, *token = NULL;
	size_t linecap = 0;
	ssize_t linelen;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) /* ARM support for FreeBSD / OpenBSD */
	int mib[] = {CTL_HW, HW_MODEL};
	char modelbuf[64];
	size_t len = sizeof(modelbuf);
#elif defined(__APPLE__) && defined(__aarch64__)
	char modelbuf[128];
	size_t modelbuf_len = sizeof(modelbuf);
#endif
	char *pm = NULL, *model = NULL;

#ifdef _X86
	if (tmpmodel == NULL)
	{
		fprintf(stderr,
				"ERROR: calloc() failed to allocate memory for "
				"cpuid_modelinfo(): %s\n",
				strerror(errno));
		return "Unknown";
	}

	for (; bi < 5; bi++, broff += 16)
	{
		__cpuid(0x80000000 + bi, eax, ebx, ecx, edx);

		memcpy(tmpmodel + broff, &eax, sizeof(unsigned));
		memcpy(tmpmodel + broff + 4, &ebx, sizeof(unsigned));
		memcpy(tmpmodel + broff + 8, &ecx, sizeof(unsigned));
		memcpy(tmpmodel + broff + 12, &edx, sizeof(unsigned));
	}

	pm = tmpmodel;

#elif __linux__
	cfd = fopen("/proc/cpuinfo", "r");

	if (cfd == NULL)
	{
		fprintf(stderr,
				"ERROR: Failed opening /proc/cpuinfo: %s\n",
				strerror(errno));
		return "Unknown";
	}

	while ((linelen = getline(&line, &linecap, cfd)) > 0)
	{
		if (!strncasecmp(line, "model", 5))
		{
			token = strsep(&line, ":");
			token = strsep(&line, ":");

			token[strlen(token) - 1] = 0;
			(void) *token++;

			pm = token;
			break;
		}
	}

	free(line);
	line = NULL;

	fclose(cfd);

	if (pm == NULL) return NULL;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	if (sysctl(mib, 2, modelbuf, &len, NULL, 0))
		snprintf(modelbuf, sizeof(modelbuf), "Unknown");

	pm = modelbuf;
#elif defined(__APPLE__) && defined(__aarch64__)
	if (sysctlbyname("machdep.cpu.brand_string", &modelbuf, &modelbuf_len, NULL, 0))
		snprintf(modelbuf, sizeof(modelbuf), "Unknown Apple AARCH64");

	pm = modelbuf;
#endif

	// Clean up the empty spaces in the model name on some intel's because they
	// let their engineers fall asleep on the space bar
	while (*pm == ' ')
	{
		pm++;
	}

	model = strdup(pm);

#ifdef _X86
	free(tmpmodel);
	tmpmodel = NULL;
#endif

	if (model == NULL)
	{
		fprintf(stderr,
				"ERROR: strdup() failed to allocate memory for "
				"cpuid_modelinfo(): %s\n",
				strerror(errno));
		return "Unknown";
	}

	return model;
}

#ifdef _X86
static inline unsigned cpuid_x86_max_function_id(void)
{
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	__cpuid(0, eax, ebx, ecx, edx);
	return (eax);
}

static inline unsigned cpuid_x86_max_extended_function_id(void)
{
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	__cpuid(0x80000000UL, eax, ebx, ecx, edx);
	return (eax);
}

static unsigned int cpuid_x86_threads_per_core(void);
static unsigned int cpuid_x86_threads_per_core(void)
{
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int mfi = cpuid_x86_max_function_id();
	unsigned int mefi = cpuid_x86_max_extended_function_id();
	const char * vendor = cpuid_vendor();

	if (mfi < 0x04U
		|| (strcmp(vendor, "Intel") != 0 && strcmp(vendor, "AMD") != 0))
	{
		return (1);
	}

	if (strcmp(vendor, "AMD") == 0 && mefi >= 0x8000001EU)
	{
		__cpuid(0x8000001EU, eax, ebx, ecx, edx);
		return (((ebx >> 8U) & 7U) + 1U);
	}

	if (mfi < 0x0BU)
	{
		__cpuid(1, eax, ebx, ecx, edx);
		if ((edx & (1U << 28U)) != 0)
		{
			// v will contain logical core count
			const unsigned v = (ebx >> 16) & 255;
			if (v > 1)
			{
				__cpuid(4, eax, ebx, ecx, edx);
				// physical cores
				const unsigned v2 = (eax >> 26U) + 1U;
				if (v2 > 0)
				{
					return v / v2;
				}
			}
		}

		return (1);
	}

	if (mfi < 0x1FU)
	{
		/*
		CPUID leaf 1FH is a preferred superset to leaf 0BH. Intel
		recommends first checking for the existence of Leaf 1FH
		before using leaf 0BH.
		*/
		__cpuid_count(0x0BU, 0, eax, ebx, ecx, edx);
		if ((ebx & 0xFFFFU) == 0)
		{
			return (1);
		}

		return (ebx & 0xFFFFU);
	}

	__cpuid_count(0x1FU, 0, eax, ebx, ecx, edx);
	if ((ebx & 0xFFFFU) == 0)
	{
		return (1);
	}

	return (ebx & 0xFFFFU);
}

static unsigned int cpuid_x86_logical_cores(void);
static unsigned int cpuid_x86_logical_cores(void)
{
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int mfi = cpuid_x86_max_function_id();
	const char * vendor = cpuid_vendor();

	if (strcmp(vendor, "Intel") == 0)
	{
		// Use this on old Intel processors
		if (mfi < 0x0BU)
		{
			if (mfi < 0x01U)
			{
				return (0);
			}

			__cpuid(1, eax, ebx, ecx, edx);
			return ((ebx >> 16U) & 0xFFU);
		}

		if (mfi < 0x1FU)
		{
			/*
			CPUID leaf 1FH is a preferred superset to leaf 0BH. Intel
			recommends first checking for the existence of Leaf 1FH
			before using leaf 0BH.
			*/
			__cpuid_count(0x0BU, 1, eax, ebx, ecx, edx);
			return (ebx & 0xFFFFU);
		}

		__cpuid_count(0x1FU, 1, eax, ebx, ecx, edx);
		return (ebx & 0xFFFFU);
	}
	else if (strcmp(vendor, "AMD") == 0)
	{
		__cpuid(1, eax, ebx, ecx, edx);
		return ((ebx >> 16U) & 0xFFU);
	}
	else
	{
		return (0);
	}
}

static unsigned int cpuid_x86_physical_cores(void);
static unsigned int cpuid_x86_physical_cores(void)
{
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int mfi = cpuid_x86_max_function_id();
	unsigned int mefi = cpuid_x86_max_extended_function_id();
	const char * vendor = cpuid_vendor();

	if (strcmp(vendor, "Intel") == 0 && mfi >= 0x01U)
	{
		return (cpuid_x86_logical_cores() / cpuid_x86_threads_per_core());
	}
	else if (strcmp(vendor, "AMD") == 0 && mefi >= 0x80000008UL)
	{
		__cpuid(0x80000008UL, eax, ebx, ecx, edx);
		return (((ecx & 0xFFU) + 1U) / cpuid_x86_threads_per_core());
	}

	return (1);
}
#endif

int cpuid_getinfo(void)
{
	int cpu_count = get_nb_cpus();
	float cpu_temp;

#ifdef _X86
	cpuinfo.maxlogic = cpuid_x86_logical_cores();
	cpuinfo.cores = cpuid_x86_physical_cores();

	printf("Vendor          = %s\n", cpuid_vendor());
#else
	cpuinfo.maxlogic = cpu_count;
#endif

#ifdef __linux__
	cpuid_findcpusensorpath(CORETEMP_PATH);
	cpuinfo.cpufreq_cur = cpuid_getfreq(1);
	cpuinfo.cpufreq_max = cpuid_getfreq(2);
#endif

	cpuinfo.model = cpuid_modelinfo();
	cpuinfo.flags = cpuid_featureflags();

	if (cpuinfo.model != NULL) printf("Model           = %s\n", cpuinfo.model);
	if (cpuinfo.flags != NULL) printf("Features        = %s\n", cpuinfo.flags);
	if (cpuinfo.hv) printf("Hypervisor      = Yes (Virtualization detected)\n");

	if (cpuinfo.cpufreq_cur)
		printf("CPU frequency   = %d MHz (Max: %d MHz)\n",
			   cpuinfo.cpufreq_cur,
			   cpuinfo.cpufreq_max);

	cpu_temp = cpuid_getcoretemp();
	if (cpu_temp != 0.0) //-V550
		printf("CPU temperature = %2.2f C\n", cpu_temp);

#ifdef _X86
	printf("Hyper-Threading = %s\n", cpuinfo.htt ? "Yes" : "No");
#endif

	printf("Logical CPUs    = %d\n", cpuinfo.maxlogic);

#ifdef _X86
	printf("Threads per core= %u\n", cpuid_x86_threads_per_core());
#endif

	if (cpuinfo.cores > 0)
	{
		printf("CPU cores       = %d", cpuinfo.cores);

		if (cpuinfo.maxlogic > 0 && cpuinfo.maxlogic != cpu_count)
		{
			if (cpu_count > cpuinfo.maxlogic)
				printf(" (%d total, %d sockets)",
					   cpu_count,
					   (cpu_count / cpuinfo.maxlogic));
			else
				printf(" (%d total)", cpu_count);
		}

		puts("");
	}

	cpuinfo.simdsize = cpuid_simdsize(1);

	printf("SIMD size       = %d ", cpuinfo.simdsize);

	if (cpuinfo.simdsize == 1)
		printf("(64 bit)\n");
	else if (cpuinfo.simdsize == 4)
		printf("(128 bit)\n");
	else if (cpuinfo.simdsize == 8)
		printf("(256 bit)\n");
	else if (cpuinfo.simdsize == 16)
		printf("(512 bit)\n");
	else
		printf("(unknown)\n");

	if (cpuinfo.flags != NULL)
	{
		free(cpuinfo.flags);
		cpuinfo.flags = NULL;
	}

	if (cpuinfo.model != NULL)
	{
		free(cpuinfo.model);
		cpuinfo.model = NULL;
	}

	if (cpuinfo.cputemppath != NULL)
	{
		free(cpuinfo.cputemppath);
		cpuinfo.cputemppath = NULL;
	}

	return 0;
}
