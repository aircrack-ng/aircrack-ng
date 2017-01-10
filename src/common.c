/*
 *  Common functions for all aircrack-ng tools
 *
 *  Copyright (C) 2006-2017 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#include <sys/user.h>
#endif
#if (defined(_WIN32) || defined(_WIN64)) || defined(__CYGWIN32__)
#include <io.h>
#include <windows.h>
#include <errno.h>
#endif
#define isHex(c) (hexToInt(c) != -1)
#define HEX_BASE 16

/*
 * The following function comes from jumbo.c from JTR.
 * It has the following license:
 *
 * This file is Copyright (c) 2013-2014 magnum, Lukasz and JimF,
 * and is hereby released to the general public under the
following terms:
 * Redistribution and use in source and binary forms, with or
without
 * modifications, are permitted.
*/
#if defined (__CYGWIN32__) && !defined(__CYGWIN64__)
int fseeko64(FILE* fp, int64_t offset, int whence) {
	fpos_t pos;

	if (whence == SEEK_CUR) {
		if (fgetpos (fp, &pos))
			return (-1);

		pos += (fpos_t) offset;
	} else if (whence == SEEK_END) {
		/* If writing, we need to flush before getting file length. */
		long long size;

		fflush (fp);
		size = 0;

		GetFileSizeEx((HANDLE)_get_osfhandle(fileno(fp)), (PLARGE_INTEGER)&size);
		pos = (fpos_t) (size + offset);
	} else if (whence == SEEK_SET)
		pos = (fpos_t) offset;
	else {
		errno = EINVAL;
		return (-1);
	}

	return fsetpos (fp, &pos);
}

int64_t ftello64(FILE * fp) {
	fpos_t pos;

	if (fgetpos(fp, &pos))
		return  -1LL;

	return (int64_t)pos;
}
#endif

/*
 * Print the time and percentage in readable format
 */
void calctime(time_t t, float perc) {
	int days = 0, hours = 0, mins = 0, secs = 0, remain = 0, printed = 0;
	char buf[8];

	days    = t / 86400;
	remain  = t % 86400;

	hours   = remain / 3600;
	remain  = remain % 3600;

	mins    = remain / 60;
	secs    = remain % 60;

	if (days)
		printed += printf("%d day%s, ", days, (days>1?"s":""));

	if (hours)
		printed += printf("%d hour%s, ", hours, (hours>1?"s":""));

	if (mins)
		printed += printf("%d minute%s, ", mins, (mins>1?"s":""));

	snprintf(buf, sizeof(buf), "%3.2f%%", perc);

	printed += printf("%d second%s", secs, (secs!=1?"s":""));

	printf("%*s %s\n", (int)(47-(printed+strlen(buf)%5))," ", buf);
}

int is_string_number(const char * str)
{
	int i;
	if (str == NULL) {
		return 0;
	}

	if (*str != '-' && !(isdigit((int)(*str)))) {
		return 0;
	}

	for (i = 1; str[i] != 0; i++) {
		if (!isdigit((int)(str[i]))) {
			return 0;
		}
	}

	return 1;
}

int get_ram_size(void) {
	int ret = -1;
#if defined(__FreeBSD__)
	int mib[] = { CTL_HW, HW_PHYSMEM };
	size_t len;
	unsigned long physmem;

	len	= sizeof(physmem);

	if (!sysctl(mib, 2, &physmem, &len, NULL, 0))
		ret = (physmem/1024);	// Linux returns memory size in kB, so we want to as well.
#elif defined(_WIN32) || defined(_WIN64)
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);

	GlobalMemoryStatusEx(&statex);
	ret = (int)(statex.ullTotalPhys/1024);
#else
	FILE *fp;
	char str[256];
	int val = 0;

	if (!(fp = fopen("/proc/meminfo", "r"))) {
		perror("fopen fails on /proc/meminfo");
		return ret;
	}

	memset(str, 0x00, sizeof(str));
	while ((fscanf(fp, "%s %d", str, &val)) != 0 && ret == -1) {
		if (!(strncmp(str, "MemTotal", 8))) {
			ret = val;
		}
	}

	fclose(fp);
#endif
	return ret;
}

/* Return the version number */
char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc)
{
	int len;
	char * temp;
	char * provis = calloc(1,20);
	len = strlen(progname) + 200;
	temp = (char *) calloc(1,len);

	snprintf(temp, len, "%s %d.%d", progname, maj, min);

	if (submin > 0) {
		snprintf(provis, 20,".%d",submin);
		strncat(temp, provis, len - strlen(temp));
		memset(provis,0,20);
	}

	if (rc > 0) {
		snprintf(provis, 20, " rc%d", rc);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	} else if (beta > 0) {
		snprintf(provis, 20, " beta%d", beta);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	if (svnrev > 0) {
		snprintf(provis, 20," r%d",svnrev);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	free(provis);
	temp = realloc(temp, strlen(temp)+1);
	return temp;
}

// Return the number of cpu. If detection fails, it will return -1;
int get_nb_cpus()
{
        int number = -1;

#if defined(_WIN32) || defined(_WIN64)
	SYSTEM_INFO sysinfo = {0};

	GetSystemInfo(&sysinfo);

	number = sysinfo.dwNumberOfProcessors;
#elif defined(__linux__)
        char * s, * pos;
        FILE * f;
	// Reading /proc/cpuinfo is more reliable on current CPUs,
	// so put it first and try the old method if this one fails
        f = fopen("/proc/cpuinfo", "r");

        if (f != NULL) {
		s = (char *)calloc(1, 81);

		if (s != NULL) {
			// Get the latest value of "processor" element
			// and increment it by 1 and it that value
			// will be the number of CPU.
			number = -2;

			while (fgets(s, 80, f) != NULL) {
				pos = strstr(s, "processor");

				if (pos == s) {
					pos = strchr(s, ':');
					number = atoi(pos + 1);
				}
			}

			++number;
			free(s);
		}

		fclose(f);
        }
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
// Not sure about defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	int mib[] = { CTL_HW, HW_NCPU };
	size_t len;
	unsigned long nbcpu;

	len     = sizeof(nbcpu);

	if (!sysctl(mib, 2, &nbcpu, &len, NULL, 0)) {
		number = (int)nbcpu;
	}
#endif

        #ifdef _SC_NPROCESSORS_ONLN
        // Try the usual method if _SC_NPROCESSORS_ONLN exist
        if (number == -1) {
		number   = sysconf(_SC_NPROCESSORS_ONLN);
		/* Fails on some archs */
		if (number < 1) {
			number = -1;
		}
        }
        #endif

        return number;
}


//compares two MACs
int maccmp(unsigned char *mac1, unsigned char *mac2)
{
    int i=0;

    if(mac1 == NULL || mac2 == NULL)
        return -1;

    for(i=0; i<6; i++)
    {
        if( toupper(mac1[i]) != toupper(mac2[i]) )
            return -1;
    }
    return 0;
}

// Converts a mac address in a human-readable format
char * mac2string(unsigned char *mac_address )
{
	char * mac_string = (char *)malloc(sizeof(char)*18);
	snprintf(mac_string, 18, "%02X:%02X:%02X:%02X:%02X:%02X", *mac_address,
						*(mac_address+1), *(mac_address+2), *(mac_address+3),
						*(mac_address+4), *(mac_address+5));
	return mac_string;
}

/* Return -1 if it's not an hex value and return its value when it's a hex value */
int hexCharToInt(unsigned char c)
{
	static int table_created = 0;
	static int table[256];

	int i;

	if (table_created == 0)
	{
		/*
		 * It may seem a bit long to calculate the table
		 * but character position depend on the charset used
		 * Example: EBCDIC
		 * but it's only done once and then conversion will be really fast
		 */
		for (i=0; i < 256; i++)
		{

			switch ((unsigned char)i)
			{
				case '0':
					table[i] = 0;
					break;
				case '1':
					table[i] = 1;
					break;
				case '2':
					table[i] = 2;
					break;
				case '3':
					table[i] = 3;
					break;
				case '4':
					table[i] = 4;
					break;
				case '5':
					table[i] = 5;
					break;
				case '6':
					table[i] = 6;
					break;
				case '7':
					table[i] = 7;
					break;
				case '8':
					table[i] = 8;
					break;
				case '9':
					table[i] = 9;
					break;
				case 'A':
				case 'a':
					table[i] = 10;
					break;
				case 'B':
				case 'b':
					table[i] = 11;
					break;
				case 'C':
				case 'c':
					table[i] = 12;
					break;
				case 'D':
				case 'd':
					table[i] = 13;
					break;
				case 'E':
				case 'e':
					table[i] = 14;
					break;
				case 'F':
				case 'f':
					table[i] = 15;
					break;
				default:
					table[i] = -1;
			}
		}

		table_created = 1;
	}

	return table[c];
}

// in: input string
// in_length: length of the string
// out: output string (needs to be already allocated).
// out_length: length of the array
// returns amount of bytes saved to 'out' or -1 if an error happened
int hexStringToArray(char* in, int in_length, unsigned char* out, int out_length)
{
    int i, out_pos;
    int chars[2];

    char *input=in;
    unsigned char *output=out;

    if (in_length < 2 || out_length < (in_length / 3) + 1 || input == NULL || output == NULL)
    	return -1;

    out_pos = 0;
    for (i = 0; i < in_length - 1; ++i)
    {
		if(input[i] == '-' || input[i] == ':' || input[i] == '_' || input[i] == ' ' || input[i] == '.')
		{
			continue;
		}
		// Check output array is big enough
    	if(out_pos >= out_length)
		{
			return -1;
		}
    	chars[0] = hexCharToInt(input[i]);
        // If first char is invalid (or '\0'), don't bother continuing (and you really shouldn't).
        if(chars[0] < 0 || chars[0] > 15)
        	return -1;

        chars[1] = hexCharToInt(input[++i]);
        // It should always be a multiple of 2 hex characters with or without separator
        if(chars[1] < 0 || chars[1] > 15)
            return -1;
        output[out_pos++] = ((chars[0] << 4) + chars[1]) & 0xFF;
    }
    return out_pos;
}

//Return the mac address bytes (or null if it's not a mac address)
int getmac(char * macAddress, int strict, unsigned char * mac)
{
	char byte[3];
	int i, nbElem, n;

	if (macAddress == NULL)
		return 1;

	/* Minimum length */
	if ((int)strlen(macAddress) < 12)
		return 1;

	memset(mac, 0, 6);
	byte[2] = 0;
	i = nbElem = 0;

	while (macAddress[i] != 0)
	{
		if (macAddress[i] == '\n' || macAddress[i] == '\r')
			break;

		byte[0] = macAddress[i];
		byte[1] = macAddress[i+1];

		if (sscanf( byte, "%x", &n ) != 1
			&& strlen(byte) == 2)
			return 1;

		if (hexCharToInt(byte[1]) < 0)
			return 1;

		mac[nbElem] = n;

		i+=2;
		nbElem++;

		if (macAddress[i] == ':' || macAddress[i] == '-'  || macAddress[i] == '_')
			i++;
	}

	if ((strict && nbElem != 6)
		|| (!strict && nbElem > 6))
		return 1;

	return 0;
}

// Read a line of characters inputted by the user
int readLine(char line[], int maxlength)
{
	int c;
	int i = -1;

	do
	{
		// Read char
		c = getchar();

		if (c == EOF)
			c = '\0';

		line[++i] = (char)c;

		if (line[i] == '\n')
			break;
		if (line[i] == '\r')
			break;
		if (line[i] == '\0')
			break;
	}
	while (i + 1 < maxlength);
	// Stop at 'Enter' key pressed or EOF or max number of char read

	// Return current size
    return i;
}

int hexToInt(char s[], int len)
{
	int i = 0;
	int convert = -1;
	int value = 0;

	// Remove leading 0 (and also the second char that can be x or X)

	while (i < len)
	{
		if (s[i] != '0' || (i == 1 && toupper((int)s[i]) != 'X'))
			break;

		++i;
	}

	// Convert to hex

	while (i < len)
	{
		convert = hexCharToInt((unsigned char)s[i]);

		// If conversion failed, return -1
		if (convert == -1)
			return -1;

		value = (value * HEX_BASE) + convert;

		++i;
	}


	return value;
}
