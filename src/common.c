/*
 *  Common functions for all aircrack-ng tools
 *
 *  Copyright (C) 2006,2007 Thomas d'Otreppe
 *
 *  WEP decryption attack (chopchop) developped by KoreK
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

#if defined(linux)
//Check if the driver is ndiswrapper */
int is_ndiswrapper(const char * iface, const char * path)
{
	int n, pid, unused;
	if ((pid=fork())==0)
	{
		close( 0 ); close( 1 ); close( 2 ); unused = chdir( "/" );
		execl(path, "iwpriv",iface, "ndis_reset", NULL);
		exit( 1 );
	}

	waitpid( pid, &n, 0 );
	return ( ( WIFEXITED(n) && WEXITSTATUS(n) == 0 ));
}
#endif /* linux */

/* Return the version number */
char * getVersion(char * progname, int maj, int min, int submin, int svnrev)
{
	char * temp;
	char * provis = calloc(1,20);
	temp = (char *) calloc(1,strlen(progname)+50);
	sprintf(temp, "%s %d.%d", progname, maj, min);
	if (submin > 0) {
		sprintf(provis,".%d",submin);
		strcat(temp,provis);
		memset(provis,0,20);
	}
	if (svnrev > 0) {
		sprintf(provis," r%d",svnrev);
		strcat(temp,provis);
	}
	free(provis);
	temp = realloc(temp, strlen(temp)+1);
	return temp;
}

/* Search a file recursively */

char * searchInside(const char * dir, const char * filename)
{
	char * ret;
	char * curfile;
	struct stat sb;
	int len, lentot;
	DIR *dp;
	struct dirent *ep;

	len = strlen(filename);
	lentot = strlen(dir) + 256 + 2;
	curfile = (char *)calloc(1, lentot);
	dp = opendir(dir);
	if (dp == NULL)
		return NULL;
	while ((ep = readdir(dp)) != NULL)
	{

		memset(curfile, 0, lentot);
		sprintf(curfile, "%s/%s", dir, ep->d_name);

		//Checking if it's the good file
		if ((int)strlen( ep->d_name) == len && !strcmp(ep->d_name, filename))
		{
			(void)closedir(dp);
			return curfile;
		}
		lstat(curfile, &sb);

		//If it's a directory and not a link, try to go inside to search
		if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
		{
			//Check if the directory isn't "." or ".."
			if (strcmp(".", ep->d_name) && strcmp("..", ep->d_name))
			{
				//Recursive call
				ret = searchInside(curfile, filename);
				if (ret != NULL)
				{
					(void)closedir(dp);
					return ret;
				}
			}
		}
	}
	(void)closedir(dp);
	return NULL;
}

#if defined(linux)
/* Search a wireless tool and return its path */
char * wiToolsPath(const char * tool)
{
	char * path;
	int i, nbelems;
	static const char * paths [] = {
		"/sbin",
		"/usr/sbin",
		"/usr/local/sbin",
		"/bin",
		"/usr/bin",
		"/usr/local/bin",
		"/tmp"
	};

	nbelems = sizeof(paths) / sizeof(char *);

	for (i = 0; i < nbelems; i++)
	{
		path = searchInside(paths[i], tool);
		if (path != NULL)
			return path;
	}

	return NULL;
}
#endif

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
		byte[0] = macAddress[i];
		byte[1] = macAddress[i+1];

		if (sscanf( byte, "%x", &n ) != 1
			&& strlen(byte) == 2)
			return 1;

		if (!(isdigit(byte[1]) || (toupper(byte[1])>='A' && toupper(byte[1])<='F')))
			return 1;
		mac[nbElem] = n;
		i+=2;
		nbElem++;
		if (macAddress[i] == ':' || macAddress[i] == '-')
			i++;
	}

	if ((strict && nbElem != 6)
		|| (!strict && nbElem > 6))
		return 1;

	return 0;
}
