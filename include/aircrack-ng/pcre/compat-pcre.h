/*
*  Copyright (C) 2023 Andras Gemes <andrasgemes@outlook.com>
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
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
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

#ifndef AIRCRACK_NG_COMPAT_PCRE_H
#define AIRCRACK_NG_COMPAT_PCRE_H

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#elif defined HAVE_PCRE
#include <pcre.h>
#endif

#ifdef HAVE_PCRE2
#define COMPAT_PCRE_COMPILE(pattern, pcreerror, pcreerroffset)                 \
	pcre2_compile((PCRE2_SPTR) (pattern),                                      \
				  PCRE2_ZERO_TERMINATED,                                       \
				  0,                                                           \
				  (pcreerror),                                                 \
				  (pcreerroffset),                                             \
				  NULL)
#elif defined HAVE_PCRE
#define COMPAT_PCRE_COMPILE(pattern, pcreerror, pcreerroffset)                 \
	pcre_compile((pattern), 0, (pcreerror), (pcreerroffset), NULL)
#endif

#ifdef HAVE_PCRE2
#define COMPAT_PCRE_MATCH(regex, essid, length, match_data)                    \
	pcre2_match((regex),                                                       \
				(PCRE2_SPTR) (essid),                                          \
				(int) strnlen((char *) (essid), (length)),                     \
				0,                                                             \
				0,                                                             \
				(match_data),                                                  \
				0)
#elif defined HAVE_PCRE
#define COMPAT_PCRE_MATCH(regex, essid, length, match_data)                    \
	pcre_exec((regex),                                                         \
			  NULL,                                                            \
			  (char *) (essid),                                                \
			  strnlen((char *) (essid), (length)),                             \
			  0,                                                               \
			  0,                                                               \
			  NULL,                                                            \
			  0)
#endif

#ifdef HAVE_PCRE2
#define COMPAT_PCRE_PRINT_ERROR(pcreerroffset, pcreerr)                        \
	printf("Error: regular expression compilation failed at "                  \
		   "offset %zu: %s; aborting\n",                                       \
		   (pcreerroffset),                                                    \
		   (pcreerr))
#elif defined HAVE_PCRE
#define COMPAT_PCRE_PRINT_ERROR(pcreerroffset, pcreerrorbuf)                   \
	printf("Error: regular expression compilation failed at "                  \
		   "offset %d: %s; aborting\n",                                        \
		   (pcreerroffset),                                                    \
		   (pcreerrorbuf))
#endif
#endif //AIRCRACK_NG_COMPAT_PCRE_H
