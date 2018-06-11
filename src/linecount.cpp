/*
 *  High speed wordcounting functions for ETA calculations by Len White <lwhite at nrw.ca>
 *
 *  Copyright (C) 2015 Len White <lwhite at nrw.ca>
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
 *
 *  Why is this in C++?
 *
 *  The first several versions of this function were written in C
 *  but when it came to optimizing the speed, I kept hitting brick walls.
 *  mmap() produced favorable results on Linux but when I tested it on
 *  Windows or BSD, it was beyond horrible.  Memory Mapping seems to work
 *  drastically different there, and I even went so far as to write a version
 *  in native Win32 code which helped slightly but was still far slower than
 *  even normal read().
 *
 *  With some people using massive dictionaries 20-25GB in size, it's important
 *  that this function be as efficient, and as portable as possible.  I used
 *  the time command to compare runtime between all my tests; ifstream ifs()
 *  and ifs.read() were at least 30-50% faster than the next best solution
 *  except for mmap() on Linux which beat it out by 3-4% but usually only
 *  on a 2nd run.
 *
 *  A possible alternative to this could be the SFIO library but further
 *  research and testing is required, other big projects like graphviz and perl
 *  make use of it.  This was designed so it's easy to replace if we can
 *  find a better solution performance wise.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <string.h>
#include <sys/types.h>
#include "linecount.h"

using namespace std;

unsigned int FileRead(istream &is, vector <char> &buff) {
	is.read(&buff[0], buff.size());
	return is.gcount();
}

unsigned int countBuffer(const vector <char> &buff, int bufsize) {
	int lines = 0, i = 4;
	const char * p = &buff[0];
	unsigned short charct = 0;

	bufsize--;

	while (i++ < bufsize) {
	    	if (p[i] == '\n') {
			if (charct > 7)
				lines++;

			i	+= 1;
			charct	= 1;
			continue;
	    	}

		charct++;
	}

	return lines;
}

unsigned int linecount(const char *file, off_t offset, size_t offsetmax) {
	const int SZ = READBUF_BLKSIZE;
	std::vector <char> buff(SZ);
	ifstream ifs(file);
	unsigned int n = 0;
	int cc = 0;
	size_t blkcnt = 0;

	if (offset)
		ifs.seekg(offset, ifs.beg);

	// I know doing a redundant loop looks dirty but it's so we don't get a performance penalty
	// inside the loop if we're not using offsetmax, since some files could be 20+ GB this is important.
	if (offsetmax) {
		while ((cc = FileRead(ifs, buff))) {
			n += countBuffer(buff, cc);

			if (blkcnt >= offsetmax)
				return n;

			blkcnt++;
		}
	} else {
		while ((cc = FileRead(ifs, buff))) {
			n += countBuffer(buff, cc);
		}
	}

	return n;
}
