/*
 *  VerifySSID function (UTF-8 supported)
 *
 *  Copyright (C) 2018 ZhaoChunsheng
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "aircrack-ng/utf8/verifyssid.h"

int verifyssid(const unsigned char * s)
{
	int i;
	unsigned char c;

	if (!s || strlen((const char *) s) > 32)
	{ // 32 characters
		return 0;
	}

	for (i = 0; (c = s[i++]);)
	{
		if ((c & 0x80) == 0)
		{ // ascii flag
			if (c < 0x20 || c == 0x7f)
			{
				return 0;
			}
		}
		else if ((c & 0xe0) == 0xc0)
		{ // utf8 flag
			if ((s[i++] & 0xc0) != 0x80)
			{
				return 0;
			}
		}
		else if ((c & 0xf0) == 0xe0)
		{ // utf8 flag
			if ((s[i++] & 0xc0) != 0x80 || (s[i++] & 0xc0) != 0x80)
			{
				return 0;
			}
		}
		else if ((c & 0xf8) == 0xf0)
		{ // utf8 flag
			if ((s[i++] & 0xc0) != 0x80 || (s[i++] & 0xc0) != 0x80
				|| (s[i++] & 0xc0) != 0x80)
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	return 1;
}
