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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
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

#include <stdlib.h>

#include "crypto_engine_loader.h"

// It must read the disk searching for the availables ones.
EXPORT int ac_crypto_engine_loader_get_available(void)
{
	return 0;
}

/// Caller must deallocate the returned pointer!
EXPORT char *ac_crypto_engine_loader_best_library_for(int flags)
{
	return NULL;
}

EXPORT int ac_crypto_engine_loader_string_to_flags(const char *const str, size_t length)
{
	return 0;
}

/// Caller must NOT deallocate the returned pointer!
/// Caller must NOT use this function simultaneously between threads!
EXPORT const char *ac_crypto_engine_loader_flags_to_string(int flags)
{
	return NULL;
}

/// dlopen's and populates all DSO variables, but if not DYNAMIC these should be the addresses via static init.
EXPORT int ac_crypto_engine_loader_load(int flags)
{
	return 0;
}

/// dlclose's and free's memory used
EXPORT void ac_crypto_engine_loader_unload(void)
{
}