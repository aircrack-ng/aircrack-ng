/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, Mike Freemon <mike@freemon.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <sys/param.h>
#include <string.h>

#include "stringlib/string.h"

/*
 * Copy the string at src to dest
 *
 * Truncates the string being copied if it will not fit into the dest buffer.
 * The resulting string at dest is always null terminated.
 *
 * Truncation can be identified in the following way:
 *   size_t bytes_copied = copy_string(dest, sizeof(dest), src);
 *   bool is_truncated = (bytes_copied != strlen(src));
 *
 * Arguments
 *   dest: destination buffer
 *   dest_bufsz: the size of the destination buffer
 *   src: source buffer
 *
 * Returns
 *   The number of bytes copied
 */
size_t copy_string(char * dest, size_t dest_bufsz, const char * src)
{
	if (dest == NULL) return 0;
	if (dest_bufsz == 0) return 0;

	if (dest_bufsz == 1) {
		// only one result is possible here
		dest[0] = '\0';
		return 0;
	}

	if (src == NULL) {
		dest[0] = '\0';
		return 0;
	}

	size_t src_str_len = strlen(src);
	size_t num_bytes_to_copy = MIN(src_str_len, (dest_bufsz - 1));

	if (num_bytes_to_copy > 0) {
		memmove(dest, src, num_bytes_to_copy);
	}
	dest[num_bytes_to_copy] = '\0';

	return num_bytes_to_copy;
}

/*
 * Concatenate the string at src to the end of the string at dest
 *
 * Truncates the string being copied if it will not fit into the dest buffer.
 * The result string at dest is always null terminated.
 *
 * Truncation can be identified in the following way:
 *   size_t bytes_copied = concat_string(dest, sizeof(dest), src);
 *   bool is_truncated = (bytes_copied != strlen(src));
 *
 * Arguments
 *   dest: destination buffer
 *   dest_bufsz: the size of the destination buffer
 *   src: source buffer
 *
 * Returns
 *   The number of bytes copied
 */
size_t concat_string(char * dest, size_t dest_bufsz, const char * src)
{
	if (dest == NULL) return 0;
	if (dest_bufsz == 0) return 0;

	size_t dest_str_len = strnlen(dest, dest_bufsz);
	if (dest_str_len == dest_bufsz) {
		// there is no null terminator in the dest str
		dest[dest_bufsz - 1] = '\0';
		return 0;
	}

	if (src == NULL) {
		// we know dest is already correctly null terminated
		return 0;
	}

	size_t src_str_len = strlen(src);

	size_t num_bytes_to_copy = MIN(src_str_len, (dest_bufsz - dest_str_len - 1));

	if (num_bytes_to_copy > 0) {
		memmove(dest + dest_str_len, src, num_bytes_to_copy);
	}
	dest[dest_str_len + num_bytes_to_copy] = '\0';

	return num_bytes_to_copy;
}
