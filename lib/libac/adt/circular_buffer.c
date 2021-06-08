/**
 * Copyright (C) 2018 Joseph Benden <joe@benden.us>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 **/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/adt/circular_buffer.h"

#ifndef NDEBUG
static inline bool is_power_of_two(size_t n)
{
	REQUIRE(n > 0);

	while ((n % 2) == 0)
	{
		n /= 2;
	}

	if (n == 1) return true;

	return false;
}
#endif

// The definition of our circular buffer is hidden from the API user.
struct circular_buffer_t
{
	uint8_t * buffer; /// Circular buffer's memory location.
	size_t read_pos; /// Current read position, as element index.
	size_t write_pos; /// Current write position, as element index.
	size_t max; /// Number of bytes allocated for whole ring buffer.
	size_t size; /// Number of bytes required for a single element.
};

/*
 * A circular buffer uses the "Virtual Streams" approach, as described on
 * the Ryg blog:
 *
 * https://fgiesen.wordpress.com/2010/12/14/ring-buffers-and-queues/
 */

#define CBUF_BUFFER_POS(cbuf, which)                                           \
	(cbuf->buffer + ((cbuf->which % (cbuf->max / cbuf->size)) * cbuf->size))

static inline void check_invariants(cbuf_handle_t cbuf)
{
#ifdef NDEBUG
	(void) cbuf;
#endif

	// All writes to structure are always ahead of the reads, unless empty.
	INVARIANT(cbuf->write_pos >= cbuf->read_pos);

	// All writes are restricted to the inside of our buffer's region.
	INVARIANT(cbuf->write_pos - cbuf->read_pos <= (cbuf->max / cbuf->size));
}

API_EXPORT cbuf_handle_t circular_buffer_init(uint8_t * buffer,
											  size_t bufferSize,
											  size_t elementSize)
{
	REQUIRE(buffer && bufferSize && elementSize);
	REQUIRE(bufferSize % elementSize == 0);
	REQUIRE(is_power_of_two(bufferSize));

	cbuf_handle_t cbuf = calloc(1, sizeof(circular_buffer_t));
	ALLEGE(cbuf);

	cbuf->buffer = buffer;
	cbuf->max = bufferSize;
	cbuf->size = elementSize;
	circular_buffer_reset(cbuf);

	ENSURE(circular_buffer_is_empty(cbuf));

	return cbuf;
}

API_EXPORT void circular_buffer_free(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);
	cbuf->buffer = NULL;
	free(cbuf);
}

API_EXPORT void circular_buffer_reset(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);

	cbuf->read_pos = 0;
	cbuf->write_pos = 0;
}

API_EXPORT bool circular_buffer_is_empty(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);
	return cbuf->read_pos == cbuf->write_pos;
}

API_EXPORT bool circular_buffer_is_full(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);
	return cbuf->write_pos == (cbuf->read_pos + (cbuf->max / cbuf->size));
}

API_EXPORT size_t circular_buffer_capacity(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);
	return cbuf->max / cbuf->size;
}

API_EXPORT size_t circular_buffer_size(cbuf_handle_t cbuf)
{
	REQUIRE(cbuf);
	return cbuf->write_pos - cbuf->read_pos;
}

API_EXPORT void
circular_buffer_put(cbuf_handle_t cbuf, void const * const data, size_t size)
{
	REQUIRE(cbuf && data && size > 0);
	REQUIRE(size <= cbuf->size);

	memcpy(CBUF_BUFFER_POS(cbuf, write_pos), data, size); // cannot overlap

	if (size < cbuf->size)
	{
		// zero extra buffer bytes
		memset(CBUF_BUFFER_POS(cbuf, write_pos) + size, 0, cbuf->size - size);
	}

	++cbuf->write_pos;

	check_invariants(cbuf);
}

API_EXPORT void
circular_buffer_get(cbuf_handle_t cbuf, void * const * data, size_t size)
{
	REQUIRE(cbuf && data && size > 0);
	REQUIRE(size <= cbuf->size);

	memcpy(*data, CBUF_BUFFER_POS(cbuf, read_pos), size); // cannot overlap

	++cbuf->read_pos;

	check_invariants(cbuf);
}
