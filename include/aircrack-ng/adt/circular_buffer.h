/**
 * Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
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

#ifndef AIRCRACK_UTIL_CIRCULAR_BUFFER_H
#define AIRCRACK_UTIL_CIRCULAR_BUFFER_H

#include <aircrack-ng/defs.h>

/**
 * @file circular_buffer.h
 *
 * @brief An implementation of a non-thread-safe circular buffer.
 *
 * @author Joseph Benden <joe@benden.us>
 */

#ifdef __cplusplus
extern "C" {
#endif

/// The type representing the internal data structure for a single
/// circular buffer; unaccessible to public API consumers.
typedef struct circular_buffer_t circular_buffer_t;

/// The type representing a handle to a single circular buffer.
typedef circular_buffer_t * cbuf_handle_t;

/*!
 * @brief Create a new circular buffer.
 * @param[in] buffer A region of memory to be used for element storage.
 * @param[in] bufferSize The number of bytes available at @a buffer.
 * @param[in] elementSize The number of bytes used by a single entry stored.
 * @return A brand-new circular buffer handle, else NULL on error.
 */
API_IMPORT cbuf_handle_t circular_buffer_init(uint8_t * buffer,
											  size_t bufferSize,
											  size_t elementSize);

/*!
 * @brief Release the memory used by the circular buffer.
 * @param[in] cbuf The circular buffer handle to operate upon.
 *
 * @par
 * The API consumer is expected to release the memory region
 * given to the @a circular_buffer_init function, by themselves.
 */
API_IMPORT void circular_buffer_free(cbuf_handle_t cbuf);

/*!
 * @brief Reset the circular buffer back to its' initial state.
 * @param[in] cbuf The circular buffer handle to operate upon.
 */
API_IMPORT void circular_buffer_reset(cbuf_handle_t cbuf);

/*!
 * @brief Store an entry to the circular buffer.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @param[in] data A buffer location for which we copy the data in from.
 * @param[in] size The length of the @a data memory buffer. This is
 *                 permitted to be less-than or equal-to the
 *                 element size. If less-than, the remaining bytes
 *                 of the element store are zeroed.
 *
 * @par
 * The memory location of @a data must not overlap the circular
 * buffer's memory location. This is because we internally use
 * the @f memcpy function.
 */
API_IMPORT void
circular_buffer_put(cbuf_handle_t cbuf, void const * const data, size_t size);

/*!
 * @brief Acquire an entry from the circular buffer.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @param[in] data A buffer location to which to copy the data out to.
 * @param[in] size The length of the @a data memory buffer. This is
 *                 permitted to be less-than or equal-to the
 *                 element size.
 *
 * @par
 * The memory location of @a data must not overlap the circular
 * buffer's memory location. This is because we internally use
 * the @f memcpy function.
 */
API_IMPORT void
circular_buffer_get(cbuf_handle_t cbuf, void * const * data, size_t size);

/*!
 * @brief Returns whether the circular buffer is empty.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @return A boolean representing the emptiness state of the
 *         circular buffer.
 */
API_IMPORT bool circular_buffer_is_empty(cbuf_handle_t cbuf);

/*!
 * @brief Returns whether the circular buffer is full.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @return A boolean representing the fullness state of the
 *         circular buffer.
 */
API_IMPORT bool circular_buffer_is_full(cbuf_handle_t cbuf);

/*!
 * @brief Returns the number of storable entries.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @return The number of entries that may be stored within the
 *         circular buffer.
 */
API_IMPORT size_t circular_buffer_capacity(cbuf_handle_t cbuf);

/*!
 * @brief Returns the number of currently stored entries.
 * @param[in] cbuf The circular buffer handle to operate upon.
 * @return The number of entries within the circular buffer.
 */
API_IMPORT size_t circular_buffer_size(cbuf_handle_t cbuf);

#ifdef __cplusplus
}
#endif

#endif
