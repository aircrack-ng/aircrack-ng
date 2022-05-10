/*
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
 */

#ifndef AIRCRACK_UTIL_CIRCULAR_QUEUE_H
#define AIRCRACK_UTIL_CIRCULAR_QUEUE_H

#include <aircrack-ng/defs.h>

/**
 * @file circular_queue.h
 *
 * @brief An implementation of a multi-threaded, blocking queue; which
 * internally uses a circular buffer for element storage.
 *
 * @author Joseph Benden <joe@benden.us>
 */

#ifdef __cplusplus
extern "C" {
#endif

/// The type representing the internal data structure for a single
/// blocking circular queue; unaccessible to public API consumers.
typedef struct circular_queue_t circular_queue_t;

/// The type representing a handle to a single blocking circular queue.
typedef circular_queue_t * cqueue_handle_t;

/*!
 * @brief Create a new blocking circular queue.
 * @param[in] buffer A region of memory to be used for element storage.
 * @param[in] bufferSize The number of bytes available at @a buffer.
 * @param[in] elementSize The number of bytes used by a single entry stored.
 * @return A brand-new circular queue handle, else NULL on error.
 */
API_IMPORT cqueue_handle_t circular_queue_init(uint8_t * buffer,
											   size_t bufferSize,
											   size_t elementSize);

/*!
 * @brief Release the memory used by the circular queue.
 * @param[in] cq   The circular queue handle to operate upon.
 *
 * @par
 * The API consumer is expected to release the memory region
 * given to the @a circular_queue_init function, by themselves.
 */
API_IMPORT void circular_queue_free(cqueue_handle_t cq);

/*!
 * @brief Reset the circular queue back to its initial state.
 * @param[in] cq The circular queue handle to operate upon.
 */
API_IMPORT void circular_queue_reset(cqueue_handle_t cq);

/*!
 * @brief Store an entry to the circular queue.
 * @param[in] cq   The circular queue handle to operate upon.
 * @param[in] data A buffer location for which we copy the data in from.
 * @param[in] size The length of the @a data memory buffer. This is
 *                 permitted to be less-than or equal-to the
 *                 element size. If less-than, the remaining bytes
 *                 of the element stored are zeroed.
 *
 * @par
 * The memory location of @a data must not overlap the circular
 * queue's memory location. This is because we internally use
 * the @f memcpy function.
 */
API_IMPORT void
circular_queue_push(cqueue_handle_t cq, void const * const data, size_t size);

/*!
 * @brief Attempts to store an entry to the circular queue, if possible.
 * @param[in] cq   The circular queue handle to operate upon.
 * @param[in] data A buffer location for which we copy the data in from.
 * @param[in] size The length of the @a data memory buffer. This is
 *                 permitted to be less-than or equal-to the
 *                 element size. If less-than, the remaining bytes
 *                 of the element stored are zeroed.
 * @return Result of operation is zero on success.
 *
 * @par
 * The memory location of @a data must not overlap the circular
 * queue's memory location. This is because we internally use
 * the @f memcpy function.
 */
API_IMPORT int circular_queue_try_push(cqueue_handle_t cq,
									   void const * const data,
									   size_t size);

/*!
 * @brief Acquire an entry from the circular queue.
 * @param[in] cq   The circular queue handle to operate upon.
 * @param[in] data A buffer location to which to copy the data out to.
 * @param[in] size The length of the @a data memory buffer. This is
 *                 permitted to be less-than or equal-to the
 *                 element size.
 *
 * @par
 * The memory location of @a data must not overlap the circular
 * queue's memory location. This is because we internally use
 * the @f memcpy function.
 */
API_IMPORT void
circular_queue_pop(cqueue_handle_t cq, void * const * data, size_t size);

/*!
 * @brief Returns whether the circular queue is empty.
 * @param[in] cq The circular queue handle to operate upon.
 * @return A boolean representing the emptiness state of the
 *         circular queue.
 */
API_IMPORT bool circular_queue_is_empty(cqueue_handle_t cq);

/*!
 * @brief Returns whether the circular queue is full.
 * @param[in] cq The circular queue handle to operate upon.
 * @return A boolean representing the fullness state of the
 *         circular queue.
 */
API_IMPORT bool circular_queue_is_full(cqueue_handle_t cq);

#ifdef __cplusplus
}
#endif

#endif
