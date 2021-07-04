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

#include <pthread.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/adt/circular_buffer.h"
#include "aircrack-ng/adt/circular_queue.h"

// The definition of our circular queue is hidden from the API user.
struct circular_queue_t
{
	cbuf_handle_t cbuf; /// Circular buffer.
	pthread_mutex_t lock; /// Lock protecting whole structure.
#if !defined(__APPLE_CC__) && !defined(__APPLE__)
	// NOTE: On the M1 macOS, the sizes subtract to zero.
	char padding1[CACHELINE_SIZE - sizeof(pthread_mutex_t)];
#endif
	pthread_cond_t full_cv; /// Signals upon no longer full.
#if !defined(__APPLE_CC__) && !defined(__APPLE__)
	// NOTE: On the M1 macOS, the sizes subtract to zero.
	char padding2[CACHELINE_SIZE - sizeof(pthread_cond_t)];
#endif
	pthread_cond_t empty_cv; /// Signals upon no longer empty.
};

API_EXPORT cqueue_handle_t circular_queue_init(uint8_t * buffer,
											   size_t bufferSize,
											   size_t elementSize)
{
	REQUIRE(buffer && bufferSize && elementSize);
	REQUIRE(bufferSize % elementSize == 0);

	cqueue_handle_t cq = calloc(1, sizeof(circular_queue_t));
	ALLEGE(cq);

	cq->cbuf = circular_buffer_init(buffer, bufferSize, elementSize);
	ALLEGE(cq->cbuf);

	ALLEGE(pthread_mutex_init(&(cq->lock), NULL) == 0);
	ALLEGE(pthread_cond_init(&(cq->empty_cv), NULL) == 0);
	ALLEGE(pthread_cond_init(&(cq->full_cv), NULL) == 0);

	return cq;
}

API_EXPORT void circular_queue_free(cqueue_handle_t cq)
{
	REQUIRE(cq);

	circular_buffer_free(cq->cbuf);
	cq->cbuf = NULL;
	ALLEGE(pthread_cond_destroy(&(cq->empty_cv)) == 0);
	ALLEGE(pthread_cond_destroy(&(cq->full_cv)) == 0);
	ALLEGE(pthread_mutex_destroy(&(cq->lock)) == 0);
	free(cq);
}

API_EXPORT void circular_queue_reset(cqueue_handle_t cq)
{
	REQUIRE(cq);

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);
	circular_buffer_reset(cq->cbuf);
	ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);
}

static inline void
do_push(cqueue_handle_t cq, void const * const data, size_t size)
{
	REQUIRE(cq && data && size > 0);
	REQUIRE(!circular_buffer_is_full(cq->cbuf));

	circular_buffer_put(cq->cbuf, data, size);

	ALLEGE(pthread_cond_signal(&(cq->empty_cv)) == 0);
	ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);
}

API_EXPORT void
circular_queue_push(cqueue_handle_t cq, void const * const data, size_t size)
{
	REQUIRE(cq && data && size > 0);

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);

	while (circular_buffer_is_full(cq->cbuf))
	{
		ALLEGE(pthread_cond_wait(&(cq->full_cv), &(cq->lock)) == 0);
	}

	do_push(cq, data, size);
}

API_EXPORT int circular_queue_try_push(cqueue_handle_t cq,
									   void const * const data,
									   size_t size)
{
	REQUIRE(cq && data && size > 0);

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);

	if (circular_buffer_is_full(cq->cbuf))
	{
		ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);
		return -1;
	}

	do_push(cq, data, size);

	return 0;
}

API_EXPORT void
circular_queue_pop(cqueue_handle_t cq, void * const * data, size_t size)
{
	REQUIRE(cq && data && size > 0);

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);

	while (circular_buffer_is_empty(cq->cbuf))
	{
		ALLEGE(pthread_cond_wait(&(cq->empty_cv), &(cq->lock)) == 0);
	}
	ALLEGE(!circular_buffer_is_empty(cq->cbuf));

	circular_buffer_get(cq->cbuf, data, size);

	ALLEGE(pthread_cond_signal(&(cq->full_cv)) == 0);
	ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);
}

API_EXPORT bool circular_queue_is_empty(cqueue_handle_t cq)
{
	REQUIRE(cq);
	bool rc;

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);
	rc = circular_buffer_is_empty(cq->cbuf);
	ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);

	return rc;
}

API_EXPORT bool circular_queue_is_full(cqueue_handle_t cq)
{
	REQUIRE(cq);
	bool rc;

	ALLEGE(pthread_mutex_lock(&(cq->lock)) == 0);
	rc = circular_buffer_is_full(cq->cbuf);
	ALLEGE(pthread_mutex_unlock(&(cq->lock)) == 0);

	return rc;
}
