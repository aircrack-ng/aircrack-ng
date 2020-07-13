#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "aircrack-ng/adt/circular_queue.h"

static void test_cqueue_init_and_empty(void ** state)
{
	(void) state;

	// GIVEN
#define	size 64
	uint8_t buffer[size];

	// WHEN
	cqueue_handle_t cq = circular_queue_init(buffer, size, 1);

	// THEN
	assert_non_null(cq);
	assert_true(circular_queue_is_empty(cq));
	assert_false(circular_queue_is_full(cq));

	// END
#undef size
	circular_queue_free(cq);
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cqueue_init_and_empty),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
