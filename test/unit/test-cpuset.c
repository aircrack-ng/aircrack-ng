#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <pthread.h>
#include <cmocka.h>

#include "aircrack-ng/cpu/cpuset.h"

static void test_cpuset_bind_out_of_range(void ** state)
{
	(void) state;

	ac_cpuset_t * cset = ac_cpuset_new();
	assert_non_null(cset);

	ac_cpuset_init(cset);
	ac_cpuset_distribute(cset, 2);

	ac_cpuset_bind_thread_at(cset, pthread_self(), 0);
	// Indices at or past the distributed count must be ignored.
	ac_cpuset_bind_thread_at(cset, pthread_self(), 2);
	ac_cpuset_bind_thread_at(cset, pthread_self(), 3);

	ac_cpuset_destroy(cset);
	ac_cpuset_free(cset);
}

static void test_cpuset_destroy_without_distribute(void ** state)
{
	(void) state;

	ac_cpuset_t * cset = ac_cpuset_new();
	assert_non_null(cset);

	ac_cpuset_init(cset);
	ac_cpuset_bind_thread_at(cset, pthread_self(), 0);
	ac_cpuset_destroy(cset);
	ac_cpuset_free(cset);
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cpuset_bind_out_of_range),
		cmocka_unit_test(test_cpuset_destroy_without_distribute),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
