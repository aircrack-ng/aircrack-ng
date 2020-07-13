#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "aircrack-ng/adt/circular_buffer.h"

static void test_cbuf_init_and_empty(void ** state)
{
	(void) state;

	// GIVEN
#define	size 64
	uint8_t buffer[size];

	// WHEN
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, 1);

	// THEN
	assert_non_null(cbuf);
	assert_true(circular_buffer_is_empty(cbuf));
	assert_false(circular_buffer_is_full(cbuf));
	assert_int_equal(size, circular_buffer_capacity(cbuf));
	assert_int_equal(0, circular_buffer_size(cbuf));

	// END
#undef size
	circular_buffer_free(cbuf);
}

static void test_cbuf_byte_size_one_element(void ** state)
{
	(void) state;

	// GIVEN
#define	size 2
	uint8_t buffer[size];
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, 1);

	// WHEN
	circular_buffer_put(cbuf, "a", 1);

	// THEN
	assert_int_equal(1, circular_buffer_size(cbuf));
	assert_false(circular_buffer_is_empty(cbuf));
	assert_false(circular_buffer_is_full(cbuf));

	// END
#undef size
	circular_buffer_free(cbuf);
}

static void test_cbuf_byte_size_two_element(void ** state)
{
	(void) state;

	// GIVEN
#define	size 2
	uint8_t buffer[size];
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, 1);

	// WHEN
	circular_buffer_put(cbuf, "a", 1);
	circular_buffer_put(cbuf, "b", 1);

	// THEN
	assert_int_equal(2, circular_buffer_size(cbuf));
	assert_false(circular_buffer_is_empty(cbuf));
	assert_true(circular_buffer_is_full(cbuf));

	// END
#undef size
	circular_buffer_free(cbuf);
}

static void test_cbuf_multibyte_compare_buffer(void ** state)
{
	(void) state;

	// GIVEN
#define	nb_elements 2
#define	elementSize 8
#define	size (nb_elements * elementSize)
	uint8_t buffer[size + 1];
	buffer[size] = 0;
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, elementSize);

	// WHEN
	circular_buffer_put(cbuf, "a1234567", 8);
	circular_buffer_put(cbuf, "b1234567", 8);

	// THEN
	assert_int_equal(nb_elements, circular_buffer_size(cbuf));
	assert_false(circular_buffer_is_empty(cbuf));
	assert_true(circular_buffer_is_full(cbuf));
	assert_string_equal("a1234567b1234567", buffer);

	// END
#undef size
#undef elementSize
#undef nb_elements
	circular_buffer_free(cbuf);
}

static void test_cbuf_multibyte_compare_buffer_of_short_put(void ** state)
{
	(void) state;

	// GIVEN
#define	nb_elements 2
#define	elementSize 8
#define	size (nb_elements * elementSize)
	uint8_t buffer[size + 1];
	buffer[size] = 0;
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, elementSize);

	// WHEN
	circular_buffer_put(cbuf, "a123", 4);
	circular_buffer_put(cbuf, "b1234567", 8);

	// THEN
	assert_int_equal(nb_elements, circular_buffer_size(cbuf));
	assert_false(circular_buffer_is_empty(cbuf));
	assert_true(circular_buffer_is_full(cbuf));
	assert_memory_equal("a123\0\0\0\0b1234567", buffer, size);

	// END
#undef size
#undef elementSize
#undef nb_elements
	circular_buffer_free(cbuf);
}

static void test_cbuf_multibyte_get_first(void ** state)
{
	(void) state;

	// GIVEN
#define	nb_elements 2
#define	elementSize 8
#define	size (nb_elements * elementSize)
	uint8_t buffer[size + 1];
	buffer[size] = 0;
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, elementSize);

	// WHEN
	circular_buffer_put(cbuf, "a123", 4);
	circular_buffer_put(cbuf, "b1234567", 8);

	uint8_t output[size];
	void * p_output = &output[0];
	circular_buffer_get(cbuf, &p_output, 8);

	// THEN
	assert_memory_equal("a123\0\0\0\0", output, 8);

	// END
#undef size
#undef elementSize
#undef nb_elements
	circular_buffer_free(cbuf);
}

static void test_cbuf_multibyte_get_both(void ** state)
{
	(void) state;

	// GIVEN
#define	nb_elements 2
#define	elementSize 8
#define	size (nb_elements * elementSize)
	uint8_t buffer[size + 1];
	buffer[size] = 0;
	cbuf_handle_t cbuf = circular_buffer_init(buffer, size, elementSize);

	// WHEN
	circular_buffer_put(cbuf, "a123", 4);
	circular_buffer_put(cbuf, "b1234567", 8);

	uint8_t output[size];
	void * p_output = &output[0];
	circular_buffer_get(cbuf, &p_output, 8);

	// THEN
	assert_memory_equal("a123\0\0\0\0", output, 8);

	// AND WHEN
	circular_buffer_get(cbuf, &p_output, 8);

	// AND THEN
	assert_memory_equal("b1234567", output, 8);

	// END
#undef size
#undef elementSize
#undef nb_elements
	circular_buffer_free(cbuf);
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cbuf_init_and_empty),
		cmocka_unit_test(test_cbuf_byte_size_one_element),
		cmocka_unit_test(test_cbuf_byte_size_two_element),
		cmocka_unit_test(test_cbuf_multibyte_compare_buffer_of_short_put),
		cmocka_unit_test(test_cbuf_multibyte_compare_buffer),
		cmocka_unit_test(test_cbuf_multibyte_get_first),
		cmocka_unit_test(test_cbuf_multibyte_get_both),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
