#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "aircrack-ng/osdep/byteorder.h"
#include "radiotap/platform.h"
#include "aircrack-ng/support/common.h"

static void test_radiotap_unaligned_access(void ** state)
{
	(void) state;

	const char bytes[] = {0x00, 0x01, 0x02, 0x00};

	assert_true(get_unaligned_le16(bytes + 1) == 0x0201); //-V1032
}

static void test_string_has_suffix(void ** state)
{
	(void) state;

	assert_true(string_has_suffix("", ""));
	assert_true(!string_has_suffix("", "a"));
	assert_true(string_has_suffix("a", ""));
	assert_true(string_has_suffix("a", "a"));
	assert_true(!string_has_suffix("a", "b"));
	assert_true(!string_has_suffix("a", "ba"));
	assert_true(string_has_suffix("abc", "abc"));
	assert_true(!string_has_suffix("abc", "eeabc"));
	assert_true(!string_has_suffix("abc", "xbc"));
	assert_true(!string_has_suffix("abc", "axc"));
	assert_true(!string_has_suffix("abcdef", "abcxef"));
	assert_true(!string_has_suffix("abcdef", "abxxef"));
	assert_true(string_has_suffix("b.a", ""));
	assert_true(string_has_suffix("b.a", "a"));
	assert_true(string_has_suffix("b.a", ".a"));
	assert_true(string_has_suffix("b.a", "b.a"));
	assert_true(!string_has_suffix("b.a", "x"));
	assert_true(string_has_suffix("abc.foo.bar", ""));
	assert_true(string_has_suffix("abc.foo.bar", "r"));
	assert_true(string_has_suffix("abc.foo.bar", "ar"));
	assert_true(string_has_suffix("abc.foo.bar", "bar"));
	assert_true(!string_has_suffix("abc.foo.bar", "xar"));
	assert_true(string_has_suffix("abc.foo.bar", ".bar"));
	assert_true(string_has_suffix("abc.foo.bar", "foo.bar"));
	assert_true(!string_has_suffix("abc.foo.bar", "xoo.bar"));
	assert_true(!string_has_suffix("abc.foo.bar", "foo.ba"));
	assert_true(string_has_suffix("abc.foo.bar", ".foo.bar"));
	assert_true(string_has_suffix("abc.foo.bar", "c.foo.bar"));
	assert_true(string_has_suffix("abc.foo.bar", "abc.foo.bar"));
	assert_true(!string_has_suffix("abc.foo.bar", "xabc.foo.bar"));
	assert_true(!string_has_suffix("abc.foo.bar", "ac.foo.bar"));
	assert_true(string_has_suffix("abc.foo.foo", ".foo"));
	assert_true(string_has_suffix("abc.foo.foo", ".foo.foo"));
	assert_true(string_has_suffix("abcdefgh", ""));
	assert_true(!string_has_suffix("abcdefgh", " "));
	assert_true(string_has_suffix("abcdefgh", "h"));
	assert_true(string_has_suffix("abcdefgh", "gh"));
	assert_true(string_has_suffix("abcdefgh", "fgh"));
	assert_true(!string_has_suffix("abcdefgh", "agh"));
	assert_true(string_has_suffix("abcdefgh", "abcdefgh"));
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_string_has_suffix),
		cmocka_unit_test(test_radiotap_unaligned_access),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
