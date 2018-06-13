#include <glib.h>
#include <locale.h>

#if 0
typedef struct {
  MyObject *obj;
  OtherObject *helper;
} MyObjectFixture;

static void
my_object_fixture_set_up (MyObjectFixture *fixture,
						  gconstpointer user_data)
{
	fixture->obj = my_object_new ();
	my_object_set_prop1 (fixture->obj, "some-value");
	my_object_do_some_complex_setup (fixture->obj, user_data);

	fixture->helper = other_object_new ();
}

static void
my_object_fixture_tear_down (MyObjectFixture *fixture,
							 gconstpointer user_data)
{
	g_clear_object (&fixture->helper);
	g_clear_object (&fixture->obj);
}

static void
test_my_object_test1 (MyObjectFixture *fixture,
					  gconstpointer user_data)
{
	g_assert_cmpstr (my_object_get_property (fixture->obj), ==, "initial-value");
}

static void
test_my_object_test2 (MyObjectFixture *fixture,
					  gconstpointer user_data)
{
	my_object_do_some_work_using_helper (fixture->obj, fixture->helper);
	g_assert_cmpstr (my_object_get_property (fixture->obj), ==, "updated-value");
}
#endif

static void
test_my_sanity (void)
{
	g_assert_cmpint(1, ==, 1);
}

int
main (int argc, char *argv[])
{
	setlocale (LC_ALL, "");

	g_test_init (&argc, &argv, NULL);
	g_test_bug_base ("http://bugzilla.gnome.org/show_bug.cgi?id=");

	// Define the tests.
	g_test_add_func ("/sanity/test1", test_my_sanity);

//	g_test_add ("/my-object/test1", MyObjectFixture, "some-user-data",
//				my_object_fixture_set_up, test_my_object_test1,
//				my_object_fixture_tear_down);
//	g_test_add ("/my-object/test2", MyObjectFixture, "some-user-data",
//				my_object_fixture_set_up, test_my_object_test2,
//				my_object_fixture_tear_down);

	return g_test_run ();
}
