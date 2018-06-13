# GLIB - Library of useful C routines

AM_TESTS_ENVIRONMENT= \
	G_TEST_SRCDIR="$(abs_srcdir)" 		\
	G_TEST_BUILDDIR="$(abs_builddir)" 	\
	G_DEBUG=gc-friendly 			\
	MALLOC_CHECK_=2 			\
	MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256))
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tap-driver.sh
LOG_COMPILER = $(top_srcdir)/tap-test

NULL =

# initialize variables for unconditional += appending
BUILT_SOURCES =
BUILT_EXTRA_DIST =
CLEANFILES = *.log *.trs
DISTCLEANFILES =
MAINTAINERCLEANFILES =
EXTRA_DIST =
TESTS =

installed_testdir =
installed_test_metadir =
installed_test_LTLIBRARIES =
installed_test_PROGRAMS =
installed_test_SCRIPTS =
nobase_installed_test_DATA =

noinst_LTLIBRARIES =
noinst_PROGRAMS =
noinst_SCRIPTS =
noinst_DATA =

check_LTLIBRARIES =
check_PROGRAMS =
check_SCRIPTS =
check_DATA =

# We support a fairly large range of possible variables.  It is expected that all types of files in a test suite
# will belong in exactly one of the following variables.
#
# First, we support the usual automake suffixes, but in lowercase, with the customary meaning:
#
#   test_programs, test_scripts, test_data, test_ltlibraries
#
# The above are used to list files that are involved in both uninstalled and installed testing.  The
# test_programs and test_scripts are taken to be actual testcases and will be run as part of the test suite.
# Note that _data is always used with the nobase_ automake variable name to ensure that installed test data is
# installed in the same way as it appears in the package layout.
#
# In order to mark a particular file as being only for one type of testing, use 'installed' or 'uninstalled',
# like so:
#
#   installed_test_programs, uninstalled_test_programs
#   installed_test_scripts, uninstalled_test_scripts
#   installed_test_data, uninstalled_test_data
#   installed_test_ltlibraries, uninstalled_test_ltlibraries
#
# Additionally, we support 'extra' infixes for programs and scripts.  This is used for support programs/scripts
# that should not themselves be run as testcases (but exist to be used from other testcases):
#
#   test_extra_programs, installed_test_extra_programs, uninstalled_test_extra_programs
#   test_extra_scripts, installed_test_extra_scripts, uninstalled_test_extra_scripts
#
# Additionally, for _scripts and _data, we support the customary dist_ prefix so that the named script or data
# file automatically end up in the tarball.
#
#   dist_test_scripts, dist_test_data, dist_test_extra_scripts
#   dist_installed_test_scripts, dist_installed_test_data, dist_installed_test_extra_scripts
#   dist_uninstalled_test_scripts, dist_uninstalled_test_data, dist_uninstalled_test_extra_scripts
#
# Note that no file is automatically disted unless it appears in one of the dist_ variables.  This follows the
# standard automake convention of not disting programs scripts or data by default.
#
# test_programs, test_scripts, uninstalled_test_programs and uninstalled_test_scripts (as well as their disted
# variants) will be run as part of the in-tree 'make check'.  These are all assumed to be runnable under
# gtester.  That's a bit strange for scripts, but it's possible.

TESTS += $(test_programs) $(test_scripts) $(uninstalled_test_programs) $(uninstalled_test_scripts) \
         $(dist_test_scripts) $(dist_uninstalled_test_scripts)

# Note: build even the installed-only targets during 'make check' to ensure that they still work.
# We need to do a bit of trickery here and manage disting via EXTRA_DIST instead of using dist_ prefixes to
# prevent automake from mistreating gmake functions like $(wildcard ...) and $(addprefix ...) as if they were
# filenames, including removing duplicate instances of the opening part before the space, eg. '$(addprefix'.
all_test_programs     = $(test_programs) $(uninstalled_test_programs) $(installed_test_programs) \
                        $(test_extra_programs) $(uninstalled_test_extra_programs) $(installed_test_extra_programs)
all_test_scripts      = $(test_scripts) $(uninstalled_test_scripts) $(installed_test_scripts) \
                        $(test_extra_scripts) $(uninstalled_test_extra_scripts) $(installed_test_extra_scripts)
all_dist_test_scripts = $(dist_test_scripts) $(dist_uninstalled_test_scripts) $(dist_installed_test_scripts) \
                        $(dist_test_extra_scripts) $(dist_uninstalled_test_extra_scripts) $(dist_installed_test_extra_scripts)
all_test_scripts     += $(all_dist_test_scripts)
EXTRA_DIST           += $(all_dist_test_scripts)
all_test_data         = $(test_data) $(uninstalled_test_data) $(installed_test_data)
all_dist_test_data    = $(dist_test_data) $(dist_uninstalled_test_data) $(dist_installed_test_data)
all_test_data        += $(all_dist_test_data)
EXTRA_DIST           += $(all_dist_test_data)
all_test_ltlibs       = $(test_ltlibraries) $(uninstalled_test_ltlibraries) $(installed_test_ltlibraries)

#if ENABLE_ALWAYS_BUILD_TESTS
#noinst_LTLIBRARIES += $(all_test_ltlibs)
#noinst_PROGRAMS += $(all_test_programs)
#noinst_SCRIPTS += $(all_test_scripts)
#noinst_DATA += $(all_test_data)
#else
check_LTLIBRARIES += $(all_test_ltlibs)
check_PROGRAMS += $(all_test_programs)
check_SCRIPTS += $(all_test_scripts)
check_DATA += $(all_test_data)
#endif

if ENABLE_INSTALLED_TESTS
installed_test_PROGRAMS += $(test_programs) $(installed_test_programs) \
                          $(test_extra_programs) $(installed_test_extra_programs)
installed_test_SCRIPTS += $(test_scripts) $(installed_test_scripts) \
                          $(test_extra_scripts) $(installed_test_extra_scripts)
installed_test_SCRIPTS += $(dist_test_scripts) $(dist_test_extra_scripts) \
                          $(dist_installed_test_scripts) $(dist_installed_test_extra_scripts)
nobase_installed_test_DATA += $(test_data) $(installed_test_data)
nobase_installed_test_DATA += $(dist_test_data) $(dist_installed_test_data)
installed_test_LTLIBRARIES += $(test_ltlibraries) $(installed_test_ltlibraries)
installed_testcases = $(test_programs) $(installed_test_programs) \
                      $(test_scripts) $(installed_test_scripts) \
                      $(dist_test_scripts) $(dist_installed_test_scripts)

installed_test_meta_DATA = $(installed_testcases:=.test)

%.test: %$(EXEEXT) Makefile
	$(AM_V_GEN) ($(MKDIR_P) $(@D); \
	echo '[Test]' > $@.tmp; \
	echo 'Type=session' >> $@.tmp; \
	echo 'Exec=$(installed_testdir)/$(notdir $<) --tap' >> $@.tmp; \
	echo 'Output=TAP' >> $@.tmp; \
	mv $@.tmp $@)

CLEANFILES += $(installed_test_meta_DATA)
endif
