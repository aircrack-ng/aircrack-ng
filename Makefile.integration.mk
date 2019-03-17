
INTEGRATION_TEST_SUITE_LOG = integration-test-suite.log
am__set_INTEGRATION_TESTS_bases = \
	bases='$(INTEGRATION_TEST_LOGS)'; \
	bases=`for i in $$bases; do echo $$i; done | sed 's/\.log$$//'`; \
	bases=`echo $$bases`

am__integration_test_logs1 = $(INTEGRATION_TESTS:=.log)
INTEGRATION_TEST_LOGS = $(am__integration_test_logs1:.log=.log)


# Leading 'am--fnord' is there to ensure the list of targets does not
# expand to empty, as could happen e.g. with make check TESTS=''.
am--fnord $(INTEGRATION_TEST_LOGS) $(INTEGRATION_TEST_LOGS:.log=.trs): $(am__force_recheck)

$(INTEGRATION_TEST_SUITE_LOG): $(INTEGRATION_TEST_LOGS)
	@$(am__set_INTEGRATION_TESTS_bases); \
	am__f_ok () { test -f "$$1" && test -r "$$1"; }; \
	redo_bases=`for i in $$bases; do \
	              am__f_ok $$i.trs && am__f_ok $$i.log || echo $$i; \
	            done`; \
	if test -n "$$redo_bases"; then \
	  redo_logs=`for i in $$redo_bases; do echo $$i.log; done`; \
	  redo_results=`for i in $$redo_bases; do echo $$i.trs; done`; \
	  if $(am__make_dryrun); then :; else \
	    rm -f $$redo_logs && rm -f $$redo_results || exit 1; \
	  fi; \
	fi; \
	if test -n "$$am__remaking_logs"; then \
	  echo "fatal: making $(INTEGRATION_TEST_SUITE_LOG): possible infinite" \
	       "recursion detected" >&2; \
	elif test -n "$$redo_logs"; then \
	  am__remaking_logs=yes $(MAKE) $(AM_MAKEFLAGS) $$redo_logs; \
	fi; \
	if $(am__make_dryrun); then :; else \
	  st=0;  \
	  errmsg="fatal: making $(INTEGRATION_TEST_SUITE_LOG): failed to create"; \
	  for i in $$redo_bases; do \
	    test -f $$i.trs && test -r $$i.trs \
	      || { echo "$$errmsg $$i.trs" >&2; st=1; }; \
	    test -f $$i.log && test -r $$i.log \
	      || { echo "$$errmsg $$i.log" >&2; st=1; }; \
	  done; \
	  test $$st -eq 0 || exit 1; \
	fi
	@$(am__sh_e_setup); $(am__tty_colors); $(am__set_INTEGRATION_TESTS_bases); \
	ws='[ 	]'; \
	results=`for b in $$bases; do echo $$b.trs; done`; \
	test -n "$$results" || results=/dev/null; \
	all=`  grep "^$$ws*:test-result:"           $$results | wc -l`; \
	pass=` grep "^$$ws*:test-result:$$ws*PASS"  $$results | wc -l`; \
	fail=` grep "^$$ws*:test-result:$$ws*FAIL"  $$results | wc -l`; \
	skip=` grep "^$$ws*:test-result:$$ws*SKIP"  $$results | wc -l`; \
	xfail=`grep "^$$ws*:test-result:$$ws*XFAIL" $$results | wc -l`; \
	xpass=`grep "^$$ws*:test-result:$$ws*XPASS" $$results | wc -l`; \
	error=`grep "^$$ws*:test-result:$$ws*ERROR" $$results | wc -l`; \
	if test `expr $$fail + $$xpass + $$error` -eq 0; then \
	  success=true; \
	else \
	  success=false; \
	fi; \
	br='==================='; br=$$br$$br$$br$$br; \
	result_count () \
	{ \
	    if test x"$$1" = x"--maybe-color"; then \
	      maybe_colorize=yes; \
	    elif test x"$$1" = x"--no-color"; then \
	      maybe_colorize=no; \
	    else \
	      echo "$@: invalid 'result_count' usage" >&2; exit 4; \
	    fi; \
	    shift; \
	    desc=$$1 count=$$2; \
	    if test $$maybe_colorize = yes && test $$count -gt 0; then \
	      color_start=$$3 color_end=$$std; \
	    else \
	      color_start= color_end=; \
	    fi; \
	    echo "$${color_start}# $$desc $$count$${color_end}"; \
	}; \
	create_testsuite_report () \
	{ \
	  result_count $$1 "TOTAL:" $$all   "$$brg"; \
	  result_count $$1 "PASS: " $$pass  "$$grn"; \
	  result_count $$1 "SKIP: " $$skip  "$$blu"; \
	  result_count $$1 "XFAIL:" $$xfail "$$lgn"; \
	  result_count $$1 "FAIL: " $$fail  "$$red"; \
	  result_count $$1 "XPASS:" $$xpass "$$red"; \
	  result_count $$1 "ERROR:" $$error "$$mgn"; \
	}; \
	{								\
	  echo "$(PACKAGE_STRING): $(subdir)/$(INTEGRATION_TEST_SUITE_LOG)" |	\
	    $(am__rst_title);						\
	  create_testsuite_report --no-color;				\
	  echo;								\
	  echo ".. contents:: :depth: 2";				\
	  echo;								\
	  for b in $$bases; do echo $$b; done				\
	    | $(am__create_global_log);					\
	} >$(INTEGRATION_TEST_SUITE_LOG).tmp || exit 1;				\
	mv $(INTEGRATION_TEST_SUITE_LOG).tmp $(INTEGRATION_TEST_SUITE_LOG);			\
	if $$success; then						\
	  col="$$grn";							\
	 else								\
	  col="$$red";							\
	  test x"$$VERBOSE" = x || cat $(INTEGRATION_TEST_SUITE_LOG);		\
	fi;								\
	echo "$${col}$$br$${std}"; 					\
	echo "$${col}Integration test-suite summary for $(PACKAGE_STRING)$${std}";	\
	echo "$${col}$$br$${std}"; 					\
	create_testsuite_report --maybe-color;				\
	echo "$$col$$br$$std";						\
	if $$success; then :; else					\
	  echo "$${col}See $(subdir)/$(INTEGRATION_TEST_SUITE_LOG)$${std}";		\
	  if test -n "$(PACKAGE_BUGREPORT)"; then			\
	    echo "$${col}Please report to $(PACKAGE_BUGREPORT)$${std}";	\
	  fi;								\
	  echo "$$col$$br$$std";					\
	fi;								\
	$$success || exit 1

integration-TESTS:
	@list='$(RECHECK_LOGS)';           test -z "$$list" || rm -f $$list
	@list='$(RECHECK_LOGS:.log=.trs)'; test -z "$$list" || rm -f $$list
	@test -z "$(INTEGRATION_TEST_SUITE_LOG)" || rm -f $(INTEGRATION_TEST_SUITE_LOG)
	@set +e; $(am__set_INTEGRATION_TESTS_bases); \
	log_list=`for i in $$bases; do echo $$i.log; done`; \
	trs_list=`for i in $$bases; do echo $$i.trs; done`; \
	log_list=`echo $$log_list`; trs_list=`echo $$trs_list`; \
	for b in $$bases; do \
		p='$$b$(EXEEXT)'; \
		$(am__check_pre) $(LOG_DRIVER) --test-name "$$b" \
		--log-file $$b.log --trs-file $$b.trs \
		$(am__common_driver_flags) $(AM_LOG_DRIVER_FLAGS) $(LOG_DRIVER_FLAGS) -- $(LOG_COMPILE) \
		"$$b" $(AM_TESTS_FD_REDIRECT); \
	done; \
	$(MAKE) $(AM_MAKEFLAGS) $(INTEGRATION_TEST_SUITE_LOG) TEST_LOGS="$$log_list"; \
	exit $$?;

integration:
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS) $(integration_PROGRAMS)
	$(MAKE) $(AM_MAKEFLAGS) integration-TESTS

mostlyclean-local:
	-test -z "$(INTEGRATION_TEST_LOGS)" || rm -f $(INTEGRATION_TEST_LOGS)
	-test -z "$(INTEGRATION_TEST_LOGS:.log=.trs)" || rm -f $(INTEGRATION_TEST_LOGS:.log=.trs)
	-test -z "$(INTEGRATION_TEST_SUITE_LOG)" || rm -f $(INTEGRATION_TEST_SUITE_LOG)
