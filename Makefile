need := 3.81
ok := $(filter $(need),$(firstword $(sort $(MAKE_VERSION) \
	$(need))))
       
ifndef ok
    $(error fatal error... Need make $(need) but using $(MAKE_VERSION), please upgrade)
endif

AC_ROOT		= .
include		$(AC_ROOT)/common.mak

DOCFILES        = ChangeLog INSTALLING README LICENSE AUTHORS VERSION


default: all

all:
	$(MAKE) -C src $(@)

aircrack-ng-opt-prof_gen: all
	mkdir -p prof
	$(MAKE) -C src $(@)

aircrack-ng-opt-prof_use:
	$(MAKE) -C src $(@)

install:
	$(MAKE) -C src $(@)
	$(MAKE) -C scripts $(@)
	$(MAKE) -C manpages $(@)

uninstall:
	$(MAKE) -C src $(@)
	-rm -fr $(DESTDIR)$(docdir)
	$(MAKE) -C manpages $(@)
	$(MAKE) -C scripts $(@)

strip:
	$(MAKE) -C src $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	$(MAKE) -C src $(@)

distclean: clean

check: 
	$(MAKE) -C src $(@)
	
