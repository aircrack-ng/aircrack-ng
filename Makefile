need := 3.81
ok := $(filter $(need),$(firstword $(sort $(MAKE_VERSION) \
	$(need))))
       
ifndef ok
    $(error fatal error... Need make $(need) but using $(MAKE_VERSION), please upgrade)
endif

AC_ROOT		= .
include		$(AC_ROOT)/common.mak

SCRIPTS         = airmon-ng airdriver-ng
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
	install -m 755 $(SCRIPTS) $(DESTDIR)$(sbindir)
	$(MAKE) -C manpages $(@)

uninstall:
	$(MAKE) -C src $(@)
	-rm -f $(DESTDIR)$(sbindir)/airmon-ng
	-rm -f $(DESTDIR)$(sbindir)/airdriver-ng
	-rm -fr $(DESTDIR)$(docdir)
	$(MAKE) -C manpages $(@)

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
	
