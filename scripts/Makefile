AC_ROOT		= ..
include		$(AC_ROOT)/common.mak

SCRIPTS         = airodump-ng-oui-update
SCRIPTS_LNX	= airmon-ng

default: all

all:
	@echo Nothing to do

install:
	install -m 755 $(SCRIPTS) $(DESTDIR)$(sbindir)
ifeq ($(OSNAME), Linux)
	install -m 755 $(SCRIPTS_LNX) $(DESTDIR)$(sbindir)
endif
ifeq ($(filter FreeBSD GNU-kFreeBSD, $(OSNAME)),)
else
	install -m 755 airmon-ng.freebsd $(DESTDIR)$(sbindir)/airmon-ng
endif
ifeq ($(subst TRUE,true,$(filter TRUE true,$(ext_scripts) $(EXT_SCRIPTS))),true)
	@for i in * ; do \
		if [ -d $$i ] && [ $$i != "." ] && [ $$i != ".." ]; then \
			make -C $$i install DESTDIR=$(DESTDIR) ; \
		fi ; \
	done
endif

uninstall:
	-rm -f $(DESTDIR)$(sbindir)/airmon-ng
	-rm -f $(DESTDIR)$(sbindir)/airdriver-ng
	-rm -f $(DESTDIR)$(sbindir)/airodump-ng-oui-update
	$(MAKE) -C airdrop-ng $(@)
	$(MAKE) -C airgraph-ng $(@)
	$(MAKE) -C airoscript-ng $(@)
	$(MAKE) -C versuck-ng $(@)

clean:
	@echo Nothing to do
