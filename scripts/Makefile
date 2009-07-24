AC_ROOT		= ..
include		$(AC_ROOT)/common.mak

SCRIPTS         = airmon-ng airdriver-ng airodump-ng-oui-update

default: all

all:
	@echo Nothing to do
	
install:
	install -m 755 $(SCRIPTS) $(DESTDIR)$(sbindir)

uninstall:
	-rm -f $(DESTDIR)$(sbindir)/airmon-ng
	-rm -f $(DESTDIR)$(sbindir)/airdriver-ng
	-rm -f $(DESTDIR)$(sbindir)/airodump-ng-oui-update

clean:
	@echo Nothing to do
