AC_ROOT		= ..
include		$(AC_ROOT)/common.mak

SCRIPTS         = airmon-ng airdriver-ng

default: all

all:
	@echo Nothing to do
	
install:
	install -m 755 $(SCRIPTS) $(DESTDIR)$(sbindir)

uninstall:
	-rm -f $(DESTDIR)$(sbindir)/airmon-ng
	-rm -f $(DESTDIR)$(sbindir)/airdriver-ng

clean:
	@echo Nothing to do