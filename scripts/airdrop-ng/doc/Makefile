AC_ROOT		= ../../../
include		$(AC_ROOT)/common.mak
DOCFILES = Apple.sample.txt dropRules.conf.example
default: all

all:
	@echo "Nothing to do, run make install" 

uninstall:
	rm -f $(DESTDIR)$(docdir)/Apple.sample.txt  $(DESTDIR)$(docdir)/dropRules.conf.example $(DESTDIR)$(mandir)/airdrop-ng.1

install:
	install -d $(DESTDIR)$(docdir)
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)
	install -m 644 airdrop-ng.1 $(DESTDIR)$(mandir)
