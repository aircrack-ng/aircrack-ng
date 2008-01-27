AC_ROOT		= .
include		$(AC_ROOT)/common.mak

SCRIPTS         = airmon-ng airdriver-ng patchchk
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
	install -d $(DESTDIR)$(mandir)
	install -m 644 ./manpages/* $(DESTDIR)$(mandir)

uninstall:
	$(MAKE) -C src $(@)
	-rm -f $(DESTDIR)$(sbindir)/airmon-ng
	-rm -f $(DESTDIR)$(sbindir)/airdriver-ng
	-rm -f $(DESTDIR)$(sbindir)/patchchk
	-rm -f $(DESTDIR)$(mandir)/aircrack-ng.1
	-rm -f $(DESTDIR)$(mandir)/airdecap-ng.1
	-rm -f $(DESTDIR)$(mandir)/airdriver-ng.1
	-rm -f $(DESTDIR)$(mandir)/aireplay-ng.1
	-rm -f $(DESTDIR)$(mandir)/airmon-ng.1
	-rm -f $(DESTDIR)$(mandir)/airodump-ng.1
	-rm -f $(DESTDIR)$(mandir)/airolib-ng.1
	-rm -f $(DESTDIR)$(mandir)/airsev-ng.1
	-rm -f $(DESTDIR)$(mandir)/airtun-ng.1
	-rm -f $(DESTDIR)$(mandir)/buddy-ng.1
	-rm -f $(DESTDIR)$(mandir)/easside-ng.1
	-rm -f $(DESTDIR)$(mandir)/ivstools.1
	-rm -f $(DESTDIR)$(mandir)/kstats.1
	-rm -f $(DESTDIR)$(mandir)/makeivs-ng.1
	-rm -f $(DESTDIR)$(mandir)/packetforge-ng.1
	-rm -f $(DESTDIR)$(mandir)/wesside-ng.1
	-rm -fr $(DESTDIR)$(docdir)

strip:
	$(MAKE) -C src $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	$(MAKE) -C src $(@)

distclean: clean

