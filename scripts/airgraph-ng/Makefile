AC_ROOT		= ../..
include		$(AC_ROOT)/common.mak

SCRIPTS         = airgraph-ng dump-join
DOCFILES        = README

default: all

all:
	@echo Nothing to do. Run make install

install:
	install -m 755 $(SCRIPTS) $(DESTDIR)$(bindir)
	$(MAKE) -C man $(@)
	$(MAKE) -C lib $(@)

uninstall:
	-rm -f $(DESTDIR)$(bindir)/airgraph-ng
	-rm -f $(DESTDIR)$(bindir)/dump-join
	-rm -f $(DESTDIR)$(docdir)/README
	$(MAKE) -C lib $(@)
	$(MAKE) -C man $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	@echo Nothing to do.

distclean: clean
	
