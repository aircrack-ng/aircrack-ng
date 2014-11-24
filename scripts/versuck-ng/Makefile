AC_ROOT		= ../..
include		$(AC_ROOT)/common.mak

SCRIPTS         = versuck-ng
DOCFILES        = README
MP_FILES        = versuck-ng.1

default: all

all:
	@echo "Nothing to do. Run make install"

install: uninstall
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(MP_FILES) $(DESTDIR)$(mandir)
	install -m 755 $(SCRIPTS) $(DESTDIR)$(bindir)

uninstall:
	-rm -f $(DESTDIR)$(bindir)/versuck-ng
	-rm -f $(DESTDIR)$(docdir)/README
	@-$(foreach CUR_MP,$(MP_FILES), rm -f $(DESTDIR)$(mandir)/$(CUR_MP); echo rm -f $(DESTDIR)$(mandir)/$(CUR_MP); ) 

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	@echo Nothing to do.

distclean: clean
	
