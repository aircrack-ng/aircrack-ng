AC_ROOT		= ../../..
include		$(AC_ROOT)/common.mak

MP_FILES        = airgraph-ng.1 dump-join.1


default: all

all:
	@echo "Nothing to do. Run make install"
	
install: uninstall
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(MP_FILES) $(DESTDIR)$(mandir)

uninstall:
	@-$(foreach CUR_MP,$(MP_FILES), rm -f $(DESTDIR)$(mandir)/$(CUR_MP); echo rm -f $(DESTDIR)$(mandir)/$(CUR_MP); ) 
