AC_ROOT		= ../../..
include		$(AC_ROOT)/common.mak

LIB_FILES	= lib_Airgraphviz.py

ag_lib		= $(DESTDIR)$(bindir)/lib

default: all

all:
	@echo Nothing to do. Run make install
	
install: uninstall
	install -d $(ag_lib)
	install -m 644 $(LIB_FILES) $(ag_lib)

uninstall:
	-rm -f $(ag_lib)/lib_Airgraphviz.py