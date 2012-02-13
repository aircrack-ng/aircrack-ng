AC_ROOT		= ../..
include		$(AC_ROOT)/common.mak

#SCRIPTS         = airgraph-ng dump-join
DOCFILES        = README

default: all
all: install doc

install:
	#install -m 755 $(SCRIPTS) $(DESTDIR)$(bindir)
	$(MAKE) -C man $(@)
	#$(MAKE) -C lib $(@)
	python setup.py install

uninstall:
	#$(MAKE) -C lib $(@)
	$(MAKE) -C man $(@)

doc:
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

clean:
	@echo Nothing to do.

distclean: clean
	
