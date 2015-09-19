AC_ROOT		= ../..
DOCFILES        = README
include		$(AC_ROOT)/common.mak

default: all

all:
	@echo "Nothing to do. Run make install"

install: doc
	python setup.py install --prefix="$(prefix)" --record files.txt

doc:
	$(MAKE) -C man install 
	install -d $(prefix)$(docdir)
	install -d $(prefix)/share/airgraph-ng
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

uninstall: clean
	$(MAKE) -C man $(@)
	cat files.txt | xargs rm -rf
	rm -f files.txt

clean:
	python setup.py clean
	rm -rf build

distclean: clean
