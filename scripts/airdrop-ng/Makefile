AC_ROOT		= ../..
DOCFILES        = README
include		$(AC_ROOT)/common.mak

default: all

all:
	@echo Nothing to do. Run make install

install: doc
	python setup.py install --root="$(DESTDIR)" --prefix="$(prefix)" --record files.txt

doc:
	$(MAKE) -C doc install 

uninstall:
	$(MAKE) -C doc $(@)
	cat files.txt | xargs rm -rf
	rm -f files.txt

clean:
	python setup.py --root="$(DESTDIR)" --prefix="$(prefix)" clean
	rm -rf build

distclean: clean
