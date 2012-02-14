AC_ROOT		= ../..
DOCFILES        = README
include		$(AC_ROOT)/common.mak

default: all
all: install doc 

install:
	python setup.py install --record files.txt

doc:
	$(MAKE) -C man install 
	install -d $(DESTDIR)$(docdir)
	install -m 644 $(DOCFILES) $(DESTDIR)$(docdir)

uninstall:
	$(MAKE) -C man $(@)
	cat files.txt | xargs rm -rf
	rm -f files.txt

clean:
	python setup.py clean
	rm -rf build

distclean: clean
