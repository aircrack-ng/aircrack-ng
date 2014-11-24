#!/usr/bin/make
# Configure prefix here:
prefix=$(DESTDIR)/usr/local/
etcdir=$(DESTDIR)/usr/local/etc/
name="airoscript-ng"

INSTALL = install -c
INSTALLDATA = install -c -m 644
INSTALLBIN = install -c -m 755

data=$(prefix)/share
bindir=$(prefix)/sbin/
picdir=$(data)/pixmaps/
appdir=$(data)/applications/
locale=$(data)/locale
mandir=$(data)/man
docdir=$(data)/doc/$(name)
datadir=$(data)/$(name)/
srcdir=./src

install: installdirs\
	 install-binary \
	 install-config \
	 install-docs \
	 install-locale \
	 install-desktop


installdirs:
	@$(SHELL) ./.mkinstalldirs $(bindir) $(datadir) \
        			$(docdir)/html/images $(etcdir) \
        			$(docdir)/html/css \
                    $(mandir)/man1 $(locale) \
					$(datadir)/themes $(picdir) $(appdir) \
					$(datadir)/plugins \
					$(datadir)/extras \
					$(datadir)/templates

install-config:
	@$(INSTALLDATA) $(srcdir)/conf/airoscript-ng.conf $(etcdir)
	@$(INSTALLDATA) $(srcdir)/conf/airoscript-ng_debug.conf $(etcdir)
	@$(INSTALLDATA) $(srcdir)/conf/airoscript-ng_advanced.conf $(etcdir)
ifeq ($(package),yes)
	@$(INSTALLDATA) $(srcdir)/conf/airoscript-ng_packaged.conf $(etcdir)
endif

install-binary:
	@echo "Installing airoscript"
	@$(INSTALLBIN) $(srcdir)/airoscript-ng $(bindir)/$(name)
	@cp -r $(srcdir)/functions/* $(datadir)
	@echo "Installing themes"
	@cp -r $(srcdir)/templates/* $(datadir)/templates
	@$(INSTALLDATA) $(srcdir)/themes/*.theme $(datadir)/themes
	@echo "Installing plugins"
	@$(INSTALLDATA) $(srcdir)/plugins/* $(datadir)/plugins
	@echo "Installing extras"
	@cp -r $(srcdir)/extras/* $(datadir)/extras
	@cp -r $(srcdir)/extras/completions/* $(datadir)/extras/completions

install-docs:
	@echo "Installing documentation"
	@echo "\t Installing standard documentation"
	@for i in doc/* ; do if [ -d $$i ] && [ $$i != "." ] && [ $$i != ".." ]; then make -s -C $$i docdir="$(docdir)" INSTALLDATA="$(INSTALLDATA)" ; else $(INSTALLDATA) $$i $(docdir) ;fi ; done
	@# This will install any manpage on manpages dir. (Just man1 manpages)
	@echo  "\t Installing manpages"
	@for i in $(docdir)/*.1 ; do $(INSTALLDATA) $$i $(mandir)/man1/ ; done
	@echo "\t Installing artwork"
	@$(INSTALLDATA) $(srcdir)/goodies/airoscriptlogo.png $(docdir)/airoscript-ng.png

install-desktop:
	@install $(srcdir)/goodies/airoscript-ng.desktop $(appdir)/
	@install $(srcdir)/goodies/airoscript-ng_gtk.desktop $(appdir)/
	@$(INSTALLDATA) src/goodies/airoscriptlogo.png $(picdir)/airoscript-ng.png
	@xdg-desktop-menu install $(appdir)/airoscript-ng.desktop
	@xdg-desktop-menu install $(appdir)/airoscript-ng_gtk.desktop

generate-locale:
	@for i in $(srcdir)/locale/* ; do \
		if [ -d $$i ] && [ $$i != "." ] && [ $$i != ".." ]; then \
			make -s -C $$i &> /dev/null ; \
		fi ; \
	done

install-locale: generate-locale
	@echo "Installing locales"
	@for i in $(srcdir)/locale/* ; do \
		if [ -d $$i ] && [ $$i != "." ] && [ $$i != ".." ]; then \
			make -s -C $$i install localedir="$(locale)" INSTALLDATA="$(INSTALLDATA)" ; \
		fi ; \
	done

uninstall:
	@rm -f $(bindir)/$(name)
	@rm -f $(etcdir)/airoscript-ng*.conf
	@rm -rf $(datadir)
	@rm -rf $(docdir)
	@rm -f $(mandir)/man1/airoscript-ng.1
	@rm -f $(picdir)/airoscript-ng.png $(picdir)/airoscript-ng.desktop $(picdir)/airoscript-ng_gtk.desktop
	@for i in $(docdir)/*.1 ; do rm -rf $(mandir)/man1/$$i ; done
	@for i in $(srcdir)/locale/* ; do \
		if [ -d $$i ] && [ $$i != "." ] && [ $$i != ".." ]; then \
			make -s -C $$i uninstall localedir="$(locale)" ; \
		fi ; \
	done
	@echo "Uninstalled succesfully"

all: install

.PHONY: all install uninstall locale manpages
