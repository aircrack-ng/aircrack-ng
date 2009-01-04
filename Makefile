#!/usr/bin/make
# ID's
UID="root"
GID="root"

# Dirs
BINMODE="755"
SBINDIR=$(DESTDIR)"/usr/local/sbin"
ETCDIR=$(DESTDIR)"/etc"
SHAREDIR=$(DESTDIR)"/usr/local/share/airoscript"
LOCALEDIR=$(DESTDIR)"/usr/local/share/locale/"
MANDIR=$(DESTDIR)"/usr/local/share/man/man1"
DOCDIR=$(DESTDIR)"/usr/local/share/doc/airoscript"
ORIGLOCALEDIR=$(DESTDIR)"/usr/share/locale"

install: airopdate
	@echo -en "Installing files into:$(BINDIR) $(ETCDIR) $(SHAREDIR) $(DOCDIR) $(SBINDIR) "
	@install -D -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.sh          $(SBINDIR)/airoscript
	@install -D -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/themes/default.theme          $(SHAREDIR)/themes/default.theme
	@install -D -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.conf        $(ETCDIR)/airoscript.conf
	@install    -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airopdate.sh           $(SHAREDIR)/airopdate
	@install    -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc.sh          $(SHAREDIR)/airoscfunc.sh
	@install    -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc_screen.sh   $(SHAREDIR)/airoscfunc_screen.sh
	@install    -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc_unstable.sh $(SHAREDIR)/airoscfunc_unstable.sh
	@install    -o $(UID) -g $(GID) -m 644        $(CURDIR)/src/screenrc               $(SHAREDIR)/screenrc
	@echo -en "...done\nInstalling locale (spanish) on $(LOCALEDIR) and link to $(ORIGLOCALEDIR)"
	@msgfmt -o $(LOCALEDIR)/es/LC_MESSAGES/airoscript.mo $(CURDIR)/src/i10n/po/es_ES
	@ln -f -s $(LOCALEDIR)/es/LC_MESSAGES/airoscript.mo $(ORIGLOCALEDIR)/es/LC_MESSAGES/airoscript.mo
	@echo -en "...done\nInstalling manpage"
	@install -D -g $(UID) -o $(GID) -m 644	      $(CURDIR)/src/airoscript.1	   $(MANDIR)/airoscript.1
	@gzip -f -9 $(MANDIR)/airoscript.1
	@echo -en "...done\nInstalling documentation"	
	@mkdir -p $(DOCDIR)
	@cp -r $(CURDIR)/doc/* $(DOCDIR)
	@echo -en "...done\n"

airopdate:
	@install -D -o $(UID) -g $(GID) -m $(BINMODE) $(CURDIR)/src/airopdate.sh $(SBINDIR)/airopdate
	
uninstall:
	@echo "Uninstalling airoscript."
	@rm  $(SBINDIR)/airoscript
	@rm -r $(SHAREDIR)
	@rm -r $(DOCDIR)
	@rm $(ETCDIR)/airoscript.conf
	@rm $(LOCALEDIR)/es/LC_MESSAGES/airoscript.mo
	@rm $(ORIGLOCALEDIR)/es/LC_MESSAGES/airoscript.mo
	

all: install 

.PHONY: all install uninstall
