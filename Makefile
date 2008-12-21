#!/usr/bin/make
# ID's
UID="root"
GID="root"

# Dirs
BINMODE="755"
SBINDIR=$(DESTDIR)"/usr/sbin"
ETCDIR=$(DESTDIR)"/etc"
SHAREDIR=$(DESTDIR)"/usr/share/airoscript"
LOCALEDIR=$(DESTDIR)"/usr/share/locale/"
MANDIR=$(DESTDIR)"/usr/share/man/man1"

install:
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.sh          $(SBINDIR)/airoscript
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/default.theme          $(SHAREDIR)/themes/default.theme
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.conf        $(ETCDIR)/airoscript.conf
	@install    -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airopdate.sh           $(SHAREDIR)/airopdate
	@install    -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc.sh          $(SHAREDIR)/airoscfunc.sh
	@install    -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc_screen.sh   $(SHAREDIR)/airoscfunc_screen.sh
	@install    -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc_unstable.sh $(SHAREDIR)/airoscfunc_unstable.sh
	@install    -g $(UID) -o $(GID) -m 644        $(CURDIR)/src/screenrc               $(SHAREDIR)/screenrc
	@msgfmt -o $(DESTDIR)/$(LOCALEDIR)/es/LC_MESSAGES/airoscript.mo $(CURDIR)/src/i10n/po/es_ES
	@install -D -g $(UID) -o $(GID) -m 644	      $(CURDIR)/doc/airoscript.1	   $(MANDIR)/airoscript.1
	@gzip -f -9 $(MANDIR)/airoscript.1

uninstall:
	rm  $(SBINDIR)/airoscript
	rm -r $(SHAREDIR)
	rm $(ETCDIR)/airoscript.conf
	rm $(DESTDIR)/usr/share/locale/es/LC_MESSAGES/airoscript.mo

all: install 

.PHONY: all install uninstall
