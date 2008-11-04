#!/usr/bin/make
# ID's
UID="root"
GID="root"

# Dirs
BINMODE="755"
SBINDIR="/usr/sbin"
ETCDIR="/etc"
SHAREDIR="/usr/share/airoscript"

install:
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.sh $(SBINDIR)/airoscript
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airopdate.sh $(SHAREDIR)/airopdate
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscript.conf $(ETCDIR)/airoscript.conf
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/default.theme $(SHAREDIR)/themes/default.theme
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc.sh $(SHAREDIR)/airoscfunc.sh
	@install -D -g $(UID) -o $(GID) -m $(BINMODE) $(CURDIR)/src/airoscfunc_unstable.sh $(SHAREDIR)/airoscfunc_unstable.sh

all: install

.PHONY: all install configure
