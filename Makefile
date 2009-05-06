#!/usr/bin/make
# ID's
UID="root"
GID="root"

# This is ok for local installs but change it for packaging... on some systems it hasn't got to be changed for packaging :-)


# Dirs
PREF="/usr/local"
BINMODE="755"
SBINDIR=$(DESTDIR)$(PREF)"/sbin"
ETCDIR=$(DESTDIR)"/etc"
SHAREDIR=$(DESTDIR)$(PREF)"/share/airoscript"
LOCALEDIR=$(DESTDIR)$(PREF)"/share/locale/"
MANDIR=$(DESTDIR)$(PREF)"/share/man/man1"
DOCDIR=$(DESTDIR)$(PREF)"/share/doc/airoscript"
OSTYPE:=$(shell uname -s|cut -d_ -f1)
include Makefile-$(OSTYPE)