REVISION	= `$(ROOT)/evalrev`
REVFLAGS	= -D_REVISION=$(REVISION)

CC              = gcc
OPTFLAGS        = -D_FILE_OFFSET_BITS=64
CFLAGS          ?= -g -W -Wall -O3
CFLAGS          += $(OPTFLAGS) $(REVFLAGS)

prefix          = /usr/local
bindir          = $(prefix)/bin
sbindir         = $(prefix)/sbin
mandir          = $(prefix)/man/man1
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng
libdir		= $(prefix)/lib
