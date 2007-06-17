ifndef TOOL_PREFIX
TOOL_PREFIX	=
endif
ifndef OSNAME
OSNAME		= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g')
endif

ifeq ($(OSNAME), cygwin)
EXE		= .exe
PIC		=
else
EXE		=
PIC		= -fPIC
endif

CC		= $(TOOL_PREFIX)gcc
RANLIB		= $(TOOL_PREFIX)ranlib
AR		= $(TOOL_PREFIX)ar

REVISION	= `$(ROOT)/evalrev`
REVFLAGS	= -D_REVISION=$(REVISION)

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
