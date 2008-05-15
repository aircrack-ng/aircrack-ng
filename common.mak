ifndef TOOL_PREFIX
TOOL_PREFIX	=
endif
ifndef OSNAME
OSNAME		= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g')
endif
ifndef SQLITE
SQLITE		= false
endif

ifndef LIBAIRPCAP
LIBAIRPCAP	=
endif

ifeq ($(OSNAME), cygwin)
EXE		= .exe
PIC		=
SQLITE		= false
NL80211		= false
else
EXE		=
PIC		= -fPIC
ifndef SQLITE
SQLITE		= true
endif
# nl80211-ng came too late for 1.0, so disable it by default - enable it once we hit 1.1
ifndef NL80211
NL80211		= false
nl80211		= false
endif
ifneq ($(OSNAME), Linux)
# nl80211-ng is for linux only
NL80211		= false
nl80211		= false
endif
endif

COMMON_CFLAGS	= 

ifeq ($(SQLITE), true)
COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
else ifeq ($(sqlite), true)
COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
else ifeq ($(SQLITE), TRUE)
COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
else ifeq ($(sqlite), TRUE)
COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
endif

ifeq ($(airpcap), true)
AIRPCAP		= true
endif

ifeq ($(AIRPCAP), true)
LIBAIRPCAP	= -DHAVE_AIRPCAP -I$(AC_ROOT)/../developers/Airpcap_Devpack/include
endif

ifeq ($(NL80211), true)
COMMON_CFLAGS	+= -I/lib/modules/`uname -r`/build/include -I/usr/include
else ifeq ($(NL80211), TRUE)
COMMON_CFLAGS	+= -I/lib/modules/`uname -r`/build/include -I/usr/include
else ifeq ($(nl80211), true)
COMMON_CFLAGS	+= -I/lib/modules/`uname -r`/build/include -I/usr/include
else ifeq ($(nl80211), TRUE)
COMMON_CFLAGS	+= -I/lib/modules/`uname -r`/build/include -I/usr/include
endif

CC		= $(TOOL_PREFIX)gcc
RANLIB		= $(TOOL_PREFIX)ranlib
AR		= $(TOOL_PREFIX)ar

REVISION	= $(shell $(AC_ROOT)/evalrev)
REVFLAGS	= -D_REVISION=$(REVISION)

OPTFLAGS        = -D_FILE_OFFSET_BITS=64
CFLAGS          ?= -g -W -Wall -Werror -O3
CFLAGS          += $(OPTFLAGS) $(REVFLAGS) $(COMMON_CFLAGS)

prefix          = /usr/local
bindir          = $(prefix)/bin
sbindir         = $(prefix)/sbin
mandir          = $(prefix)/man/man1
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng
libdir		= $(prefix)/lib
