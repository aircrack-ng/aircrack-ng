PKG_CONFIG ?= pkg-config

ifndef TOOL_PREFIX
TOOL_PREFIX	=
endif
ifndef OSNAME
OSNAME		:= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g' -e 's,/,-,g')
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
else
EXE		=
PIC		= -fPIC
ifndef SQLITE
SQLITE		= true
endif
endif

COMMON_CFLAGS	=



ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	COMMON_CFLAGS	+= -DHAVE_SQLITE
endif

ifeq ($(pcre), true)
PCRE            = true
endif

ifeq ($(PCRE), true)
COMMON_CFLAGS += $(shell $(PKG_CONFIG) --cflags libpcre) -DHAVE_PCRE
endif

ifeq ($(OSNAME), cygwin)
	COMMON_CFLAGS   += -DCYGWIN
endif

ifeq ($(OSNAME), Linux)
	ifneq ($(libnl), false)
		NL3xFOUND := $(shell $(PKG_CONFIG) --atleast-version=3.2 libnl-3.0 && echo Y)
		ifneq ($(NL3xFOUND),Y)
			NL31FOUND := $(shell $(PKG_CONFIG) --exact-version=3.1 libnl-3.1 && echo Y)
			ifneq ($(NL31FOUND),Y)
				NL3FOUND := $(shell $(PKG_CONFIG) --atleast-version=3 libnl-3.0 && echo Y)
			endif
			ifneq ($(NL3FOUND),Y)
				NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
			endif
			ifneq ($(NL1FOUND),Y)
				NLTFOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-tiny && echo Y)
			endif
		endif


		ifeq ($(NL1FOUND),Y)
			NLLIBNAME = libnl-1
			COMMON_CFLAGS += -DCONFIG_LIBNL
		endif

		ifeq ($(NLTFOUND),Y)
			NLLIBNAME = libnl-tiny
			COMMON_CFLAGS += -DCONFIG_LIBNL -DCONFIG_LIBNL20
		endif

		ifeq ($(NL3xFOUND),Y)
			COMMON_CFLAGS += -DCONFIG_LIBNL30 -DCONFIG_LIBNL
			LIBS += -lnl-genl-3
			NLLIBNAME = libnl-3.0
		endif

		ifeq ($(NL3FOUND),Y)
			COMMON_CFLAGS += -DCONFIG_LIBNL30 -DCONFIG_LIBNL
			LIBS += -lnl-genl
			NLLIBNAME = libnl-3.0
		endif

		# nl-3.1 has a broken libnl-gnl-3.1.pc file
		# as show by pkg-config --debug --libs --cflags --exact-version=3.1 libnl-genl-3.1;echo $?
		ifeq ($(NL31FOUND),Y)
			COMMON_CFLAGS += -DCONFIG_LIBNL30 -DCONFIG_LIBNL
			LIBS += -lnl-genl
			NLLIBNAME = libnl-3.1
		endif

		NLLIBNAME ?= $(error Cannot find development files for any supported version of libnl. install either libnl1 or libnl3.)

		LIBS += $(shell $(PKG_CONFIG) --libs $(NLLIBNAME))
		COMMON_CFLAGS +=$(shell $(PKG_CONFIG) --cflags $(NLLIBNAME))
		COMMON_CFLAGS := $(COMMON_CFLAGS)
	endif
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(airpcap) $(AIRPCAP))),true)
	LIBAIRPCAP = -DHAVE_AIRPCAP -I$(AC_ROOT)/../developers/Airpcap_Devpack/include
endif

ifneq ($(origin CC),environment)
	CC	= $(TOOL_PREFIX)gcc
endif

RANLIB		?= $(TOOL_PREFIX)ranlib
ifneq ($(origin AR),environment)
	AR	= $(TOOL_PREFIX)ar
endif

REVISION	= $(shell $(AC_ROOT)/evalrev $(AC_ROOT))
REVFLAGS	?= -D_REVISION=$(REVISION)

OPTFLAGS        = -D_FILE_OFFSET_BITS=64
CFLAGS          ?= -g -W -Wall -O3
CFLAGS          += $(OPTFLAGS) $(REVFLAGS) $(COMMON_CFLAGS)

prefix          = /usr/local
bindir          = $(prefix)/bin
sbindir         = $(prefix)/sbin
mandir          = $(prefix)/share/man/man1
smandir         = $(prefix)/share/man/man8
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng
libdir		= $(prefix)/lib
etcdir		= $(prefix)/etc/aircrack-ng

GCC_OVER45	= $(shell expr 45 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
ifeq ($(GCC_OVER45), 0)
	GCC_OVER45	= $(shell expr 4.5 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
endif

ifeq ($(GCC_OVER45), 1)
	CFLAGS		+= -Wno-unused-but-set-variable -Wno-array-bounds
endif
