PKG_CONFIG ?= pkg-config

ifndef TOOL_PREFIX
TOOL_PREFIX	=
endif
ifndef OSNAME
OSNAME		= $(shell uname -s | sed -e 's/.*CYGWIN.*/cygwin/g' -e 's,/,-,g')
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



ifeq ($(SQLITE), true)
    COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
else
    ifeq ($(sqlite), true)
        COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
    else
        ifeq ($(SQLITE), TRUE)
            COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
        else
            ifeq ($(sqlite), TRUE)
                COMMON_CFLAGS	+= -I/usr/local/include -DHAVE_SQLITE
            endif
        endif
    endif
endif

ifeq ($(OSNAME), cygwin)
	COMMON_CFLAGS   += -DCYGWIN
else ifeq ($(libnl), true)
	NL1FOUND := $(shell $(PKG_CONFIG) --atleast-version=1 libnl-1 && echo Y)
	NL2FOUND := $(shell $(PKG_CONFIG) --atleast-version=2 libnl-2.0 && echo Y)
	NL3FOUND := $(shell $(PKG_CONFIG) --atleast-version=3 libnl-3.0 && echo Y)
	NL31FOUND := $(shell $(PKG_CONFIG) --exact-version=3.1 libnl-3.1 && echo Y)
	NL3xFOUND := $(shell $(PKG_CONFIG) --atleast-version=3.2 libnl-3.0 && echo Y)
	
	ifeq ($(NL1FOUND),Y)
		COMMON_CFLAGS += -DCONFIG_LIBNL
		NLLIBNAME = libnl-1
	endif
	
	ifeq ($(NL2FOUND),Y)
		#COMMON_CFLAGS += -DCONFIG_LIBNL
		#LIBS += -lnl-genl
		NLLIBNAME = libnl-2.0
        $(error libnl2 is not supported. install either libnl1 or libnl3)
	endif
	
	ifeq ($(NL3xFOUND),Y)
		NL3FOUND = N
		COMMON_CFLAGS += -DCONFIG_LIBNL30
		LIBS += -lnl-genl-3
		NLLIBNAME = libnl-3.0
	endif
	
	ifeq ($(NL3FOUND),Y)
		COMMON_CFLAGS += -DCONFIG_LIBNL
		LIBS += -lnl-genl
		NLLIBNAME = libnl-3.0
	endif
	
	# nl-3.1 has a broken libnl-gnl-3.1.pc file
	# as show by pkg-config --debug --libs --cflags --exact-version=3.1 libnl-genl-3.1;echo $?
	ifeq ($(NL31FOUND),Y)
		COMMON_CFLAGS += -DCONFIG_LIBNL30
		LIBS += -lnl-genl
		NLLIBNAME = libnl-3.1
	endif
	
	ifeq ($NLLIBNAME,)
        $(error Cannot find development files for any supported version of libnl)
	endif
	
	LIBS += $(shell $(PKG_CONFIG) --libs $(NLLIBNAME))
	CFLAGS += $(shell $(PKG_CONFIG) --cflags $(NLLIBNAME))
	NLVERSION :=$(shell $(PKG_CONFIG) --print-provides $(NLLIBNAME))
endif

ifeq ($(airpcap), true)
AIRPCAP		= true
endif

ifeq ($(AIRPCAP), true)
LIBAIRPCAP	= -DHAVE_AIRPCAP -I$(AC_ROOT)/../developers/Airpcap_Devpack/include
endif

ifeq ($(OSNAME), cygwin)
CC              = $(TOOL_PREFIX)gcc-4
else
CC		= $(TOOL_PREFIX)gcc
endif

RANLIB		= $(TOOL_PREFIX)ranlib
AR		= $(TOOL_PREFIX)ar

REVISION	= $(shell $(AC_ROOT)/evalrev)
REVFLAGS	= -D_REVISION=$(REVISION)

OPTFLAGS        = -D_FILE_OFFSET_BITS=64
CFLAGS          ?= -g -W -Wall -O3
CFLAGS          += $(OPTFLAGS) $(REVFLAGS) $(COMMON_CFLAGS)

prefix          = /usr/local
bindir          = $(prefix)/bin
sbindir         = $(prefix)/sbin
mandir          = $(prefix)/share/man/man1
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng
libdir		= $(prefix)/lib
etcdir		= $(prefix)/etc/aircrack-ng 

GCC_OVER45	= $(shell expr 45 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
ifeq ($(GCC_OVER45), 1)
CFLAGS		+= -Wno-unused-but-set-variable -Wno-array-bounds
endif
