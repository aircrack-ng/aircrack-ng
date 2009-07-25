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
else
EXE		=
PIC		= -fPIC
ifndef SQLITE
SQLITE		= true
endif
endif

COMMON_CFLAGS	=

ifeq ($(OSNAME), cygwin)
COMMON_CFLAGS   += -DCYGWIN
endif

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
CFLAGS          ?= -g -W -Wall -Werror -O3
CFLAGS          += $(OPTFLAGS) $(REVFLAGS) $(COMMON_CFLAGS)

prefix          = /usr/local
bindir          = $(prefix)/bin
sbindir         = $(prefix)/sbin
mandir          = $(prefix)/man/man1
datadir         = $(prefix)/share
docdir          = $(datadir)/doc/aircrack-ng
libdir		= $(prefix)/lib
