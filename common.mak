PKG_CONFIG ?= pkg-config

NEWSSE		= true
# Newer version of the core can be enabled via SIMDCORE
# but should be automatically flipped on thru autodetection
SIMDCORE	= false

# Multibin will compile a separate binary for each core: original, SSE and SIMD.
MULTIBIN	= false

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
ifeq ($(OSNAME), SunOS)
PIC		=
LDFLAGS		+= -lsocket -lnsl
else
PIC		= -fPIC
endif
ifndef SQLITE
SQLITE		= true
endif
endif

COMMON_CFLAGS	=
OSX_ALT_FLAGS	=

ifeq ($(subst TRUE,true,$(filter TRUE true,$(xcode) $(XCODE))),true)
	COMMON_CFLAGS	+= -I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr/include/ -D_XCODE -I../..
	OSX_ALT_FLAGS	= true
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(macport) $(MACPORT))),true)
	COMMON_CFLAGS	+= -I/opt/local/include -I../..
	LDFLAGS		+= -L/opt/local/lib
	OSX_ALT_FLAGS	= true
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	COMMON_CFLAGS	+= -DHAVE_SQLITE
endif

ifeq ($(pcre), true)
PCRE            = true
endif

ifeq ($(PCRE), true)
COMMON_CFLAGS += $(shell $(PKG_CONFIG) --cflags libpcre) -DHAVE_PCRE
endif

STACK_PROTECTOR	= true
ifeq ($(stackprotector), false)
	STACK_PROTECTOR	= false
endif

ifeq ($(STACKPROTECTOR), false)
	STACK_PROTECTOR	= false
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
ifeq ($(OSNAME), FreeBSD)
	CC	= $(TOOL_PREFIX)cc
	CXX	= $(TOOL_PREFIX)c++
else
	CC	= $(TOOL_PREFIX)gcc
	CXX	= $(TOOL_PREFIX)g++
endif
endif

# This is for autodetection of processor features in the new crypto cores.
-include	$(AC_ROOT)/common.cfg

RANLIB		?= $(TOOL_PREFIX)ranlib
ifneq ($(origin AR),environment)
	AR	= $(TOOL_PREFIX)ar
endif

REVISION	= $(shell $(AC_ROOT)/evalrev $(AC_ROOT))
REVFLAGS	?= -D_REVISION=$(REVISION)

OPTFLAGS	= -D_FILE_OFFSET_BITS=64
CFLAGS		?= -g -W -Wall -O3 

ifeq ($(subst TRUE,true,$(filter TRUE true,$(icc) $(ICC))),true)
	ICCMODE	= Y
	CC	= icc
	CXX	= icpc
	AR	= xiar
	CFLAGS	+= -no-prec-div
endif

# If we're building multibin make sure simd is disabled
ifeq ($(subst TRUE,true,$(filter TRUE true,$(multibin) $(MULTIBIN))),true)
	SIMDCORE = false
endif

ifeq ($(HAS_NEON), Y)
	CFLAGS	+= -mfpu=neon
endif

ifeq ($(subst FALSE,false,$(filter FALSE false,$(newsse) $(NEWSSE))),false)
	CFLAGS  += -DOLD_SSE_CORE=1
else
ifeq ($(AVX2FLAG), Y)
ifeq ($(ICCMODE), Y)
	CFLAGS	+= -march=core-avx2 -DJOHN_AVX2
else
	CFLAGS	+= -mavx2 -DJOHN_AVX2
endif
else
ifeq ($(AVX1FLAG), Y)
ifeq ($(ICCMODE), Y)
	CFLAGS	+= -march=corei7-avx -DJOHN_AVX
else
	CFLAGS	+= -mavx -DJOHN_AVX
endif
else
ifeq ($(SSEFLAG), Y)
ifeq ($(ICCMODE), Y)
	CFLAGS	+= -march=corei7
else
	CFLAGS  += -msse2
endif
endif
endif # AVX1FLAG
endif # AVX2FLAG
endif # NEWSSE

ifeq ($(INTEL_ASM), Y)
	ASMFLAG	= -masm=intel
endif

# This will enable -D_REENTRANT if compatible so we have thread-safe functions available to us via -pthread.
ifeq ($(PTHREAD), Y)
	CFLAGS	+= -pthread
endif

CXXFLAGS	= $(CFLAGS) $(ASMFLAG) -fdata-sections -ffunction-sections

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

ifneq ($(ICCMODE), Y)
GCC_OVER41	= $(shell expr 41 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
GCC_OVER45	= $(shell expr 45 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
GCC_OVER49	= $(shell expr 49 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
ifeq ($(GCC_OVER41), 0)
	GCC_OVER41	= $(shell expr 4.1 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
endif
ifeq ($(GCC_OVER45), 0)
	GCC_OVER45	= $(shell expr 4.5 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
endif
ifeq ($(GCC_OVER49), 0)
	GCC_OVER49	= $(shell expr 4.9 \<= `$(CC) -dumpversion | awk -F. '{ print $1$2 }'`)
endif

ifeq ($(STACK_PROTECTOR), true)
	ifeq ($(GCC_OVER49), 0)
		ifeq ($(GCC_OVER41), 1)
			COMMON_CFLAGS += -fstack-protector
		endif
	endif

	ifeq ($(GCC_OVER49), 1)
		COMMON_CFLAGS += -fstack-protector-strong
	endif
endif

ifeq ($(GCC_OVER45), 1)
	CFLAGS		+= -Wno-unused-but-set-variable -Wno-array-bounds
endif
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(duma) $(DUMA))),true)
	LIBS += -lduma
endif
