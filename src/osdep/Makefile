AC_ROOT	= ../..
include $(AC_ROOT)/common.mak

LIB		= libosdep.a 
CFLAGS		+= $(PIC) -I.. $(LIBAIRPCAP)

OBJS_NET	= network.o
OBJS		= osdep.o $(OBJS_NET)

#AIRPCAP_DIR	= airpcap
OBJS_APCAP	= airpcap.o

OBJS_OBSD	= $(OBJS) openbsd.o openbsd_tap.o
OBJS_NBSD	= $(OBJS) netbsd.o netbsd_tap.o
OBJS_FBSD	= $(OBJS) freebsd.o freebsd_tap.o
OBJS_LINUX	= $(OBJS) linux.o linux_tap.o radiotap-parser.o common.o
OBJS_DUMMY	= $(OBJS) dummy.o dummy_tap.o
OBJS_CYGWIN	= $(OBJS) cygwin.o cygwin_tap.o

# XXX make it a DLL, without polluting cygwin.c
DOPCAP		=
ifeq ($(AIRPCAP), true)
OBJS_CYGWIN    += $(OBJS_APCAP)
DOPCAP		= $(AR) x $(AC_ROOT)/../developers/Airpcap_Devpack/lib/libairpcap.a
endif

all:
	@echo Building for $(OSNAME)
	@$(MAKE) .os.$(OSNAME)

.os.dummy: $(OBJS_DUMMY)
	$(AR) cru $(LIB) $(OBJS_DUMMY)
	$(RANLIB) $(LIB)
	touch $(@)

.os.FreeBSD: $(OBJS_FBSD)
	$(AR) cru $(LIB) $(OBJS_FBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.OpenBSD: $(OBJS_OBSD)
	$(AR) cru $(LIB) $(OBJS_OBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.NetBSD: $(OBJS_NBSD)
	$(AR) cru $(LIB) $(OBJS_NBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.Linux: $(OBJS_LINUX)
	$(AR) cru $(LIB) $(OBJS_LINUX)
	$(RANLIB) $(LIB)
	touch $(@)

.os.cygwin: $(OBJS_CYGWIN) 
	$(DOPCAP)
	$(AR) cru $(LIB) *.o
	$(RANLIB) $(LIB) 
	touch $(@)

.os.%: .os.dummy
	@echo "Your platform is unsupported by osdep, dummy code compiled."
	touch $(@)

install: all

uninstall:

clean:
	rm -f $(LIB) *.o .os.*
