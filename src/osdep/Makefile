AC_ROOT	= ../..
include $(AC_ROOT)/common.mak

RTAP		= radiotap

LIB		= libosdep.a 
CFLAGS		+= $(PIC) -I.. $(LIBAIRPCAP)

OBJS_COMMON	= network.o file.o
OBJS		= osdep.o $(OBJS_COMMON)

#AIRPCAP_DIR	= airpcap
OBJS_APCAP	= airpcap.o

OBJS_OBSD	= $(OBJS) openbsd.o openbsd_tap.o
OBJS_NBSD	= $(OBJS) netbsd.o netbsd_tap.o
OBJS_FBSD	= $(OBJS) freebsd.o freebsd_tap.o
OBJS_LINUX	= $(OBJS) linux.o linux_tap.o radiotap/radiotap.o common.o
OBJS_DUMMY	= $(OBJS) dummy.o dummy_tap.o
OBJS_CYGWIN	= $(OBJS) cygwin.o cygwin_tap.o radiotap/radiotap.o
OBJS_DARWIN = $(OBJS) darwin.o darwin_tap.o radiotap/radiotap.o

# XXX make it a DLL, without polluting cygwin.c
ifeq ($(subst TRUE,true,$(filter TRUE true,$(airpcap) $(AIRPCAP))),true)
	OBJS_CYGWIN    += $(OBJS_APCAP)
	DOPCAP		= $(AR) x $(AC_ROOT)/../developers/Airpcap_Devpack/lib/libairpcap.a
else
	DOPCAP		=
endif

all:
	@echo Building for $(OSNAME)
	@$(MAKE) .os.$(OSNAME)

.os.dummy: $(OBJS_DUMMY)
	$(AR) cru $(LIB) $(OBJS_DUMMY)
	$(RANLIB) $(LIB)
	touch $(@)

.os.DragonFly: $(OBJS_FBSD)
	$(AR) cru $(LIB) $(OBJS_FBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.FreeBSD: $(OBJS_FBSD)
	$(AR) cru $(LIB) $(OBJS_FBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.GNU-kFreeBSD: $(OBJS_FBSD)
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
	$(AR) cru $(LIB) *.o radiotap/radiotap.o
	$(RANLIB) $(LIB) 
	touch $(@)

.os.Darwin: $(OBJS_DARWIN) 
	$(DOPCAP)
	$(AR) cru $(LIB) $(OBJS_DARWIN)
	$(RANLIB) $(LIB) 
	touch $(@)

.os.%: .os.dummy
	@echo "Your platform is unsupported by osdep, dummy code compiled."
	touch $(@)

install: all

uninstall:

clean: 
	$(MAKE) -C $(RTAP) clean
	rm -f $(LIB) *.o .os.*
