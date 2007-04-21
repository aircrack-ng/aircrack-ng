ROOT	= ../..
include $(ROOT)/common.mak

LIB		= libosdep.a
CFLAGS		+= $(PIC) -I..

OBJS_NET	= network.o
OBJS		= osdep.o $(OBJS_NET)

OBJS_FBSD	= $(OBJS) freebsd.o
OBJS_LINUX	= $(OBJS) linux.o
OBJS_DUMMY	= $(OBJS) dummy.o
OBJS_CYGWIN	= $(OBJS) cygwin.o

all:
	@echo Building for $(OS)
	@$(MAKE) .os.$(OS)

.os.dummy: $(OBJS_DUMMY)
	$(AR) cru $(LIB) $(OBJS_DUMMY)
	$(RANLIB) $(LIB)
	touch $(@)

.os.FreeBSD: $(OBJS_FBSD)
	$(AR) cru $(LIB) $(OBJS_FBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.Linux: $(OBJS_LINUX)
	$(AR) cru $(LIB) $(OBJS_LINUX)
	$(RANLIB) $(LIB)
	touch $(@)

.os.cygwin: $(OBJS_CYGWIN)
	$(AR) cru $(LIB) $(OBJS_CYGWIN)
	$(RANLIB) $(LIB)
	touch $(@)

.os.%: .os.dummy
	touch $(@)

install: all

uninstall:

clean:
	rm -f $(LIB) *.o .os.*
