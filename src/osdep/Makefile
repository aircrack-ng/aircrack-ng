ROOT	= ../..
include $(ROOT)/common.mak

LIB=libosdep.a
CFLAGS	+= -fPIC -I..
OBJS=osdep.o
OS= `uname -s`
AR=ar
RANLIB=ranlib

OBJS_NET=network.o
OBJS_FBSD=$(OBJS) $(OBJS_NET) freebsd.o
OBJS_LINUX=linux.o
OBJS_DUMMY=dummy.o

all:
	@echo Building for $(OS)
	@$(MAKE) .os.$(OS)

.os.dummy: $(OBJS) $(OBJS_DUMMY)
	$(AR) cru $(LIB) $(OBJS) $(OBJS_DUMMY)
	$(RANLIB) $(LIB)
	touch $(@)

.os.FreeBSD: $(OBJS_FBSD)
	$(AR) cru $(LIB) $(OBJS_FBSD)
	$(RANLIB) $(LIB)
	touch $(@)

.os.Linux: $(OBJS) $(OBJS_LINUX)
	$(AR) cru $(LIB) $(OBJS) $(OBJS_LINUX)
	$(RANLIB) $(LIB)
	touch $(@)

.os.%: .os.dummy
	touch $(@)

install: all

uninstall:

clean:
	rm -f $(LIB) *.o .os.*
