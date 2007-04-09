ROOT	= ../..
include $(ROOT)/common.mak

LIB=libosdep.so
CFLAGS	+= -fPIC -I..
OBJS=osdep.o
OS= `uname -s`

OBJS_FBSD=freebsd.o
OBJS_LINUX=linux.o
OBJS_DUMMY=dummy.o

all:
	@echo Building for $(OS)
	@$(MAKE) .os.$(OS)

.os.dummy: $(OBJS) $(OBJS_DUMMY)
	$(CC) $(CFLAGS) -shared -o $(LIB) $(OBJS) $(OBJS_DUMMY)
	touch $(@)

.os.FreeBSD: $(OBJS) $(OBJS_FBSD)
	$(CC) $(CFLAGS) -shared -o $(LIB) $(OBJS) $(OBJS_FBSD)
	touch $(@)

.os.Linux: $(OBJS) $(OBJS_LINUX)
	$(CC) $(CFLAGS) -shared -o $(LIB) $(OBJS) $(OBJS_LINUX)
	touch $(@)

.os.%: .os.dummy
	touch $(@)

install: all
	install -d $(libdir)
	install -m 755 $(LIB) $(libdir)

uninstall:
	-rm -f $(libdir)/$(LIB)

clean:
	rm -f $(LIB) *.o .os.*
