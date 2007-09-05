ROOT		= ..
include $(ROOT)/common.mak

CFLAGS		+= -Iinclude

iCC             = /opt/intel/cc/9.0/bin/icc
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

BINFILES        = aircrack-ng$(EXE) airdecap-ng$(EXE) packetforge-ng$(EXE) \
		  ivstools$(EXE) kstats$(EXE) buddy-ng$(EXE) makeivs-ng$(EXE)
ifeq ($(SQLITE), true)
BINFILES	+= airolib-ng$(EXE)
endif

SBINFILES       = aireplay-ng$(EXE) airodump-ng$(EXE) airserv-ng$(EXE) \
		  airtun-ng$(EXE) wesside-ng$(EXE) easside-ng$(EXE)
OPTFILES	= aircrack-ng-opt-prof_gen aircrack-ng-opt \
		  aircrack-ng-opt-prof prof/*

SRC_PTW		= aircrack-ptw-lib.c
SRC_AC		= aircrack-ng.c crypto.c common.c $(SRC_PTW)
OBJS_PTW	= aircrack-ptw-lib.o
OBJS_AC		= aircrack-ng.o crypto.o common.o uniqueiv.o $(OBJS_PTW)

OBJS_AD		= airdecap-ng.o crypto.o common.o
OBJS_PF		= packetforge-ng.o common.o crypto.o
OBJS_AR		= aireplay-ng.o common.o crypto.o
OBJS_ADU	= airodump-ng.o common.o crypto.o uniqueiv.o
OBJS_AT		= airtun-ng.o common.o crypto.o
OBJS_IV		= ivstools.o common.o crypto.o uniqueiv.o
OBJS_AS		= airserv-ng.o common.o
OBJS_WS		= wesside-ng.o crypto.c common.o $(OBJS_PTW)
OBJS_AL		= airolib-ng.o crypto.c
OBJS_ES		= easside-ng.o
OBJS_BUDDY	= buddy-ng.o
OBJS_MI		= makeivs-ng.o common.o uniqueiv.o


OSD		= osdep
LIBS		= -L$(OSD) -l$(OSD) $(LDFLAGS)
ifeq ($(OSNAME), cygwin)
LIBS		+= -liphlpapi -lsetupapi -luuid
endif
LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto $(LDFLAGS)
ifeq ($(SQLITE), true)
LIBSQL		= -L/usr/local/lib -lsqlite3
else
LIBSQL		=
endif

all: osd userland $(SBINFILES)

userland: $(BINFILES)

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

aircrack-ng-opt: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) $(SRC_AC) $(LIBSSL) \
	uniqueiv.o -o aircrack-ng-opt -lpthread $(LIBSQL)

aircrack-ng-opt-prof_gen: $(SRC_AC)
	mkdir -p prof
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_genx -DDO_PGO_DUMP \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof_gen -lpthread $(LIBSQL)

aircrack-ng-opt-prof_use: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_use \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof -lpthread $(LIBSQL)

aircrack-ng$(EXE): $(OBJS_AC)
	$(CC) $(CFLAGS) $(OBJS_AC) -o $(@) -lpthread $(LIBSSL) $(LIBSQL)

airdecap-ng$(EXE): $(OBJS_AD)
	$(CC) $(CFLAGS) $(OBJS_AD) -o $(@) $(LIBSSL)

packetforge-ng$(EXE): $(OBJS_PF)
	$(CC) $(CFLAGS) $(OBJS_PF) -o $(@) $(LIBSSL)

aireplay-ng$(EXE): $(OBJS_AR) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AR) -o $(@) $(LIBS) $(LIBSSL)

airodump-ng$(EXE): $(OBJS_ADU) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_ADU) -o $(@) $(LIBS) $(LIBSSL)

airserv-ng$(EXE): $(OBJS_AS) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AS) -o $(@) $(LIBS)

airtun-ng$(EXE): $(OBJS_AT) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AT) -o $(@) $(LIBS) $(LIBSSL)

ivstools$(EXE): $(OBJS_IV)
	$(CC) $(CFLAGS) $(OBJS_IV) -o $(@) $(LIBSSL)

kstats$(EXE): kstats.o
	$(CC) $(CFLAGS) kstats.o -o $(@)

wesside-ng$(EXE): $(OBJS_WS) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_WS) -o $(@) $(LIBS) $(LIBSSL) -lz

easside-ng$(EXE): $(OBJS_ES) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_ES) -o $(@) $(LIBS) -lz

buddy-ng$(EXE): $(OBJS_BUDDY)
	$(CC) $(CFLAGS) $(OBJS_BUDDY) -o $(@)

makeivs-ng$(EXE): $(OBJS_MI)
	$(CC) $(CFLAGS) $(OBJS_MI) -o $(@)

airolib-ng$(EXE): $(OBJS_AL)
	$(CC) $(CFLAGS) $(OBJS_AL) -o $(@) $(LIBSSL) -DHAVE_REGEXP $(LIBSQL)

strip: $(BINFILES) $(SBINFILES)
	strip $(BINFILES) $(SBINFILES)

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(SBINFILES) $(BINFILES) $(OPTFILES) *.o

distclean: clean

install: all
	$(MAKE) -C $(OSD) install
	install -d $(bindir)
	install -m 755 $(BINFILES) $(bindir)
	install -d $(sbindir)
	install -m 755 $(SBINFILES) $(sbindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -f $(bindir)/aircrack-ng$(EXE)
	-rm -f $(bindir)/airdecap-ng$(EXE)
	-rm -f $(bindir)/packetforge-ng$(EXE)
	-rm -f $(bindir)/airolib-ng$(EXE)
	-rm -f $(bindir)/ivstools$(EXE)
	-rm -f $(bindir)/kstats$(EXE)
	-rm -f $(bindir)/buddy-ng$(EXE)
	-rm -f $(sbindir)/airodump-ng$(EXE)
	-rm -f $(sbindir)/airserv-ng$(EXE)
	-rm -f $(sbindir)/airtun-ng$(EXE)
	-rm -f $(sbindir)/aireplay-ng$(EXE)
	-rm -f $(sbindir)/wesside-ng$(EXE)
	-rm -f $(sbindir)/easside-ng$(EXE)
