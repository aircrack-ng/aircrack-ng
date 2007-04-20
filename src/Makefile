ROOT		= ..
include $(ROOT)/common.mak

iCC             = /opt/intel/cc/9.0/bin/icc
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

BINFILES        = aircrack-ng airdecap-ng packetforge-ng ivstools kstats
SBINFILES       = aireplay-ng airodump-ng airserv-ng airtun-ng
OPTFILES	= aircrack-ng-opt-prof_gen aircrack-ng-opt \
		  aircrack-ng-opt-prof prof/*

SRC_PTW		= aircrack-ptw-lib.c
SRC_AC		= aircrack-ng.c crypto.c common.c $(SRC_PTW)
OBJS_PTW	= aircrack-ptw-lib.o
OBJS_AC		= aircrack-ng.o crypto.o common.o $(OBJS_PTW)

OBJS_AD		= airdecap-ng.o crypto.o common.o
OBJS_PF		= packetforge-ng.o common.o crypto.o
OBJS_AR		= aireplay-ng.o common.o crypto.o
OBJS_ADU	= airodump-ng.o common.o
OBJS_AT		= airtun-ng.o common.o crypto.o
OBJS_IV		= ivstools.o common.o
OBJS_AS		= airserv-ng.o common.o

OSD		= osdep
LIBS		= -L$(OSD) -l$(OSD)
LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto

all: osd userland $(SBINFILES)

userland: $(BINFILES)

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

aircrack-ng-opt: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) $(SRC_AC)

aircrack-ng-opt-prof_gen: $(SRC_AC)
	mkdir -p prof
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_genx -DDO_PGO_DUMP \
	-prof_dir$(PROF_DIR) $(SRC_AC) -o aircrack-ng-opt-prof_gen -lpthread

aircrack-ng-opt-prof_use: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_use \
	-prof_dir$(PROF_DIR) $(SRC_AC) -o aircrack-ng-opt-prof -lpthread

aircrack-ng: $(OBJS_AC)
	$(CC) $(CFLAGS) $(OBJS_AC) -o $(@) -lpthread $(LIBSSL)

airdecap-ng: $(OBJS_AD)
	$(CC) $(CFLAGS) $(OBJS_AD) -o $(@) $(LIBSSL)

packetforge-ng: $(OBJS_PF)
	$(CC) $(CFLAGS) $(OBJS_PF) -o $(@) $(LIBSSL)

aireplay-ng: $(OBJS_AR) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AR) -o $(@) $(LIBS) $(LIBSSL)

airodump-ng: $(OBJS_ADU) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_ADU) -o $(@) $(LIBS)

airserv-ng: $(OBJS_AS) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AS) -o $(@) $(LIBS)

airtun-ng: $(OBJS_AT) $(LIBSOSD)
	$(CC) $(CFLAGS) $(OBJS_AT) -o $(@) $(LIBS) $(LIBSSL)

ivstools: $(OBJS_IV)
	$(CC) $(CFLAGS) $(OBJS_IV) -o $(@)

kstats: kstats.o
	$(CC) $(CFLAGS) kstats.o -o $(@)

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
	-rm -f $(bindir)/aircrack-ng
	-rm -f $(bindir)/airdecap-ng
	-rm -f $(bindir)/packetforge-ng
	-rm -f $(bindir)/ivstools
	-rm -f $(bindir)/kstats
	-rm -f $(sbindir)/airodump-ng
	-rm -f $(sbindir)/airtun-ng
	-rm -f $(sbindir)/aireplay-ng
