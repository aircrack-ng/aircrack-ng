AC_ROOT		= ..
LIBPCAP		=
include $(AC_ROOT)/common.mak

TEST_DIR	= $(AC_ROOT)/test

CFLAGS		+= -Iinclude

iCC             = $(shell find /opt/intel/cc/*/bin/icc)
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

BINFILES        = aircrack-ng$(EXE) airdecap-ng$(EXE) packetforge-ng$(EXE) \
		  ivstools$(EXE) kstats$(EXE) makeivs-ng$(EXE) \
		  airdecloak-ng$(EXE)

ifeq ($(SQLITE), true)
	BINFILES	+= airolib-ng$(EXE)
else
	ifeq ($(sqlite), true)
		BINFILES        += airolib-ng$(EXE)
	else
		ifeq ($(SQLITE), TRUE)
			BINFILES        += airolib-ng$(EXE)
		else
			ifeq ($(sqlite), TRUE)
				BINFILES        += airolib-ng$(EXE)
			endif
		endif
	endif
endif


LIBPCAP		=

SBINFILES       = aireplay-ng$(EXE) airodump-ng$(EXE) airserv-ng$(EXE) \
		  airtun-ng$(EXE) airbase-ng$(EXE)
		  
OPTFILES	= aircrack-ng-opt-prof_gen aircrack-ng-opt \
		  aircrack-ng-opt-prof prof/*



ifeq ($(UNSTABLE), true)
	SBINFILES	+= wesside-ng$(EXE) tkiptun-ng$(EXE) easside-ng$(EXE)
	BINFILES	+= buddy-ng$(EXE)
else
	ifeq ($(unstable), true)
		SBINFILES       += wesside-ng$(EXE) tkiptun-ng$(EXE) easside-ng$(EXE)
		BINFILES	+= buddy-ng$(EXE)
	else
		ifeq ($(UNSTABLE), TRUE)
			SBINFILES       += wesside-ng$(EXE) tkiptun-ng$(EXE) easside-ng$(EXE)
			BINFILES	+= buddy-ng$(EXE)
		else
			ifeq ($(unstable), TRUE)
				SBINFILES       += wesside-ng$(EXE) tkiptun-ng$(EXE) easside-ng$(EXE)
				BINFILES	+= buddy-ng$(EXE)
			endif
		endif
	endif
endif


SRC_PTW		= aircrack-ptw-lib.c
SRC_AC		= aircrack-ng.c crypto.c common.c $(SRC_PTW)
OBJS_PTW	= aircrack-ptw-lib.o
OBJS_AC		= aircrack-ng.o crypto.o common.o uniqueiv.o $(OBJS_PTW)
ASM_AC		= sha1-sse2.S

ifeq ($(CUDA), true)
	SRC_AC		+= cudacrypto.cu cudacrypto_sha1_process.cuh
	OBJS_AC		+= cudacrypto.o
endif

OBJS_AD		= airdecap-ng.o crypto.o common.o
OBJS_PF		= packetforge-ng.o common.o crypto.o
OBJS_AR		= aireplay-ng.o common.o crypto.o
OBJS_ADU	= airodump-ng.o common.o crypto.o uniqueiv.o
ifneq ($(OSNAME), Linux)
	OBJS_ADU	+= osdep/common.o
endif
OBJS_AT		= airtun-ng.o common.o crypto.o
OBJS_IV		= ivstools.o common.o crypto.o uniqueiv.o
OBJS_AS		= airserv-ng.o common.o
OBJS_WS		= wesside-ng.o crypto.c common.o $(OBJS_PTW)
OBJS_AL		= airolib-ng.o crypto.c common.o
OBJS_ES		= easside-ng.o common.o
OBJS_BUDDY	= buddy-ng.o common.o
OBJS_MI		= makeivs-ng.o common.o uniqueiv.o
OBJS_AB		= airbase-ng.o common.o crypto.o
OBJS_AU		= airdecloak-ng.o common.o osdep/radiotap-parser.o
OBJS_TT		= tkiptun-ng.o common.o crypto.o


OSD		= osdep
LIBS		= -L$(OSD) -l$(OSD) $(LIBPCAP) $(LDFLAGS)
ifeq ($(OSNAME), cygwin)
LIBS		+= -liphlpapi -lsetupapi -luuid
endif
LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto $(LDFLAGS)
LIBSQL		=
ifeq ($(SQLITE), true)
	LIBSQL		= -L/usr/local/lib -lsqlite3
else
	ifeq ($(sqlite), true)
		LIBSQL          = -L/usr/local/lib -lsqlite3
	else
		ifeq ($(SQLITE), TRUE)
			LIBSQL          = -L/usr/local/lib -lsqlite3
		else
			ifeq ($(sqlite), TRUE)
				LIBSQL          = -L/usr/local/lib -lsqlite3
			endif
		endif
	endif
endif

all: osd userland $(SBINFILES)

userland: $(BINFILES)

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

aircrack-ng-opt: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) $(SRC_AC) $(ASM_AC) $(LIBSSL) \
	uniqueiv.o -o aircrack-ng-opt -lpthread $(LIBSQL)

aircrack-ng-opt-prof_gen: $(SRC_AC)
	mkdir -p prof
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_genx -DDO_PGO_DUMP \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(ASM_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof_gen -lpthread $(LIBSQL)

aircrack-ng-opt-prof_use: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_use \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(ASM_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof -lpthread $(LIBSQL)

aircrack-ng$(EXE): $(OBJS_AC)
	$(CC) $(CFLAGS) $(OBJS_AC) $(ASM_AC) -o $(@) -lpthread $(LIBSSL) $(LIBSQL)

airdecap-ng$(EXE): $(OBJS_AD)
	$(CC) $(CFLAGS) $(OBJS_AD) -o $(@) $(LIBSSL)

packetforge-ng$(EXE): $(OBJS_PF)
	$(CC) $(CFLAGS) $(OBJS_PF) -o $(@) $(LIBSSL)

aireplay-ng$(EXE): $(OBJS_AR) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AR) -o $(@) $(LIBS) $(LIBSSL)

airodump-ng$(EXE): $(OBJS_ADU) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_ADU) -o $(@) $(LIBS) $(LIBSSL)

airserv-ng$(EXE): $(OBJS_AS) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AS) -o $(@) $(LIBS) $(LIBPCAP)

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

airbase-ng$(EXE): $(OBJS_AB) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_AB) -o $(@) $(LIBS) $(LIBSSL) -lpthread

airdecloak-ng$(EXE): $(OBJS_AU)
	$(CC) $(CFLAGS) $(OBJS_AU) -o $(@)

tkiptun-ng$(EXE): $(OBJS_TT) $(LIBOSD)
	$(CC) $(CFLAGS) $(OBJS_TT) -o $(@) $(LIBS) $(LIBSSL)

strip: $(BINFILES) $(SBINFILES)
	strip $(BINFILES) $(SBINFILES)

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(SBINFILES) $(BINFILES) $(OPTFILES) airolib-ng$(EXE) *.o wesside-ng$(EXE) tkiptun-ng$(EXE) easside-ng$(EXE) buddy-ng$(EXE)

distclean: clean

install: all
	$(MAKE) -C $(OSD) install
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(sbindir)
	install -m 755 $(SBINFILES) $(DESTDIR)$(sbindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -f $(DESTDIR)$(bindir)/aircrack-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/airdecap-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/packetforge-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/airolib-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/ivstools$(EXE)
	-rm -f $(DESTDIR)$(bindir)/kstats$(EXE)
	-rm -f $(DESTDIR)$(bindir)/buddy-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airodump-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airserv-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airtun-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/aireplay-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/wesside-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/easside-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airbase-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airuncloak-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/tkiptun-ng$(EXE)

check: aircrack-ng$(EXE)
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e Harkonen -q $(TEST_DIR)/wpa2.eapol.cap | grep 'KEY FOUND! \[ 12345678 \]' 
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e test -q $(TEST_DIR)/wpa.cap | grep 'KEY FOUND! \[ biscotte \]'


ifeq ($(CUDA), true)
CFLAGS += -DCUDA_ENABLED

NVCC := $(CUDA_INSTALL_PATH)/bin/nvcc
INCLUDES += -I. -I$(CUDA_INSTALL_PATH)/include
COMMONFLAGS += $(INCLUDES) -DUNIX

NVCCFLAGS += --compiler-options -fno-strict-aliasing --host-compilation=C $(COMMONFLAGS)

# Change this only if you have COMPUTE > 1.0
NVCCFLAGS += -maxrregcount 12

# Enable this for extra compiler and as output
#NVCCFLAGS += --ptxas-options "-v" --verbose

LIBSSL += -L$(CUDA_INSTALL_PATH)/lib -lcuda -lcudart

%.o : %.cu   
	$(NVCC) $(NVCCFLAGS) $(SMVERSIONFLAGS) -o $@ -c $<
endif
