MAKEFLAGS += --no-print-directory

CC ?= "gcc"
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration
CFLAGS += -I/lib/modules/`uname -r`/build/include
CFLAGS += -O2 -g
LDFLAGS += -lnl

OBJS = airvif-ng.o interface.o info.o station.o util.o mpath.o
ALL = airvif-ng

ifeq ($(V),1)
Q=
NQ=true
else
Q=@
NQ=echo
endif

all: $(ALL)

%.o: %.c
		@$(NQ) ' CC  ' $@
		$(Q)$(CC) $(CFLAGS) -c -o $@ $<

airvif-ng:	$(OBJS)
		@$(NQ) ' CC  ' airvif-ng
		$(Q)$(CC) $(LDFLAGS) $(OBJS) -o airvif-ng

check:
		$(Q)$(MAKE) all CC="REAL_CC=$(CC) CHECK=\"sparse -Wall\" cgcc"

clean:
		$(Q)rm -f airvif-ng *.o *~
