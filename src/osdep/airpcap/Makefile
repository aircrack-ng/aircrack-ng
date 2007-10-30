ROOT	= ../../..
include $(ROOT)/common.mak

CFLAGS = $(PIC) -I$(ROOT)/../developers/Airpcap_Devpack/include -I$(ROOT)/src/osdep
LIBS = -L $(ROOT)/../developers/Airpcap_Devpack/lib -lairpcap

OBJS_AIRPCAP	= airpcap.o

all: $(OBJS_AIRPCAP)
	$(CC) ${CFLAGS} -o $(OBJS_AIRPCAP)

install: all

uninstall:

clean:
	rm -f *.o 
