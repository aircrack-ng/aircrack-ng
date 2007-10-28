ROOT    = ../..
include $(ROOT)/common.mak

CFLAGS = -g -I$(ROOT)/../developers/Airpcap_Devpack/include -I$(ROOT)/src/osdep
#LIBS = -L $(ROOT)/../developers/Airpcap_Devpack/lib -lairpcap -L $(ROOT)/src/osdep -losdep
LIBS = -L $(ROOT)/../developers/Airpcap_Devpack/lib -lairpcap


CFLAGS	+= $(PIC) 
OBJS	= airpcap.o
DLL	= airpcap.dll

all: $(DLL)

$(DLL): $(OBJS)
	$(CC) ${CFLAGS} -shared -o $(DLL) $(OBJS) ${LIBS}

clean:
	rm -f $(DLL) $(OBJS)
