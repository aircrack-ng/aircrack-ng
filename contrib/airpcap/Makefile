ROOT    = ../..
include $(ROOT)/common.mak

CFLAGS = -g -I../../../developers/Airpcap_Devpack/include -I../../../developers/WinPcap_Devpack/include
LIBS = -L ../../../developers/Airpcap_Devpack/lib -lairpcap -L ../../../developers/WinPcap_Devpack/lib -lwpcap


CFLAGS	+= $(PIC) -I$(ROOT)/src/osdep
OBJS	= airpcap.o
DLL	= airpcap.dll

all: $(DLL)

$(DLL): $(OBJS)
	$(CC) ${CFLAGS} -shared -o $(DLL) $(OBJS) ${LIBS}

clean:
	rm -f $(DLL) $(OBJS)
