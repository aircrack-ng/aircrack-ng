ROOT    = ../..
include $(ROOT)/common.mak

#CFLAGS = -g -O -mno-cygwin  -I ../../../include -I ../../../../WinPcap_Devpack/include
#CFLAGS = -mno-cygwin -I ../../../include
CFLAGS = -I ../../../include
#LIBS = -L ../../../lib -L ../../../../WinPcap_Devpack/lib -lwpcap -lairpcap
LIBS = -L ../../../lib -lairpcap


PATH1 = ../../../lib

CFLAGS	+= $(PIC) -I$(ROOT)/src/osdep
OBJS	= airpcap.o
DLL	= airpcap.dll

all: $(DLL)

$(DLL): $(OBJS)
	$(CC) ${CFLAGS} -shared -o $(DLL) $(OBJS) ${LIBS}

clean:
	rm -f $(DLL) $(OBJS)
