ROOT    = ../..
include $(ROOT)/common.mak

CFLAGS	+= $(PIC) -I$(ROOT)/src/osdep
OBJS	= commview.o
DLL	= commview.dll
LIBS	= -liphlpapi -lsetupapi -luuid -lpthread

all: $(DLL)

$(DLL): $(OBJS)
	$(CC) -shared -o $(DLL) $(OBJS) $(LIBS)

clean:
	rm -f $(DLL) $(OBJS)
