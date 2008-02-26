ROOT    = ../..
include $(ROOT)/common.mak

CFLAGS	+= $(PIC) -I$(ROOT)/src/osdep
NAME	= omnipeek
OBJS	= $(NAME).o
DLL	= $(NAME).dll
LIBS	=

all: $(DLL)

$(DLL): $(OBJS)
	$(CC) -shared -o $(DLL) $(OBJS) $(LIBS)

clean:
	rm -f $(DLL) $(OBJS)
