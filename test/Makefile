ROOT		= ..
include $(ROOT)/common.mak

OBJS		= makeivs.o
BIN		= makeivs$(EXE)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(@)

clean:
	-rm -f $(BIN) $(OBJS)

distclean: clean

install: all
	install -d $(bindir)
	install -m 755 $(BIN) $(bindir)

uninstall:
	-rm -f $(bindir)/$(BIN)
