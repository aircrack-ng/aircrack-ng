AC_ROOT		= ..
include $(AC_ROOT)/common.mak

TEST_DIR	= $(AC_ROOT)/test

CFLAGS		+= -Iinclude

all: test-hex_string_to_array

test-hex_string_to_array:
	$(CC) $(CFLAGS) $(LDFLAGS) test-hex_string_to_array.c ../src/common.c -o $(@) $(LDFLAGS)

clean:
	-rm -f test-hex_string_to_array.o test-hex_string_to_array$(EXE)

check: all
	./test-hex_string_to_array.sh
