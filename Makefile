CFLAGS = -g -Wall


parse:	parse.c radiotap.c

check-all:	parse
	(cd check && sh check.sh)

clean:
	rm -f *~ *.o parse
