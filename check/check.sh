#!/bin/sh

for t in *.bin ; do
	echo -n "Checking $t: "
	../parse $t | diff $(basename $t .bin).out - && echo "OK" || echo "FAIL"
done
