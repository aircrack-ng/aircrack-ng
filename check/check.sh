#!/bin/sh

for t in *.bin ; do
	echo -n "Checking $t: "
	args=""
	base="$(basename "$t" .bin)"
	if [ -f "$base.args" ] ; then
		args="$(cat "$base.args")"
	fi
	../parse $args $t | diff "$base.out" - && echo "OK" || echo "FAIL"
done
