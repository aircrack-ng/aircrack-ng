#!/bin/sh

bin="$1/parse"

for t in *.bin ; do
	echo -n "Checking $t: "
	args=""
	base="$(basename "$t" .bin)"
	if [ -f "$base.args" ] ; then
		args="$(cat "$base.args")"
	fi
	"$bin" $args $t | diff "$base.out" - && echo "OK" || echo "FAIL"
done
