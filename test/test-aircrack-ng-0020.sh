#!/bin/sh
# -*- tcl -*-
# The next line is executed by /bin/sh, but not expect \
exec ${EXPECT:=expect} "$0" ${1+"$@"}

set abs_builddir $::env(abs_builddir)
set abs_srcdir $::env(abs_srcdir)

exit -onexit {
    exp_internal 1
    exec rm -f pipe.cap
}

puts -nonewline "Aircrack-ng will tail PCAP files: "
flush stdout

log_user 0

exec cp ${abs_srcdir}/wep_64_ptw_01.cap pipe.cap

spawn ${abs_builddir}/../aircrack-ng -X pipe.cap
set tool_spawn_id $spawn_id

set timeout 900

# wait for startup
expect "Opening pipe.cap"

expect "got 2551 IVs"
expect "Failed. Next try with 5000 IVs."

exec cat ${abs_srcdir}/wep_64_ptw_02.cap >> pipe.cap
expect "Failed. Next try with 10000 IVs." { sleep 2 }

exec cat ${abs_srcdir}/wep_64_ptw_03.cap >> pipe.cap
exec cat ${abs_srcdir}/wep_64_ptw_04.cap >> pipe.cap
expect "got 10180 IVs"
expect {
    "Failed. Next try with 15000 IVs." { puts "OK\n"; exit 0 }
    eof { puts "FAILED"; exit 1 }
    timeout { puts "FAILED(timeout)"; exit 2 }
}

puts "FAILED(exceptional)"
exit 99
