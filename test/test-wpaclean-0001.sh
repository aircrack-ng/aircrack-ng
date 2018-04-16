#!/bin/sh

set -ef

if test ! -e "${top_builddir}/src/wpaclean${EXEEXT}"; then
    echo "Skipped: $0"
    exit 0
fi

"${top_builddir}/src/wpaclean${EXEEXT}" \
    -nvr \
    "${abs_srcdir}/wpaclean_crash.pcap"

exit 0

