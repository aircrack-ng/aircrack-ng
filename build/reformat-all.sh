#!/usr/bin/env bash

set -euf

if [ ! -e configure.ac ]; then
    echo "E: must be in root of project."
    exit 1
fi

find src \( -iname *.h -o -iname *.cpp -o -iname *.c \) -a \( ! -path "src/include/*" -a ! -path "src/aircrack-osdep/radiotap/*" \) | xargs clang-format -i -style=file

clang-format -i -style=file src/include/eapol.h
clang-format -i -style=file src/include/hashcat.h

