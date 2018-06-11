#!/usr/bin/env bash

set -euf

if [ ! -e configure.ac ]; then
    echo "E: must be in root of project."
    exit 1
fi

find src -iname *.h -o -iname *.cpp -o -iname *.c | xargs clang-format -i -style=file
