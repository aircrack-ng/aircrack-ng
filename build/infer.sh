#!/bin/sh

set -euf

infer --report-blacklist-path-regex lib/radiotap \
      --compilation-database compile_commands.json

[ -r infer-out/report.json ] || exit 2

exec ./build/count-infer-bugs.py infer-out/report.json 27
