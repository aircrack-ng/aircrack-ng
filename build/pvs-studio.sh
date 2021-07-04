#!/bin/sh

set -euf

pvs-studio-analyzer analyze -a "GA;OP;CS" -j8 -o PVS-Studio.log
plog-converter -a 'GA:1,2,3;64:1,2,3;OP:1,2,3' -d V1032,V1042,V597 -t errorfile PVS-Studio.log
plog-converter -a 'GA:1,2,3;64:1,2,3;OP:1,2,3' -d V1032,V1042,V597 -t csv -o pvs-report.csv PVS-Studio.log

./build/count-pvs-bugs.py pvs-report.csv 94
