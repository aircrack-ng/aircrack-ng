#!/bin/sh

set -euf

pvs-studio-analyzer analyze -j8 -o PVS-Studio.log
plog-converter -a 'GA:1,2,3;64:1,2,3;OP:1,2,3' -d V1042 -t errorfile PVS-Studio.log
