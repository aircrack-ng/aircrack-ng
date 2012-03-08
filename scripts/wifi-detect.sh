#!/bin/sh
#this script is a compare and combine for detecting wifi cards using old vs new methods.
#this is intended for reference and testing not actual use
#I have added it to svn so that others can watch my insanity, it will be cleared when I am done with it.

        for iface in `ls -1 /sys/class/net`
        do
                if $(grep -q DEVTYPE=wlan /sys/class/net/${iface}/uevent)
                then
			added_by_ls="${added_by_ls}\n ${iface}"
		fi
	done
	for iface in `iwconfig 2> /dev/null | sed 's/^\([a-zA-Z0-9_]*\) .*/\1/'`
	do
		from_iwconfig="${from_iwconfig}\n ${iface}"
	done
	echo "ls ${added_by_ls}"
	echo "iwconfig ${from_iwconfig}"

	REAL_DEVS=$(echo "${added_by_ls}\n ${from_iwconfig}" | sort -bu)
	echo "real $REAL_DEVS"
