#!/bin/sh

test_tool()
{
	TOOL_PATH="${top_builddir}/src/${1}${EXEEXT}"
	if [ -f "${TOOL_PATH}" ]; then
		"${TOOL_PATH}"
		# Anything greater than 1 indicates it does not
		# exist or did not run properly (crash)
		[ $? -gt 1 ] && exit 1
	fi
}

test_tool airbase-ng
test_tool aircrack-ng
test_tool airdecap-ng
test_tool airdecloak-ng
test_tool aireplay-ng
test_tool airodump-ng
test_tool airolib-ng
test_tool airserv-ng
test_tool airtun-ng
test_tool airventriloquist-ng
test_tool besside-ng
test_tool besside-ng-crawler
# Buddy-ng doesn't have any parameters and requires root
#test_tool buddy-ng
test_tool easside-ng
test_tool ivstools
test_tool kstats
test_tool makeivs-ng
test_tool packetforge-ng
test_tool tkiptun-ng
test_tool wesside-ng
test_tool wpaclean

exit 0
