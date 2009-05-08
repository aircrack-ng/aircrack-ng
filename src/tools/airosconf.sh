#!/bin/bash
# Airoscript configuration management script
# Same licensing as the rest of the airoscript project (gpl2+)
# Warning, this is a very limited way to configure airoscript, use it at your own risk.
# Anyway, it's usefull for new installations.
# Copyright (C) 2009 David Francos Cuartero
#        This program is free software; you can redistribute it and/or
#        modify it under the terms of the GNU General Public License
#        as published by the Free Software Foundation; either version 2
#        of the License, or (at your option) any later version.

#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#        GNU General Public License for more details.

#        You should have received a copy of the GNU General Public License
#        Along with this program; if not, write to the Free Software
#        Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


function _set_airoscript(){
	$tmp=`mktemp`
	grep -v $third /etc/airoscript.conf > $tmp
	echo "$third = \"$fourth\" " > /etc/airoscript.conf
}

function _set_airosperl(){
	if [ $a != "--force-yes" ]; then
		read -p "Are you sure to do this? If you've got an improper (more than one scalar per line) conffile, this can break it. (N/y)" YN && [[ $YN != "y" ]] && exit 
	fi
	if [ "`perl -e 'print ref($3)' `" == "SCALAR" ] || [ "`perl -e 'print ref ($3)'`" == "" ];
	then
		tmp=`mktemp`
		grep -v "$third" /etc/airosperl.conf |grep -v "1;"> $tmp
		echo -e "\nour \$$third=\"$fourth\";\n1;" >> $tmp
		mv $tmp /etc/airosperl.conf
	else
		echo "ERROR: value must be scalar in conffile."
	fi
}

function _update_from_airoscript(){
	source /etc/airoscript.conf
	echo -e "our (\$q,\n\$FT,\n\$FAKE_MAC,\n\$INJMAC,\n\$INJECTRATE,\n\$TKIPTUN_MAX_PL,\n\$TKIPTUN_MIN_PL,\n\$Client_IP,\n\$Host_IP,\n\$FRAG_HOST_IP,\n\$FRAG_CLIENT_IP)=("\"",\n"f",\n$FAKE_MAC,\n'FF:FF:FF:FF:FF:FF',\n$INJECTRATE,\n$TKIPTUN_MAX_PL,\n$TKIPTUN_MIN_PL,\n$Host_IP,\n$Client_IP,\n$FRAG_HOST_IP,\n$FRAG_CLIENT_IP);\n%our termopts('exec'=>'-e');\n$apath=\"/usr/bin/\";\n$bpath=\"/usr/sbin/\";\n$cpath=\"/sbin/\";\nour %bin=(\n'terminal' => \$apath.'xterm',\n'airmon' '> \$bpath.'airmon-ng',\n'ifconfig' => \$cpath.'ifconfig',\n'airodump' => \$bpath.'airodump-ng',\n'aireplay' => \$bpath.'aireplay-ng');\n1;" > /etc/airosperl.conf
exit
}

function _set {
	case $second in
		--to-airoscript) _set_airoscript;;
		--to-airosperl) _set_airosperl;;
	esac

}

function _update {
	if [ $second == "--from-airoscript" ]; then
		# Update airosperl.conf from airoscript
			read -p "You are about to deleted old airosperl conf. Continue?[Y/n]" YN && [[ $YN != "n" ]] && _update_from_airoscript
	else
		# Update airoscript.conf from airosperl
		echo -e "Not yet supported. \n Maybe when I decide to use yaml conf files."
	fi

}
first=$1;second=$2;third=$3;fourth=$4;
a=$5;
case $1 in 
	--set) _set;;
	--update) _update;;
esac

