#!/bin/bash

document_description "Device tools, handy functions to get all the power from your hardware"

cdtool(){
    document "cdtool" "Manipulate cdrom device" "[save|write_iso|write_dir|erase_dev] [device] [destination]" && return
    [[ $1 == "save"  ]] && { dd if=$2 of=$3 bs=2048 conv=sync,notrunc; }
    [[ $1 == "write_iso" ]] && { wodim -eject -tao speed=1 dev=$2 -v -data $3 || wodim -eject -tao speed=1 dev=$2 -v -data $3; }
    [[ $1 == "write_dir" ]] && { temp=`mktemp`; mkisofs -o $temp.iso -J -r -v -V $3 $4; cdtool "write_iso" $2 $temp.iso; rm $temp.iso; }
    [[ $1 == "erase_dev" ]] && { wodim blank=fast -eject dev=$2; }
}


battery_percentage(){
    document "battery_percentage" "Get battery percentage" "" && return
    awk '/Battery/ {print substr($4,1,2)}' <(acpi); 
}
