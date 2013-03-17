#!/bin/bash
document_description "Colouring functions, easily customizable and themable colouring for your scripts"
declare -A colors highlights
get_color(){
    document "get_color" "Return a color, either a colorcode or one of the color list" "colorname" && return
    [[ $1 < 254 ]] && { echo $1; } || { echo ${colors[$1]} ; } ; }
colorize(){
    document "colorize" "Colorize bg and fg for a specific frase" "bg fg frase" && return
    a=($(split $1 ","));
    fg=$(get_color ${a[1]});
    bg=$(get_color ${a[2]});
    ef=$(get_color ${a[0]}); 
    [[ $bg ]] && tput setab $bg
    [[ ${fg} ]] && tput setaf $fg
    [[ ${ef} != "0" ]] && tput $ef
    echo -en "$2"; tput sgr0
}
