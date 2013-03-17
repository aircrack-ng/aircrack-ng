#!/bin/bash
# General utils

get_source_path(){
    # Source: http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in
    {
        SCRIPT_PATH="${BASH_SOURCE[0]}";
        if [ -h "${SCRIPT_PATH}" ]; then while [ -h "${SCRIPT_PATH}" ]; do SCRIPT_PATH=`readlink "${SCRIPT_PATH}"`; done; fi
        pushd . > /dev/null; cd `dirname ${SCRIPT_PATH}` > /dev/null; SCRIPT_PATH=`pwd`; popd  > /dev/null
    } &>/dev/null
    echo $SCRIPT_PATH;
}

source_path=`get_source_path`;
declare -A loaded
debug=0;
. $source_path/__config
. $source_path/__main.theme

document(){ [[ $helpbuilder == 1 ]] && { docs[$1]=" $1 $3\n\t$2"; return 0; } || return 1; }
document_files(){ for i in "$@"; do document_file $i; done; }
document_file(){
    export helpbuilder=1;
    [[ $1 ]] && a=$1 || a=$0
    for i in `command grep "document " $a|command grep -v 'document()'|grep -v document_file|command awk '{print $2}'|tr '"' ' '`; do 
        $i;
    done
    export helpbuilder=0;
}

help(){
    document_files ${!loaded[@]} $source_path/general.plugin.bash
    [[ ! $1 ]] && { command help; echo "---- Jabashit help ----"; for i in "${docs[@]}"; do echo -en "$i"|head -n1; done; } || echo -e ${docs[$1]}
}

jabashit_plugins(){
    document "jabashit_plugins" "Shows a list of available jabashit plugins" ""
    cd $source_path; plugins_=(*); cd - &>/dev/null;
    declare -a plugins=( ${plugins_[@]/__*/} )
    echo ${plugins[@]/\.plugin\.bash/}
}

jabashit_describe_plugin(){
    document "jabashit_describe_plugin" "Shows an entire plugin documentation" "" && return
    bash -c "source $(source_jabashit); jabashit_describe_plugin_ $@;"
}

function document_description() {
    [[ $document_description_enabled == 1 ]] && echo -e "\t${@}";
    export document_description_enabled=0;
}

jabashit_describe_plugin_(){
    unset docs; source $(source_jabashit); 
    echo -e "Documentation for $1";
    document_description_enabled=1; load $1; 
    document_file $source_path/$1.plugin.bash
    echo
    for i in "${docs[@]}";
        do echo -e $i; 
    done
}

load(){ # For backwards compatibility, undocumented (awful ;-) )  
    jabashit_load $@;
}

function jabashit_api(){
    document "jabashit_api" "Show all available functions and plugins for jabashit" "" && return 
    for i in $(jabashit_plugins); do jabashit_describe_plugin $i; echo -e "\n"; done
}

build_docs(){
    document_files ${available_plugins} 
    [[ ! $1 ]] && { command help; echo "---- Jabashit help ----"; for i in "${docs[@]}"; do echo -en "$i"|head -n1; done; } || echo -e ${docs[$1]}
}
addone(){
    document "addone" "Increases by one varname." "VAR_TO_INCREASE" && return
    export $1=$(( $1 + 1 )); 
}

_(){
    document "_" "Calls gettext for translation" "TEXT" && return
    gettext "$@";
}

max_len_in_array(){
    document "max_len_in_array" "Gets max lenght in array passed as argument" "array" && return 
    o=0; { for i in "${@}"; do (( ${#i} > $o )) && o=${#i}; done } &>/dev/null; 
    echo -n $o;
}

get_center(){
    document "get_center" "Gets the center , or, if specified a variable, where to start printing it to make it centered"\
        "number [string]" && return
    [[ $2 ]] && echo $(( ( $1 - $2 ) / 2 )) || echo $(( $1 / 2 )); 
}

split(){ 
    document "split" 'Returns an array replacing \$2 in \$1' "STRING SEPARATOR" && return
    echo $1|tr $2 " ";
}

jabashit_load(){
    document "jabashit_load" "Load a specific file or a jabashit plugin" "file|pluginname" && return
    for i in "${@}"; do 
        [[ ! ${loaded[$i]} ]] && { 
            if [ -f $source_path/$i.plugin.bash ]; then _load $source_path/$i.plugin.bash; else _load $i; fi;
            } 
    done;
}
_load(){ source $1 && loaded[$1]=1 || load_failed "$@";  }
load_failed(){  _ "Failed loading: "; echo -e "\t$1"; }
