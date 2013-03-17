#!/bin/bash
document_description "Time manipulation in bash"
scale=2

minutes(){
    document "minutes" "Convert seconds or hours to (aproximated when s or h lowercase) minutes" "[time][s|h|m|S|H|M]"  && return
    c=$(echo -n $@ |tail -c -1) 
    case $c in 
        s) echo $(( $(sed s/.$// <( echo "${@}" ) ) / 60 )) ;;
        S) echo "scale=$scale; $(sed s/.$// <( echo "${@}" ) ) / 60" | bc;;
        h) echo $(( $(sed s/.$// <( echo "${@}" ) ) * 60 )) ;;
        H) echo "scale=$scale; $(sed s/.$// <( echo "${@}" ) ) * 60" |bc  ;;
        m) sed s/.$// <( echo "${@}" ) ;;
        M) sed s/.$// <( echo "${@}" ) ;;
        *) echo $(( $(sed s/.$// <( echo "${@}" ) ) / 60 )) ;;
    esac
}

seconds(){
    document "seconds" "Convert minutes or hours to (aproximated when s or h lowercase) seconds" "[time][s|h|m|S|H|M]"  && return
    c=$(echo -n $@ |tail -c -1) 
    case $c in 
        m) echo $(( $(sed s/.$// <( echo "${@}" ) ) * 60 )) ;;
        M) echo "scale=$scale; $(sed s/.$// <( echo "${@}" ) ) * 60" | bc;;
        h) echo $(( $(sed s/.$// <( echo "${@}" ) ) * 3600 )) ;;
        H) echo "scale=$scale; $(sed s/.$// <( echo "${@}" ) ) * 60" |bc  ;;
        s) sed s/.$// <( echo "${@}" ) ;;
        S) sed s/.$// <( echo "${@}" ) ;;
        *) echo $(( $(sed s/.$// <( echo "${@}" ) ) * 60 )) ;;
    esac
}

delay(){ 
    { time=$1; shift; sleep $(seconds $time) && ${@}; } & 
} # I know... I know, sleep allows you to choose seconds minutes and all that. But hell, I had to do a practical example for this.
