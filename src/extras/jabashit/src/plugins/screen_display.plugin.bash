#!/bin/bash
document_description "Screen tools, allows you to get all the power from your terminal, and from your xserver."
# Screen Utilities
X11_screen_reso(){ xrandr 2>/dev/null | grep "[[:digit:]].*x.*[[:digit:]]\*[[:blank:]]*$" | awk '{print $1}' ; }
X11_best_screen_reso(){ xrandr |awk '/\+$/ {print $1}'; }
X11_screen_outputs(){ xrandr |awk '/ connected/ {print $1}';  }
set_auto_X11_reso(){ 
    document "set_auto_X11_reso" "Sets the best (according to xrandr) resolution to all active screen outputs" "" && return 
    outputs=($(X11_screen_outputs)); a=($(X11_best_screen_reso)); b=0; for i in ${a[@]}; do output=${outputs[$b]}; xrandr --output $output --mode $i; addone b; done; }

auto_screensize(){
    document "auto_screensize" "Sets a bash trap to keep COLUMNS and LINES updated" "" && return
    trap 'COLUMNS=$(tput cols) LINES=$(tput lines)' WINCH; export AUTO_SCREENSIZE=1; 
}
screen_c(){  [[ "$AUTO_SCREENSIZE" ]] && echo $COLUMNS || tput cols; }
screen_l(){  [[ "$AUTO_SCREENSIZE" ]] && echo $LINES || tput lines; }
screen_goto(){ 
    document "screen_goto" "Put the cursor in a specific screen position" " Column [Row] " && return
    [[ "1" ]] && [[ "$2" ]] &&  echo -n -e "\033[${1};${2}H" || screen_goto_col $1; }
screen_goto_col(){ tput cuf $1; } 
print_at(){
    document "print_at" "Print text in a specific position" "COLUMNxROW" && return
    screen_goto $(split $1 x); shift; echo $@;
} 
echo_center(){ a=$2; [[ ! $a ]] && a=`screen_c`; print_at "`get_center $a ${#1}`" "$1"; }
mkline(){ 
    document "mkline" "Prints a line of a specified character during N times, or foreach column in current size" "CHAR [Cols]" && return
    [[ $2 ]] && { for i in `seq 0 $2`; do echo -n $1; done ; echo; } || {  eval printf "%.0s$1" {1..$(screen_c)}; }; 

}
