#!/bin/bash
document_description "Git tools, to work with one of the bests cvs out there"

function git_stats {
document "git_stats" "Return git statistics" "Git LOG OPTIONS" && return
# awesome work from https://github.com/esc/git-stats
# including some modifications by Bash-It author and then by me.

if [ -n "$(git symbolic-ref HEAD 2> /dev/null)" ]; then
    echo "Number of commits per author:"; git --no-pager shortlog -sn --all

    LOGOPTS="$@"

    for a in $( git shortlog -sn --all | cut -f2 | cut -f1 -d' '); do
        echo "Statistics for: $a"
        echo -n "Number of files changed: "
        git log $LOGOPTS --all --numstat --format="%n" --author=$a | cut -f3 | sort -iu | wc -l
        echo -n "Number of lines added: "
        git log $LOGOPTS --all --numstat --format="%n" --author=$a | cut -f1 | awk '{s+=$1} END {print s}'
        echo -n "Number of lines deleted: "
        git log $LOGOPTS --all --numstat --format="%n" --author=$a | cut -f2 | awk '{s+=$1} END {print s}'
        echo -n "Number of merges: "
        git log $LOGOPTS --all --merges --author=$a | grep -c '^commit'
    done
else
    echo "you're currently not in a git repository"
fi
}

