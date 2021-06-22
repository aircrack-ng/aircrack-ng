#!/usr/bin/python3

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2020-2021  Kevin R. Croft <krcroft@gmail.com>

"""
Count the number of issues found in an PVS-Studio report.

Usage: count-pvs-issues.py REPORT [MAX-ISSUES]
Where:
 - REPORT is a file in CSV-format
 - MAX-ISSUES is as a positive integer indicating the maximum
   issues that should be permitted before returning failure
   to the shell. Default is non-limit.

"""

# pylint: disable=invalid-name
# pylint: disable=missing-docstring

import collections
import csv
import os
import sys

def parse_issues(filename):
    """
    Returns a dict of source filename keys having occurrence-count values

    """
    cwd = os.getcwd()
    issues = collections.defaultdict(int)
    with open(filename) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Skip non-file lines
            if not row['FilePath'].startswith('/'):
                continue
            sourcefile = os.path.realpath(row['FilePath'])
            # Skip non-file lines
            if not sourcefile.startswith('/'):
                continue
            sourcefile = os.path.relpath(sourcefile, cwd)
            issues[sourcefile] += 1
    return issues


def main(argv):
    # assume success until proven otherwise
    rcode = 0

    # Get the issues and the total tally
    issues = parse_issues(argv[1])
    tally = sum(issues.values())

    if tally > 0:
        # find the longest source filename
        longest_name = max(len(sourcefile) for sourcefile in issues.keys())
        # Print the source filenames and their issue counts
        print("Sorted by issue count:\n")

        for sourcefile in sorted(issues, key=issues.get, reverse=True):
            print(f'  {sourcefile:{longest_name}} : {issues[sourcefile]}')

    # Print the tally against the desired maximum
    if len(sys.argv) == 3:
        max_issues = int(sys.argv[2])
        print(f'\nTotal: {tally} issues (out of {max_issues} allowed)')
        if tally > max_issues:
            rcode = 1
    else:
        print(f'\nTotal: {tally} issues')

    return rcode

if __name__ == "__main__":
    sys.exit(main(sys.argv))
