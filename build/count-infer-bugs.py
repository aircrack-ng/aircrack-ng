#!/usr/bin/python3

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2020-2021  Kevin R. Croft <krcroft@gmail.com>
# Copyright (C) 2020-2022  Joseph Benden <joe@benden.us>

"""
Count the number of issues found in an Infer report.

Usage: count-infer-bugs.py REPORT [MAX-ISSUES]
Where:
 - REPORT is a file in JSON-format
 - MAX-ISSUES is as a positive integer indicating the maximum
   issues that should be permitted before returning failure
   to the shell. Default is non-limit.

"""

# pylint: disable=invalid-name
# pylint: disable=missing-docstring

import collections
import os
import json
import sys

def parse_issues(filename):
    """
    Returns a dict of source filename keys having occurrence-count values

    """
    cwd = os.getcwd()
    issues = collections.defaultdict(int)
    types = collections.defaultdict(int)
    with open(filename) as csvfile:
        reader = json.load(csvfile)
        for row in reader:
            bug_type = row['bug_type_hum'] or row['bug_type']
            sourcefile = os.path.realpath(row['file'])
            # Skip non-file lines
            if not sourcefile.startswith('/'):
                continue
            sourcefile = os.path.relpath(sourcefile, cwd)
            issues[sourcefile] += 1
            types[bug_type] += 1
    return issues, types


def main(argv):
    # assume success until proven otherwise
    rcode = 0

    # Get the issues and the total tally
    issues, types = parse_issues(argv[1])
    tally = sum(issues.values())
    tally_types = sum(types.values())

    if tally_types > 0:
        # find the longest entry
        longest_name = max(len(entry) for entry in types.keys())
        # Print the category and their issue counts
        print("Counts sorted by bug category:\n")

        for entry in sorted(types, key=types.get, reverse=True):
            print(f'  {entry:{longest_name}} : {types[entry]}')

    print("")

    if tally > 0:
        # find the longest source filename
        longest_name = max(len(sourcefile) for sourcefile in issues.keys())
        # Print the source filenames and their issue counts
        print("Counts sorted by filename:\n")

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
