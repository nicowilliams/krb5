# Copyright (C) 2012 by the Massachusetts Institute of Technology.
# All rights reserved.
#
# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
#
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.

# This program attempts to detect MIT krb5 coding style violations
# attributable to the changes in a diff.  It is intended to be run at
# the top level of a krb5 source checkout with the diff as stdin.

import os
import re
import subprocess
import sys

line_re = re.compile(r'^\s*(\d+)  (.*)$')
def check_file(filename, new_lines):
    # Process only C source files under src.
    root, ext = os.path.splitext(filename)
    if not filename.startswith('src/') or ext not in ('.c', '.h', '.hin'):
        return
    dispname = filename[4:]

    p = subprocess.Popen(['python', 'src/util/krb5-check-cstyle.py', filename],
                          stdout=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        sys.exit(1)

    first = True
    for line in out.splitlines():
        m = line_re.match(line)
        if int(m.group(1)) in new_lines:
            if first:
                print dispname + ':'
                first = False
            print line

    if not first:
        print


chunk_header_re = re.compile(r'^@@ -\d+(,(\d+))? \+(\d+)(,(\d+))? @@')
def check_diff(lines):
    old_count, new_count, lineno = 0, 0, 0
    filename = None
    for line in lines:
        line = line.rstrip('\r\n')
        if not line or line.startswith('\\ No newline'):
            continue
        if old_count > 0 or new_count > 0:
            # We're in a chunk.
            if line[0] == '+':
                new_lines.append(lineno)
            if line[0] in ('+', ' '):
                new_count = new_count - 1
                lineno = lineno + 1
            if line[0] in ('-', ' '):
                old_count = old_count - 1
        elif line.startswith('+++ b/'):
            # We're starting a new file.  Check the last one.
            if filename:
                check_file(filename, new_lines)
            filename = line[6:]
            new_lines = []
        else:
            m = chunk_header_re.match(line)
            if m:
                old_count = int(m.group(2) or '1')
                lineno = int(m.group(3))
                new_count = int(m.group(5) or '1')

    # Check the last file in the diff.
    if filename:
        check_file(filename, new_lines)


check_diff(sys.stdin.readlines())
