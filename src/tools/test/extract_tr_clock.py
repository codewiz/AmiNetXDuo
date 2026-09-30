#!/usr/bin/env python3
"""Emit traceroute.c's EClock block verbatim, for the host test.

The host test must run the production tr_now() rather than re-type its
arithmetic, so it compiles the real function against a stubbed ReadEClock.
This script pulls the block from the `extern struct Device *TimerBase;`
declaration through the end of tr_now() -- the `checksum,` banner that opens
the next section marks the end -- and writes it to OUTPUT_INC.

Usage: extract_tr_clock.py TRACEROUTE_C OUTPUT_INC
"""

import re
import sys

START = "extern struct Device *TimerBase;"
END = "checksum,"
NEED = ("static ULONG tr_rate", "static BOOL tr_clock_open", "static ULONG tr_now")


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: extract_tr_clock.py TRACEROUTE_C OUTPUT_INC\n")
        return 2

    src, dst = argv[1], argv[2]
    with open(src, "r", encoding="ascii") as handle:
        lines = handle.readlines()

    start = end = None
    for i, line in enumerate(lines):
        if start is None and START in line:
            start = i
        if start is not None and END in line:
            end = i
            break

    if start is None or end is None or end <= start:
        sys.stderr.write("extract_tr_clock: markers not found in %s\n" % src)
        return 1

    body = "".join(lines[start:end])
    # Whitespace in traceroute.c is column-aligned, so collapse runs of it
    # before the sanity check: "static ULONG            tr_rate" must match
    # the single-spaced NEED token.
    norm = re.sub(r"\s+", " ", body)
    for token in NEED:
        if token not in norm:
            sys.stderr.write(
                "extract_tr_clock: %r missing from the extracted block\n" % token)
            return 1

    with open(dst, "w", encoding="ascii") as handle:
        handle.write(
            "/* Generated from traceroute.c by extract_tr_clock.py"
            " -- do not edit. */\n")
        handle.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
