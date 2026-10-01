#!/usr/bin/env bash
#
# Every call across a calling-convention boundary is pinned (-mregparm=3).
#
#   tools/check-call-abi.sh
#
# The rules, and why each exists, are in tools/check-call-abi.py; the
# crossings that are right unpinned are in tools/check-call-abi-allow.txt.
# The selftest runs first: it holds the six shipped instances in miniature,
# and a rule that stops seeing one fails here before the tree is read.
#
# Output: key=value lines, `call_abi=ok|fail ... findings=N` last.
# Exit 0 clean, 1 on a finding or a selftest miss, 2 on a usage error.
#
# SPDX-License-Identifier: MIT

set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$ROOT/tools/check-call-abi.py" --selftest
exec python3 "$ROOT/tools/check-call-abi.py" --root "$ROOT" "$@"
