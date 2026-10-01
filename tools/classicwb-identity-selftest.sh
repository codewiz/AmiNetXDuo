#!/usr/bin/env bash
# Prove ClassicWB's default mDNS identity follows its per-checkout MAC.
# SPDX-License-Identifier: MIT

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# The standing-address lock goes in a directory of our own, never beside a
# live guest's.
LOCKS=$(mktemp -d "${TMPDIR:-/tmp}/cwb-identity.XXXXXX")
trap 'rm -rf "$LOCKS"' EXIT

probe() { # mac [classicwb arguments]
    local mac="$1"
    shift
    AMINETXDUO_CWB_MAC="$mac" HOME=/nonexistent \
    AMINETXDUO_BRIDGE_LOCK="$LOCKS/bridge.lock" \
        "$ROOT/tools/classicwb.sh" "$@" 2>/dev/null || true
}

hostname_of() {
    sed -n 's/^hostname=//p' | head -1
}

# Standing-range addresses: ClassicWB is a standing guest and refuses any
# other (rig_standing_exempt), which the fifth check holds it to.
one=$(probe 02:41:4d:47:12:34 | hostname_of)
two=$(probe 02:41:4d:47:56:78 | hostname_of)
named=$(probe 02:41:4d:47:12:34 -n workshop | hostname_of)
refused=$(AMINETXDUO_CWB_MAC=02:41:4d:49:12:34 HOME=/nonexistent \
          AMINETXDUO_BRIDGE_LOCK="$LOCKS/bridge.lock" \
          "$ROOT/tools/classicwb.sh" 2>&1 > /dev/null; echo "rc=$?")

bad=0
[ "$one" = amiga-a1200-plain-471234 ] || {
    echo "wrong first default: '$one'" >&2; bad=$((bad + 1)); }
[ "$two" = amiga-a1200-plain-475678 ] || {
    echo "wrong second default: '$two'" >&2; bad=$((bad + 1)); }
[ "$one" != "$two" ] || {
    echo "two MAC addresses produced the same hostname" >&2; bad=$((bad + 1)); }
[ "$named" = workshop ] || {
    echo "-n was not preserved: '$named'" >&2; bad=$((bad + 1)); }

case "$refused" in
    *"REFUSING to start standing guest"*rc=2) ;;
    *) echo "a test-range MAC was not refused: $refused" >&2; bad=$((bad + 1)) ;;
esac

echo "classicwb identity selftest: $((5 - bad)) passed, $bad failed"
[ "$bad" = 0 ]
