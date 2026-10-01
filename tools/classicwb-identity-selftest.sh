#!/usr/bin/env bash
# Prove ClassicWB's default mDNS identity follows its per-checkout MAC.
#
# STRUCTURALLY UNABLE TO WIPE ANYTHING: classicwb.sh runs from a scratch copy
# of tools/, under `env -i` (no ambient AMINETXDUO_KICKSTART, snapshot path or
# asset store), with AMINETXDUO_CWB_IDENTITY_ONLY=1, which exits right after
# the identity and the standing check.  The drive and dist directories it
# would wipe hold sentinels, and the last check is that they are untouched.
# SPDX-License-Identifier: MIT

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

S=$(mktemp -d "${TMPDIR:-/tmp}/cwb-identity.XXXXXX")
trap 'rm -rf "$S"' EXIT
cp -R "$ROOT/tools" "$S/tools"
SENTINELS="$S/build/classicwb-cwb-a1200-plain-dh0 $S/build/cwb-dist-cwb-a1200-plain"
for d in $SENTINELS; do mkdir -p "$d"; echo keep > "$d/sentinel"; done

run() { # mac [classicwb arguments] -- stdout and stderr, then rc=
    local mac="$1"
    shift
    env -i PATH="$PATH" TMPDIR="$S" HOME=/nonexistent \
        AMINETXDUO_CWB_MAC="$mac" AMINETXDUO_CWB_IDENTITY_ONLY=1 \
        AMINETXDUO_BRIDGE_LOCK="$S/bridge.lock" \
        "$S/tools/classicwb.sh" "$@" 2>&1
    echo "rc=$?"
}

hostname_of() {
    sed -n 's/^hostname=//p' | head -1
}

# Standing-range addresses: ClassicWB is a standing guest and refuses any
# other (rig_standing_exempt), which the fifth check holds it to.
one_out=$(run 02:41:4d:47:12:34)
one=$(printf '%s\n' "$one_out" | hostname_of)
two=$(run 02:41:4d:47:56:78 | hostname_of)
named=$(run 02:41:4d:47:12:34 -n workshop | hostname_of)
refused=$(run 02:41:4d:49:12:34)

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

# Where it stopped: at the identity-only exit (rc=0), or, on a host with no
# flock(1), at the standing check (rc=2).  Nothing past either.
case "$one_out" in
    *"identity_only=1"*rc=0|*"flock(1) is not installed"*rc=2) ;;
    *) echo "the probe did not stop at the identity: $one_out" >&2
       bad=$((bad + 1)) ;;
esac
for d in $SENTINELS; do
    [ "$(cat "$d/sentinel" 2>/dev/null)" = keep ] || {
        echo "a probe touched $d" >&2; bad=$((bad + 1)); }
done

echo "classicwb identity selftest: $((7 - bad)) passed, $bad failed"
[ "$bad" = 0 ]
