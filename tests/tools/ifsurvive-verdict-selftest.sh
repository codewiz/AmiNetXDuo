#!/usr/bin/env bash
#
# Prove tests/tools/ifsurvive-verdict.sh can fail.
#
#   tests/tools/ifsurvive-verdict-selftest.sh
#
# The FORCE leg of run-ifsurvive.sh needs an emulator, a ROM and a bridged
# rig.  Its host-ping verdict is checked here against synthetic iputils -D
# output: a guest silent from the FORCE, one lost probe, a stall, a slow
# baseline probe hiding a stall, a stream with no summary or cut short, one
# probe carrying a long removal, and an empty stream must all fail; a clean
# run must pass.
#
# SPDX-License-Identifier: MIT

set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
. "$ROOT/tests/tools/ifsurvive-verdict.sh"

f=""; r=""; out=""; v=0; ok=0; bad=0
dir=$(mktemp -d "${TMPDIR:-/tmp}/claudecode-ifsurvive-selftest.XXXXXX") || exit 2
# 200 ms probes from t=100.000 (seq 1..30); FORCE window 101.9..103.1
# widened, a 1000 ms removal; stop 106.0.
gen() { # name lostfrom lostto spike_seq spike_ms summary last_seq
    local q ts rtt
    f="$dir/$1.txt"
    echo "PING 192.168.1.5 (192.168.1.5) 56(84) bytes of data." > "$f"
    for q in $(seq 1 "${7:-30}"); do
        [ "$q" -ge "$2" ] && [ "$q" -le "$3" ] && continue
        rtt=2.0; [ "$q" = "$4" ] && rtt="$5"
        ts=$(awk -v q="$q" -v r="$rtt" 'BEGIN { printf "%.3f", 100 + (q - 1) * 0.2 + r / 1000 }')
        echo "[$ts] 64 bytes from 192.168.1.5: icmp_seq=$q ttl=255 time=$rtt ms" >> "$f"
    done
    [ "$6" = 1 ] &&
        echo "${7:-30} packets transmitted, ${7:-30} received, 0% packet loss" >> "$f"
    true
}
check() { # name want(pass|fail) [window start] [window end] [force ms]
    local ws="${3:-101.9}" we="${4:-103.1}" fm="${5:-1000}"
    r=$(ifs_host_window "$f" "$ws" "$we" 200 106.0)
    out=$(ifs_host_verdict "$r" "$we" 250 "$fm")
    v=$?
    if { [ "$2" = pass ] && [ "$v" = 0 ]; } || { [ "$2" = fail ] && [ "$v" != 0 ]; }; then
        ok=$((ok + 1)); echo "ifsurvive_selftest case=$1 want=$2 ok=1 parse=\"$r\" reason=\"$out\""
    else
        bad=$((bad + 1)); echo "ifsurvive_selftest case=$1 want=$2 ok=0 parse=\"$r\" reason=\"$out\""
    fi
}
gen clean 99 99 0 0 1;              check clean pass
gen no_summary 99 99 0 0 0;         check no_summary fail
gen silent_from_force 11 30 0 0 1;  check silent_from_force fail
gen silent_no_summary 11 30 0 0 0;  check silent_no_summary fail
gen one_lost 13 13 0 0 1;           check one_lost fail
gen stall 99 99 14 900 1;           check stall fail
gen baseline_spike 99 99 3 900 1
awk '/icmp_seq=13 /{ sub(/time=2.0/, "time=300.0") } { print }' "$f" > "$f.x" && mv "$f.x" "$f"
                                    check baseline_spike fail
gen truncated 99 99 0 0 1 15;       check truncated fail
gen one_probe_long_force 99 99 0 0 1
                                    check one_probe_long_force fail 102.05 102.25 1220
gen empty 1 30 0 0 0;  : > "$f";    check empty fail
gen no_baseline 1 30 0 0 0;         check no_baseline fail
# A peer that cannot reach the guest: iputils' error lines, no reply.
f="$dir/unreachable.txt"
{ echo "PING 192.168.1.5 (192.168.1.5) 56(84) bytes of data."
  echo "[100.100] From 192.168.1.2 icmp_seq=1 Destination Host Unreachable"
  echo "6 packets transmitted, 0 received, +6 errors, 100% packet loss"; } > "$f"
check unreachable fail

# The leg itself: no peer, or a peer without iputils, is a SKIP.
leg() { # name want(run|skip) peer version
    local why rc
    why=$(ifs_peer_leg "$3" "$4"); rc=$?
    if { [ "$2" = run ] && [ "$rc" = 0 ]; } || { [ "$2" = skip ] && [ "$rc" = 2 ]; }; then
        ok=$((ok + 1)); echo "ifsurvive_selftest case=$1 want=$2 ok=1 reason=\"$why\""
    else
        bad=$((bad + 1)); echo "ifsurvive_selftest case=$1 want=$2 ok=0 rc=$rc reason=\"$why\""
    fi
}
leg no_peer skip "" ""
leg peer_without_iputils skip turo@peer "ping from BusyBox v1.36.1
peer_can_ping=1"
leg peer_without_raw_icmp skip turo@peer "ping from iputils 20240117"
leg peer_with_iputils run turo@peer "ping from iputils 20240117
peer_can_ping=1"

# The clock offset: a peer 2.5 s ahead, read inside a 40 ms round trip.
o=$(ifs_peer_offset 1000.000 1002.520 1000.040)
if [ "$o" = "2.500 0.020" ]; then
    ok=$((ok + 1)); echo "ifsurvive_selftest case=peer_offset ok=1 got=\"$o\""
else
    bad=$((bad + 1)); echo "ifsurvive_selftest case=peer_offset ok=0 got=\"$o\""
fi

rm -rf "$dir"
echo "ifsurvive_selftest_cases=$((ok + bad)) failed=$bad"
[ "$bad" = 0 ] && echo "ifsurvive-verdict selftest: $ok of $((ok + bad)) cases" && exit 0
echo "ifsurvive_selftest=FAIL"; exit 1
