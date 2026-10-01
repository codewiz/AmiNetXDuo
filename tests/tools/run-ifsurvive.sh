#!/usr/bin/env bash
#
# REMOVE ONE INTERFACE, THEN USE THE OTHER ONE.
#
#   tests/tools/run-ifsurvive.sh [-b builddir] [-t seconds] [-B iface]
#                                [-a address] [-c address] [-g gateway]
#
# Two interfaces on a2065.device UNIT=0 -- the shipping rig config, which
# run-ifslots.sh already stages four of.  Traffic goes out over A (an ARP/ping
# exchange and three name resolutions), A is removed, and B has to still have a
# wire AND still reach something OFF-LINK.  Then B goes too and nothing may be
# left holding the unit.
#
# THE TWO BUGS THAT SHIPPED THROUGH THIS GAP, and what each needs to bite:
#
#   77896ac2  S2_OFFLINE was addressed to the DEVICE, not to the last opener of
#             the unit, so removing one interface took the sibling's wire.  An
#             ON-LINK ping over B catches it.
#   afedeb06  nx_ip_interface_detach clears nx_ip_gateway_address MACHINE-WIDE,
#             and the LAST interface to bind owns it, so removing that one left
#             the survivor able to reach its own subnet and nothing else.  An
#             on-link ping passes with no gateway at all, so only an OFF-LINK
#             destination catches it.  A is therefore the DHCP interface and is
#             added SECOND: NetX installs the gateway at bind.
#
# THEN FORCE WITH A CONNECTION OPEN.  A third interface, zforce, static on the
# same unit, carries a TCP connection the guest opens to its own zforce
# address (NetX routes an interface's own address to that interface, so the
# connection counts as zforce's).  A plain removal must refuse; then, while
# aeth0 pings the gateway, `RemoveNetInterface zforce FORCE` must return
# within FORCE_MS (rc 0, or 5 for a device that kept requests), aeth0 must
# lose no ping, and the gateway and DNS checks must still pass after it.
# This is the PiStorm32 defect of 2026-09-26: one FORCE removal stopped every
# interface.  -c pins zforce's address, else a second one is claimed.
#
# BRIDGED.  -B names the host NIC (default $AMINETXDUO_AMIBERRY_BACKEND, else
# ens18).  B's static address is claimed from the rig's free range the way
# run-events.sh claims one, or pinned with -a; -g is the segment's router.
#
# Exit: 0 pass, 1 a claim failed, 2 the rig did not produce something to read.
#
# SPDX-License-Identifier: MIT

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT" || exit 2

. "$ROOT/tools/test-verdict.sh"
. "$ROOT/tools/serial-log.sh"

BUILD="${AMINETXDUO_BUILD:-build/cm}"
BOARD=a2065
TIMEOUT=450
MIN_CHECKS=23
IFACE="${AMINETXDUO_AMIBERRY_BACKEND:-ens18}"
ADDRESS=
ADDRESS2=
GATEWAY="${AMINETXDUO_IFSURVIVE_GATEWAY:-192.168.1.1}"

# A resolution that comes back at all but takes longer than this is the user's
# symptom: the sibling did not fail, it stalled.
STALL_MS="${AMINETXDUO_IFSURVIVE_STALL_MS:-8000}"

# Off-link by construction: it is not on the bridged segment, so reaching it
# needs a gateway.
OFFLINK="${AMINETXDUO_IFSURVIVE_OFFLINK:-8.8.8.8}"

# How long RemoveNetInterface FORCE may take with a connection open.  The
# device stop is bounded at about ten seconds for a device that answers
# nothing (sana2_internal.h); this one answers.
FORCE_MS="${AMINETXDUO_IFSURVIVE_FORCE_MS:-15000}"
FORCE_PORT=7777

# The two probes that must span the FORCE window.  The guest's: back to back
# (-i 0, one request in flight), started right before the FORCE, and enough of
# them to outlast it; every one must be SENT and none lost.  The host's: Linux
# iputils at its non-root minimum interval, started seconds before the FORCE
# and stopped seconds after it, from the host to aeth0's address.
GUEST_PING_COUNT=3000
GUEST_PING_TIMEOUT=90
HOST_PING_INTERVAL_MS=200
HOST_PING_TAIL_S=5

# The watcher polls tools.txt this often, so every window edge it stamps is
# when the HOST SAW the line, up to this late.  Host probes are selected over
# the window widened by it at both ends, so polling can only add probes to the
# window, never drop the ones a stall hit.
POLL_MS=100

# ifs_host_window and ifs_host_verdict: tests/tools/ifsurvive-verdict.sh,
# proved by tests/tools/ifsurvive-verdict-selftest.sh.
. "$ROOT/tests/tools/ifsurvive-verdict.sh"

while getopts "b:t:N:B:a:c:g:" opt; do
    case "$opt" in
        b) BUILD="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        N) BOARD="$OPTARG" ;;
        B) IFACE="$OPTARG" ;;
        a) ADDRESS="$OPTARG" ;;
        c) ADDRESS2="$OPTARG" ;;
        g) GATEWAY="$OPTARG" ;;
        *) echo "usage: $0 [-b builddir] [-t seconds] [-N board] [-B iface]\
 [-a address] [-c address] [-g gateway]" >&2
           exit 2 ;;
    esac
done

case "$IFACE" in
    slirp|slirp_inbound)
        echo "run-ifsurvive.sh runs bridged: -B names the host NIC the guest\
 bridges onto" >&2
        exit 2 ;;
esac

if [ "$BOARD" != a2065 ]; then
    echo "run-ifsurvive.sh stages a2065.device in both interface files: the\
 point is two interfaces on ONE unit, so -N $BOARD would bring nothing up." >&2
    exit 2
fi

TOOLS="$ROOT/$BUILD/src/tools"
BSD="$ROOT/$BUILD/src/bsdsocket/bsdsocket.library"
NEEDED="ToolsSmoke AddNetInterface RemoveNetInterface ShowNetStatus
        netstat ping nslookup nc"

for t in $NEEDED; do
    [ -f "$TOOLS/$t" ] || { echo "build $BUILD first: no $TOOLS/$t" >&2
                            exit 2; }
done
[ -f "$BSD" ] || { echo "build $BUILD first: no $BSD" >&2; exit 2; }

[ -n "${AMINETXDUO_KICKSTART:-}" ] || {
    echo "No Kickstart.  Set AMINETXDUO_KICKSTART=<rom>." >&2; exit 2; }

A2065="${AMINETXDUO_A2065:-}"
if [ -z "$A2065" ]; then
    for c in "$ROOT/build/a2065.device" "$HOME/amiga-assets/devs/a2065.device"
    do
        [ -f "$c" ] && { A2065="$c"; break; }
    done
fi
[ -n "$A2065" ] && [ -f "$A2065" ] || {
    echo "No a2065.device found.  Set AMINETXDUO_A2065=<path>." >&2; exit 2; }

# shellcheck source=../../tools/emu-rig-lock.sh
. "$ROOT/tools/emu-rig-lock.sh"
if [ -z "$ADDRESS" ]; then
    rig_claim_address "${AMINETXDUO_RIG_ADDR_PREFIX:-192.168.1}" \
                      "${AMINETXDUO_RIG_ADDR_FIRST:-200}" \
                      "${AMINETXDUO_RIG_ADDR_LAST:-254}" \
                      "run-ifsurvive in $ROOT" || {
        echo "no free guest address; pass -a <addr> to pin one" >&2; exit 2; }
    ADDRESS="$RIG_ADDRESS"
fi
if [ -z "$ADDRESS2" ]; then
    rig_claim_address "${AMINETXDUO_RIG_ADDR_PREFIX:-192.168.1}" \
                      "${AMINETXDUO_RIG_ADDR_FIRST:-200}" \
                      "${AMINETXDUO_RIG_ADDR_LAST:-254}" \
                      "run-ifsurvive zforce in $ROOT" || {
        echo "no second free guest address; pass -c <addr> to pin one" >&2
        exit 2; }
    ADDRESS2="$RIG_ADDRESS"
fi
echo "guest_address=$ADDRESS force_address=$ADDRESS2 gateway=$GATEWAY iface=$IFACE"

# ------------------------------------------------------------- the stage ---

STAGE="$ROOT/build/ifsurvive-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/libs" "$STAGE/devs/NetInterfaces"
cp "$BSD" "$STAGE/libs/bsdsocket.library"
cp "$A2065" "$STAGE/devs/a2065.device"

# What this run is a result for.
ifs_sha() { { sha256sum "$1" 2> /dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }
echo "git_head=$(git -C "$ROOT" rev-parse HEAD 2> /dev/null || echo none)\
 bsdsocket_sha256=$(ifs_sha "$STAGE/libs/bsdsocket.library")\
 a2065_sha256=$(ifs_sha "$STAGE/devs/a2065.device")"

# B SURVIVES and binds FIRST; A is DHCP, binds SECOND and therefore owns the
# machine's gateway, which is what makes the detach path's clear observable.
# B carries a GATEWAY line of its own: the hand-off has nothing to hand over
# otherwise, and an interface with no gateway is not a candidate for one.
printf 'DEVICE=a2065.device\nUNIT=0\nCONFIGURE=STATIC\nADDRESS=%s\nNETMASK=255.255.255.0\nGATEWAY=%s\n' \
    "$ADDRESS" "$GATEWAY" > "$STAGE/devs/NetInterfaces/aeth0"
printf 'DEVICE=a2065.device\nUNIT=0\nCONFIGURE=DHCP\n' \
    > "$STAGE/devs/NetInterfaces/zeth1"
# The FORCE leg's interface: static, no gateway of its own, so aeth0 keeps the
# route and its pings stay on aeth0.
printf 'DEVICE=a2065.device\nUNIT=0\nCONFIGURE=STATIC\nADDRESS=%s\nNETMASK=255.255.255.0\n' \
    "$ADDRESS2" > "$STAGE/devs/NetInterfaces/zforce"

# THE GATEWAY MUST ANSWER ICMP FROM THIS ADDRESS AT ALL.  The lab router
# answers some rig addresses and silently ignores every ICMP request from
# others (192.168.1.224 and .232 on 2026-10-01: no reply on the wire, on-link
# or forwarded off-link, with aeth0 alone, while .244 answered every one).
# aeth0 pings it alone first; no reply there leaves the ping checks below
# undecidable, so the run says so and exits 2 rather than FAIL.
BASEPING="SYS:ping $GATEWAY -c 3 -t 15"

{
    echo "SYS:AddNetInterface aeth0"
    echo "$BASEPING"
    echo "SYS:AddNetInterface zeth1"
    echo "SYS:netstat -i"
    echo "SYS:ShowNetStatus"
    echo "SYS:ping $GATEWAY -c 3 -t 20"
    echo "SYS:ping $OFFLINK -c 3 -t 20"
    echo "SYS:ShowNetStatus ICMP"
    echo "SYS:nslookup example.com $OFFLINK"
    echo "SYS:nslookup www.example.com $OFFLINK"
    echo "SYS:nslookup example.org $OFFLINK"
    echo "SYS:RemoveNetInterface zeth1"
    echo "SYS:netstat -i"
    echo "SYS:ShowNetStatus"
    echo "SYS:ping $GATEWAY -c 3 -t 20"
    echo "SYS:ping $OFFLINK -c 3 -t 20"
    echo "SYS:ShowNetStatus ICMP"
    echo "SYS:nslookup example.net $OFFLINK"
    echo "SYS:AddNetInterface zforce"
    echo "&SYS:nc -l $FORCE_PORT -v -w 120 >DH0:ifs-server.txt"
    echo "wait 2"
    echo "&SYS:nc $ADDRESS2 $FORCE_PORT -v -w 120 >DH0:ifs-client.txt"
    echo "wait 3"
    echo "SYS:RemoveNetInterface zforce"
    echo "&SYS:ping $GATEWAY -i 0 -c $GUEST_PING_COUNT -t $GUEST_PING_TIMEOUT >DH0:ifs-ping.txt"
    echo "SYS:RemoveNetInterface zforce FORCE"
    echo "wait $((GUEST_PING_TIMEOUT + 5))"
    echo "SYS:ShowNetStatus ICMP"
    echo "SYS:ShowNetStatus"
    echo "SYS:nslookup example.edu $OFFLINK"
    echo "SYS:RemoveNetInterface aeth0"
    echo "SYS:netstat -i"
    echo "SYS:ShowNetStatus INTERFACES"
    echo "SYS:ShowNetStatus EVENTS"
} > "$STAGE/commands.txt"

# AMINETXDUO_IFSURVIVE_PINGFALS=1: SYS:ping (a raw socket) to the gateway with
# aeth0 alone, after zeth1 attaches, and after zeth1 is removed again, with
# the ICMP counters and netstat -i after each.  Same stage, same boot; the
# verdict is the pingfals_* lines, not the checks below.
PINGFALS="${AMINETXDUO_IFSURVIVE_PINGFALS:-0}"
if [ "$PINGFALS" = 1 ]; then
    {
        echo "SYS:AddNetInterface aeth0"
        for leg in alone with_zeth1 zeth1_removed; do
            case "$leg" in
                with_zeth1)    echo "SYS:AddNetInterface zeth1" ;;
                zeth1_removed) echo "SYS:RemoveNetInterface zeth1" ;;
            esac
            echo "SYS:netstat -i"
            echo "SYS:ShowNetStatus"
            echo "SYS:ShowNetStatus ICMP"
            echo "SYS:ping $GATEWAY -c 5 -t 20"
            echo "SYS:ping $OFFLINK -c 3 -t 20"
            echo "SYS:ShowNetStatus ICMP"
            echo "SYS:netstat -i"
        done
        echo "SYS:RemoveNetInterface aeth0"
    } > "$STAGE/commands.txt"
    TIMEOUT=240
fi

# ------------------------------------------------------------------ run ---

TAG=ifsurvive
REPORT="$ROOT/build/amiberry-testhd-$TAG/tools.txt"
rm -f "$REPORT"

# ------------------------------------------------- the host-side watcher ---
#
# The guest's clock is not the host's, so the FORCE window is taken on the
# host: ToolsSmoke opens, appends and closes tools.txt for every header and
# every rc line, and the drawer is a host directory, so each one is visible
# here within the 100 ms poll.  Recorded as epoch seconds, key=value, into
# $EVENTS:
#   force_start   "===== SYS:RemoveNetInterface zforce FORCE =====" appeared
#   force_end     the "----- rc" line after it appeared
#   guest_ping_start  its "===== &SYS:ping ..." header (written just before
#                     the process is started, and before the FORCE header)
#   guest_ping_end    its statistics line (ping's output reaches the file
#                     when it exits)
#   host_ping_start / host_ping_end  launch and stop of the peer's ping
#                     (host clock), launched at "AddNetInterface zforce",
#                     stopped HOST_PING_TAIL_S after force_end
EVENTS="$ROOT/build/ifsurvive-events.txt"
HOSTPING="$ROOT/build/ifsurvive-hostping.txt"

# THE 0.2 s PROBE RUNS ON THE PEER.  This host's frames never loop back into
# its own bridged guest ("Destination Host Unreachable" from playhouse3), so
# the probe needs AMINETXDUO_PEER, a third machine on the segment, as
# install/test/run-workbench.sh -H does.  Its -D stamps are the PEER's clock:
# the offset to this host's is read before and after the run (ssh date,
# bracketed by this host's), and the window is moved into the peer's clock
# and widened by the read's uncertainty.  No peer, or no iputils on it: the
# leg is SKIPPED, and says so.
PEER="${AMINETXDUO_PEER:-}"
PEER_SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10"
PEER_PIDFILE="/tmp/claudecode-ifsurvive-ping.$(hostname -s 2> /dev/null || echo host).$$.pid"
peer_version=""
# Which ping, and whether this user may send ICMP with it at all: a ping
# without cap_net_raw ("Operation not permitted") cannot probe anything.
[ -n "$PEER" ] && peer_version=$($PEER_SSH "$PEER" 'ping -V 2>&1 | head -1;\
 ping -n -c 1 -W 1 127.0.0.1 > /dev/null 2>&1 && echo peer_can_ping=1' 2> /dev/null)
peer_why=$(ifs_peer_leg "$PEER" "$peer_version"); PEER_LEG=$?
peer_offset_read() {
    local a p b
    a=$(date +%s.%N)
    p=$($PEER_SSH "$PEER" 'date +%s.%N' 2> /dev/null)
    b=$(date +%s.%N)
    ifs_peer_offset "$a" "$p" "$b"
}
PEER_OFF="none none"
[ "$PEER_LEG" = 0 ] && PEER_OFF=$(peer_offset_read)
echo "host_ping_leg=$( [ "$PEER_LEG" = 0 ] && echo run || echo skip)\
 host_ping_from=${PEER:-none} peer_ping_version=\"$(printf '%s' "${peer_version:-none}" | head -1)\"\
 peer_clock_offset_s=${PEER_OFF% *} peer_clock_err_s=${PEER_OFF#* }"
[ "$PEER_LEG" = 0 ] || echo "  host ping leg will be SKIPPED: $peer_why"
GUESTPING_HDR="===== &SYS:ping $GATEWAY -i 0 -c $GUEST_PING_COUNT -t $GUEST_PING_TIMEOUT >DH0:ifs-ping.txt ====="
FORCE_HDR="===== SYS:RemoveNetInterface zforce FORCE ====="
: > "$EVENTS"
: > "$HOSTPING"

ifs_watch() {
    local deadline now txt hp_pid="" hp_stop="" fe="" fs="" gs="" ge="" add=""
    local interval_s
    interval_s=$(awk -v ms="$HOST_PING_INTERVAL_MS" 'BEGIN { printf "%.1f", ms / 1000 }')
    deadline=$(( $(date +%s) + TIMEOUT + 120 ))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        now=$(date +%s.%N)
        txt=$(tr -d '\r' < "$REPORT" 2> /dev/null || true)

        if [ -z "$add" ] &&
           printf '%s\n' "$txt" | grep -qxF "===== SYS:AddNetInterface zforce ====="
        then
            add=1
            if [ "$PEER_LEG" = 0 ]; then
                # The remote shell writes its pid, then becomes ping; the
                # stop below sends it SIGINT there, so its summary comes back.
                $PEER_SSH "$PEER" "echo \$\$ > $PEER_PIDFILE; exec ping -D\
 -i $interval_s -W 1 -w $((TIMEOUT + 120)) $ADDRESS" > "$HOSTPING" 2>&1 &
                hp_pid=$!
                echo "host_ping_start=$now" >> "$EVENTS"
            fi
        fi
        if [ -z "$gs" ] && printf '%s\n' "$txt" | grep -qxF "$GUESTPING_HDR"; then
            gs=1; echo "guest_ping_start=$now" >> "$EVENTS"
        fi
        if [ -z "$fs" ] && printf '%s\n' "$txt" | grep -qxF "$FORCE_HDR"; then
            fs=1; echo "force_start=$now" >> "$EVENTS"
        fi
        if [ -n "$fs" ] && [ -z "$fe" ] &&
           printf '%s\n' "$txt" | awk -v h="$FORCE_HDR" '
               $0 == h { on = 1; next }
               on && /^----- rc / { f = 1 }
               on && /^===== / { on = 0 }
               END { exit !f }'
        then
            fe=1; echo "force_end=$now" >> "$EVENTS"
            hp_stop=$(awk -v n="$now" -v t="$HOST_PING_TAIL_S" 'BEGIN { printf "%.3f", n + t }')
        fi
        if [ -z "$ge" ] &&
           tr -d '\r' < "$HD_WATCH/ifs-ping.txt" 2> /dev/null |
               grep -q " packets transmitted, "
        then
            ge=1; echo "guest_ping_end=$now" >> "$EVENTS"
        fi
        if [ -n "$hp_pid" ] && [ -n "$hp_stop" ] &&
           awk -v n="$now" -v s="$hp_stop" 'BEGIN { exit !(n >= s) }'
        then
            $PEER_SSH "$PEER" "kill -INT \$(cat $PEER_PIDFILE) 2> /dev/null; rm -f $PEER_PIDFILE" 2> /dev/null
            wait "$hp_pid" 2> /dev/null
            echo "host_ping_end=$(date +%s.%N)" >> "$EVENTS"
            hp_pid=""
        fi
        printf '%s\n' "$txt" | grep -q '^===== done' && break
        sleep 0.1
    done

    if [ -n "$hp_pid" ]; then
        $PEER_SSH "$PEER" "kill -INT \$(cat $PEER_PIDFILE) 2> /dev/null; rm -f $PEER_PIDFILE" 2> /dev/null
        wait "$hp_pid" 2> /dev/null
        echo "host_ping_end=$(date +%s.%N)" >> "$EVENTS"
    fi
}

HD_WATCH="$ROOT/build/amiberry-testhd-$TAG"
ifs_watch &
WATCH_PID=$!

(
    export AMINETXDUO_RUN_TAG="$TAG"
    "$ROOT/tools/amiberry-run.sh" -N "$BOARD" -B "$IFACE" -m A1200 -t "$TIMEOUT" \
        "$TOOLS/ToolsSmoke" "$STAGE/devs" "$STAGE/libs" \
        "$TOOLS/AddNetInterface" "$TOOLS/RemoveNetInterface" \
        "$TOOLS/ShowNetStatus" "$TOOLS/netstat" "$TOOLS/ping" \
        "$TOOLS/nslookup" "$TOOLS/nc" "$STAGE/commands.txt"
)
RUN_RC=$?
wait "$WATCH_PID" 2> /dev/null

serial_log_have "$(serial_log_path "$TAG")" "$BUILD" \
                "guest ami_log() output" || true

# EMPTY OR TRUNCATED IS NOT A PASS.  Exit 2 -- the tree's rig code -- so a
# caller records it apart from a claim that went red.
if [ ! -s "$REPORT" ]; then
    echo "!! the guest wrote no $REPORT (amiberry-run rc=$RUN_RC)." >&2
    echo "!! Nothing was checked.  This is the rig, not a result." >&2
    verdict_kv "name=ifsurvive" "verdict=SKIP" "reason=no_transcript" \
               "checks=0" "failures=0" "min_checks=$MIN_CHECKS" \
               "run_rc=$RUN_RC" "transcript="
    exit 2
fi
if ! tr -d '\r' < "$REPORT" | grep -q '^===== done'; then
    echo "!! the guest did not finish (amiberry-run rc=$RUN_RC).  The last of" >&2
    echo "!! what it printed:" >&2
    tr -d '\r' < "$REPORT" | tail -12 | sed 's/^/!!   /' >&2
    verdict_kv "name=ifsurvive" "verdict=SKIP" "reason=no_summary" \
               "checks=0" "failures=0" "min_checks=$MIN_CHECKS" \
               "run_rc=$RUN_RC" "transcript=$REPORT"
    exit 2
fi

echo
echo "------------------ what the guest printed --------------------"
tr -d '\r' < "$REPORT"
echo "--------------------------------------------------------------"
echo

if [ "$PINGFALS" = 1 ]; then
    # Per leg: replies to the five pings, the ICMP counters before and after
    # them, and aeth0/zeth1 Ipkts and addresses from netstat -i.
    pf_block() { # command n
        tr -d '\r' < "$REPORT" | awk -v want="$1" -v n="$2" '
            index($0, "===== ") == 1 {
                cur = substr($0, 7); sub(/[ \t]*=====[ \t]*$/, "", cur)
                if (cur == want) { seen++; on = (seen == n) } else { on = 0 }
                next
            }
            on { print }'
    }
    pf_kv() { # ShowNetStatus ICMP text -> key=value per counter
        printf '%s\n' "$1" | awk -F '  +' '
            /^----- rc / { next }
            {
                for (i = 1; i < NF; i++)
                    if ($(i + 1) ~ /^[0-9]+$/ && $i ~ /[a-z]/) {
                        k = $i; gsub(/[^A-Za-z0-9]+/, "_", k)
                        printf "%s=%s ", k, $(i + 1)
                    }
            }'
    }
    pf_if() { # netstat text -> name:address:ipkts:opkts per interface
        printf '%s\n' "$1" | awk '
            $1 ~ /^(aeth0|zeth1)$/ { printf "%s:%s:ipkts=%s:opkts=%s ", $1, $3, $5, $7 }'
    }
    pf_rc=0
    n=0
    for leg in alone with_zeth1 zeth1_removed; do
        n=$((n + 1))
        ping=$(pf_block "SYS:ping $GATEWAY -c 5 -t 20" "$n")
        tx=$(printf '%s\n' "$ping" | sed -n 's/^\([0-9]*\) packets transmitted, .*/\1/p' | head -1)
        rx=$(printf '%s\n' "$ping" | sed -n 's/^[0-9]* packets transmitted, \([0-9]*\) .*/\1/p' | head -1)
        off=$(pf_block "SYS:ping $OFFLINK -c 3 -t 20" "$n")
        otx=$(printf '%s\n' "$off" | sed -n 's/^\([0-9]*\) packets transmitted, .*/\1/p' | head -1)
        orx=$(printf '%s\n' "$off" | sed -n 's/^[0-9]* packets transmitted, \([0-9]*\) .*/\1/p' | head -1)
        echo "pingfals_leg=$leg ping_tx=${tx:-none} ping_rx=${rx:-none} offlink_tx=${otx:-none} offlink_rx=${orx:-none}"
        echo "pingfals_leg=$leg icmp_before: $(pf_kv "$(pf_block "SYS:ShowNetStatus ICMP" $((2 * n - 1)))")"
        echo "pingfals_leg=$leg icmp_after: $(pf_kv "$(pf_block "SYS:ShowNetStatus ICMP" $((2 * n)))")"
        echo "pingfals_leg=$leg netstat_before: $(pf_if "$(pf_block "SYS:netstat -i" $((2 * n - 1)))")"
        echo "pingfals_leg=$leg netstat_after: $(pf_if "$(pf_block "SYS:netstat -i" $((2 * n)))")"
        [ -n "$rx" ] && [ "$rx" -gt 0 ] || pf_rc=1
    done
    echo "pingfals_verdict=$( [ "$pf_rc" = 0 ] && echo PASS || echo FAIL)"
    exit "$pf_rc"
fi

# -------------------------------------------------------------- verdict ---

CHECKS="$ROOT/build/ifsurvive-checks.txt"
: > "$CHECKS"
TOTAL=0
BAD=0

pass() { printf '  ok   %s\n' "$*" | tee -a "$CHECKS"; TOTAL=$((TOTAL + 1)); }
fail() { printf '  FAIL %s\n' "$*" | tee -a "$CHECKS"
         TOTAL=$((TOTAL + 1)); BAD=$((BAD + 1)); }
rig()  { printf '  RIG  %s\n' "$*"; }

block() { # command n
    tr -d '\r' < "$REPORT" |
    awk -v want="$1" -v n="${2:-1}" '
        index($0, "===== ") == 1 {
            cur = substr($0, 7); sub(/[ \t]*=====[ \t]*$/, "", cur)
            if (cur == want) { seen++; on = (seen == n) } else { on = 0 }
            next
        }
        on { print }'
}

ms_of() { # block text -> the ms ToolsSmoke charged the command
    printf '%s\n' "$1" |
    sed -n 's/^----- rc [-0-9]*, \([0-9]*\) ms.*/\1/p' | head -1
}

# At least one reply, read from ping's count.  Not the loss percentage: "100%
# packet loss" ends in "0% packet loss".
replied() { # block text
    printf '%s\n' "$1" | awk '
        / packets transmitted, / {
            s = $0; sub(/.* packets transmitted, */, "", s)
            if (s ~ /^[1-9][0-9]* (packets )?received/) ok = 1
        }
        END { exit !ok }'
}

# nslookup's answer header for THIS name, an address record under it, rc 0 and
# no error line.  Not any dotted quad: "8.8.8.8 did not answer" has one.
resolved() { # block text, name
    printf '%s\n' "$1" | awk -v n="$2" '
        index($0, n " from ") == 1 { hdr = 1 }
        hdr && /^  address +[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { rec = 1 }
        /^----- rc 0,/ { rc0 = 1 }
        /^nslookup: / { err = 1 }
        END { exit !(hdr && rec && rc0 && !err) }'
}

# The IPv4 address on <name>'s own netstat -i line, if it is a usable one:
# not empty, not 0.0.0.0, not link-local.
netstat_addr() { # netstat text, name
    printf '%s\n' "$1" | awk -v n="$2" '$1 == n { print $3; exit }' |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    grep -vE '^(0\.0\.0\.0|169\.254\.)'
}

lease_router() { # ShowNetStatus text -> the router the DHCP lease named
    printf '%s\n' "$1" |
    awk '$1 == "it" && $2 == "offered" && $3 == "router" { print $4; exit }'
}

gateway_of() { # ShowNetStatus text -> the default route, or empty
    printf '%s\n' "$1" |
    sed -n 's/^Default route:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' | head -1
}

ONLINK="SYS:ping $GATEWAY -c 3 -t 20"
OFFPING="SYS:ping $OFFLINK -c 3 -t 20"

before=$(block "SYS:netstat -i" 1)
if printf '%s\n' "$before" | grep -qE "^aeth0[[:space:]]"; then
    pass "aeth0 -- the one that must survive -- is up"
else
    fail "aeth0 never came up, so there is no sibling to survive"
fi
if printf '%s\n' "$before" | grep -qE "^zeth1[[:space:]]"; then
    pass "zeth1 is up on the same unit"
else
    fail "zeth1 never came up, so there is nothing to remove"
fi
lease1=$(netstat_addr "$before" zeth1)
if [ -n "$lease1" ] && [ "$lease1" != "$ADDRESS" ]; then
    pass "and zeth1, added second, took a DHCP lease: $lease1"
else
    fail "zeth1 has no DHCP address, so it did not install the gateway"
fi

if ! replied "$(block "$BASEPING" 1)"; then
    rig "the gateway $GATEWAY answered no ICMP from $ADDRESS with aeth0 ALONE:\
 this rig's router ignores that source, so no ping check here decides anything"
    verdict_kv "name=ifsurvive" "verdict=SKIP" "reason=gateway_no_icmp" \
               "guest_address=$ADDRESS" "checks=0" "failures=0" \
               "min_checks=$MIN_CHECKS" "run_rc=$RUN_RC" "transcript=$REPORT"
    exit 2
fi
pass "the gateway answers ICMP from $ADDRESS with aeth0 alone"

# The on-link target was written before boot.  The lease says what the
# segment's router really is; a different one means -g is wrong for this rig,
# and nothing on-link below would be decided.
status1=$(block "SYS:ShowNetStatus" 1)
router=$(lease_router "$status1")
if [ -n "$router" ] && [ "$router" != "$GATEWAY" ]; then
    rig "zeth1's lease names router $router, but aeth0 was given $GATEWAY:\
 pass -g $router"
    verdict_kv "name=ifsurvive" "verdict=SKIP" "reason=gateway_mismatch" \
               "checks=0" "failures=0" "min_checks=$MIN_CHECKS" \
               "run_rc=$RUN_RC" "transcript=$REPORT"
    exit 2
fi

gw1=$(gateway_of "$status1")
if [ -n "$gw1" ] && [ "$gw1" != 0.0.0.0 ]; then
    pass "the machine has a default route while both are up: $gw1"
else
    fail "no default route while both interfaces are up (read '$gw1')"
fi

if replied "$(block "$ONLINK" 1)"; then
    pass "the gateway answers on-link: real frames went over the wire"
else
    fail "no on-link ping replies while both interfaces are up"
fi

# THE OFF-LINK LEG'S PRECONDITIONS.  A rig with no route off the segment cannot
# decide these in either direction, and a claim that cannot be evaluated here
# is not a claim that failed.
offping_up=0
replied "$(block "$OFFPING" 1)" && offping_up=1
dns_up=0
for q in example.com www.example.com example.org; do
    resolved "$(block "SYS:nslookup $q $OFFLINK" 1)" "$q" &&
        dns_up=$((dns_up + 1))
done
if [ "$dns_up" -gt 0 ]; then
    pass "$dns_up of 3 names resolved through $OFFLINK -- OFF-LINK, so the\
 gateway carried them -- before zeth1 was removed"
else
    rig "nothing resolved through $OFFLINK with both interfaces up: this rig\
 has no route off the segment, so the off-link half is not decided here"
fi
[ "$offping_up" = 1 ] ||
    rig "no off-link ICMP with both up either; only the resolver probes the\
 gateway on this rig"

removal=$(block "SYS:RemoveNetInterface zeth1" 1)
if printf '%s\n' "$removal" | grep -qiE "removed|no longer|^----- rc 0"; then
    pass "RemoveNetInterface zeth1 -- the interface that owns the gateway --\
 was accepted"
else
    fail "RemoveNetInterface zeth1 did not report success"
fi

after=$(block "SYS:netstat -i" 2)
if printf '%s\n' "$after" | grep -qE "^zeth1[[:space:]]"; then
    fail "zeth1 is still a live interface after it was removed"
else
    pass "zeth1 is gone"
fi
if printf '%s\n' "$after" | grep -qE "^aeth0[[:space:]]"; then
    pass "aeth0 is still a live interface"
else
    fail "aeth0 went with zeth1: removing one interface took its sibling"
fi
if [ "$(netstat_addr "$after" aeth0)" = "$ADDRESS" ]; then
    pass "and still carries its own address"
else
    fail "aeth0 lost its address when zeth1 was removed"
fi
# BUG 1, 77896ac2.  S2_OFFLINE is a unit command and it went to the device.
if printf '%s\n' "$after" | grep -qE "^aeth0[[:space:]].*[[:space:]]down"; then
    fail "aeth0's LINK IS DOWN: removing zeth1 took the wire out from under\
 the other interface on a2065.device unit 0"
else
    pass "and its link is still up: the unit was not taken offline under it"
fi
if replied "$(block "$ONLINK" 2)"; then
    pass "the gateway still answers on-link over aeth0"
else
    fail "NO ON-LINK PING REPLIES over aeth0 after zeth1 was removed: the\
 surviving interface has no wire"
fi

# BUG 2, afedeb06.  READ THE LIVE GATEWAY BACK.  An on-link ping passes with no
# gateway at all, so the two checks above cannot see this one. ShowNetStatus
# uses the configured value only when it cannot read the running stack; this
# second report is live, so a non-zero answer is the route NetX is using.
status2=$(block "SYS:ShowNetStatus" 2)
gw2=$(gateway_of "$status2")
echo "  default route: '$gw1' with both up, '$gw2' after zeth1 was removed"
if printf '%s\n' "$status2" | grep -qE '^Default route:.*\(configured\)'; then
    fail "ShowNetStatus substituted a configured route for the live table"
elif [ -n "$gw2" ] && [ "$gw2" != 0.0.0.0 ]; then
    pass "the machine still reports a default route after zeth1 was removed:\
 $gw2"
else
    fail "THE DEFAULT ROUTE IS GONE (read '$gw2'): removing one interface took\
 the machine's gateway with it, and the survivor can reach only its own subnet"
fi

if [ "$dns_up" -gt 0 ]; then
    if [ "$offping_up" = 1 ]; then
        if replied "$(block "$OFFPING" 2)"; then
            pass "$OFFLINK -- OFF-LINK -- still answers over aeth0"
        else
            fail "$OFFLINK IS UNREACHABLE over aeth0 after zeth1 was removed,\
 and it answered before"
        fi
    fi

    lookup2=$(block "SYS:nslookup example.net $OFFLINK" 1)
    lookup2_ms=$(ms_of "$lookup2")
    echo "  the surviving interface's resolution took ${lookup2_ms:-?} ms\
 (stall threshold $STALL_MS ms)"
    if resolved "$lookup2" example.net; then
        pass "a name still resolves over aeth0 through the off-link server"
        if [ -n "$lookup2_ms" ] && [ "$lookup2_ms" -gt "$STALL_MS" ]; then
            fail "but it took ${lookup2_ms} ms, over the ${STALL_MS} ms stall\
 threshold: the user's symptom is the wait, not the failure"
        else
            pass "and it came back in ${lookup2_ms:-?} ms, under the threshold"
        fi
    else
        fail "NO NAME RESOLVES over aeth0 after zeth1 was removed, and\
 $dns_up did before it"
    fi
fi

# ---- FORCE with a connection open, while aeth0 pings --------------------

HD="$ROOT/build/amiberry-testhd-$TAG"
rc_of_block() { # block text -> the rc ToolsSmoke recorded
    printf '%s\n' "$1" | sed -n 's/^----- rc \([-0-9]*\),.*/\1/p' | head -1
}

zadd=$(block "SYS:AddNetInterface zforce" 1)
if [ "$(rc_of_block "$zadd")" = 0 ]; then
    pass "zforce came up on the same unit for the FORCE leg"
else
    fail "zforce did not come up (rc '$(rc_of_block "$zadd")')"
fi

if tr -d '\r' < "$HD/ifs-client.txt" 2>/dev/null |
       grep -q "^connected to $ADDRESS2 port $FORCE_PORT"; then
    pass "a TCP connection to zforce's own address is open"
else
    fail "the client never connected to $ADDRESS2 port $FORCE_PORT"
fi

plain=$(block "SYS:RemoveNetInterface zforce" 1)
plain_rc=$(rc_of_block "$plain")
if [ "$plain_rc" = 20 ] &&
   printf '%s\n' "$plain" | grep -qi "connections open"; then
    pass "a plain removal refused: the connection counts as zforce's"
else
    fail "a plain removal did not refuse with connections open (rc\
 '$plain_rc'), so FORCE below forces nothing"
fi

force=$(block "SYS:RemoveNetInterface zforce FORCE" 1)
force_rc=$(rc_of_block "$force")
force_ms=$(ms_of "$force")
ev() { sed -n "s/^$1=//p" "$EVENTS" | head -1; }
FORCE_START=$(ev force_start);           FORCE_END=$(ev force_end)
GPING_START=$(ev guest_ping_start);      GPING_END=$(ev guest_ping_end)
HPING_START=$(ev host_ping_start);       HPING_END=$(ev host_ping_end)
# The stack's own ICMP counters after each leg's pings, leg 3 being the
# FORCE leg's -i 0 stream (opt-in in
# ShowNetStatus): requests sent against replies received and checksum
# errors say whether a lost reply reached the stack at all.
for leg in 1 2 3; do
    block "SYS:ShowNetStatus ICMP" $leg | tr -s ' \t' ' ' |
        awk -v leg=$leg 'NF { gsub(/^ /, ""); print "icmp_leg" leg ": " $0 }'
done
echo "force_rc=${force_rc:-none} force_ms=${force_ms:-none}\
 force_bound_ms=$FORCE_MS force_start=${FORCE_START:-none}\
 force_end=${FORCE_END:-none}"
case "$force_rc" in
    0) pass "RemoveNetInterface zforce FORCE returned rc 0" ;;
    5) if printf '%s\n' "$force" | grep -qi "holds requests"; then
           pass "RemoveNetInterface zforce FORCE returned rc 5: removed, the\
 device kept requests (retained)"
       else
           fail "RemoveNetInterface zforce FORCE returned rc 5 without\
 saying the device kept requests"
       fi ;;
    *) fail "RemoveNetInterface zforce FORCE returned rc '${force_rc:-none}'" ;;
esac
if [ -n "$force_ms" ] && [ "$force_ms" -le "$FORCE_MS" ]; then
    pass "and returned in $force_ms ms, within $FORCE_MS ms"
else
    fail "FORCE took '${force_ms:-never returned}' ms, over $FORCE_MS ms"
fi

# True when start <= window start and end >= window end, all epoch seconds.
spans() { # start end
    [ -n "$1" ] && [ -n "$2" ] && [ -n "$FORCE_START" ] && [ -n "$FORCE_END" ] &&
    awk -v a="$1" -v b="$2" -v s="$FORCE_START" -v e="$FORCE_END" \
        'BEGIN { exit !(a <= s && b >= e) }'
}

# CONSERVATIVE: the guest's largest gap is taken over all its probes, not only
# those inside the window, which it cannot place without a clock.
#
# The guest's back-to-back ping (-i 0): one request in flight, so a stall is
# a gap between replies.  ping prints no clock, but with one in flight the gap
# before reply k is probe k's own round trip, so the largest time= over the
# run bounds the largest gap anywhere in it, the FORCE window included; a
# lost probe is a five-second reply wait (ping.c PING_REPLY_WAIT).  Every
# requested probe must be SENT: a run TIMEOUT cut short is a failure.
# THE ALLOWED STALL.  The claim is that no lock is held across the device
# stop, so the other interface never waits for the removal; a regression to
# holding one would stall it for about force_ms.  A stall passes only when it
# is under min(250, force_ms / 2), small enough that such a regression fails
# at any removal speed.
STALL_CAP_MS=250
HALF_FORCE_MS=$(( ${force_ms:-0} / 2 ))
ALLOW_MS=$(( HALF_FORCE_MS < STALL_CAP_MS ? HALF_FORCE_MS : STALL_CAP_MS ))
gping=$(tr -d '\r' < "$HD/ifs-ping.txt" 2> /dev/null || true)
gping_tx=$(printf '%s\n' "$gping" |
           sed -n 's/^\([0-9]*\) packets transmitted, .*/\1/p' | head -1)
gping_rx=$(printf '%s\n' "$gping" |
           sed -n 's/^[0-9]* packets transmitted, \([0-9]*\) received.*/\1/p' |
           head -1)
# The largest gap, and the cadence: the median round trip.
read -r gping_gap gping_cad <<< "$(printf '%s\n' "$gping" | awk '
    / icmp_seq=[0-9]+ time=[0-9]+ ms/ {
        t = $0; sub(/.* time=/, "", t); sub(/ ms.*/, "", t); t += 0
        if (t > m) m = t
        v[++n] = t
    }
    /^Request timed out/ { m = (m > 5000) ? m : 5000 }
    END {
        for (i = 2; i <= n; i++) {
            x = v[i]; j = i - 1
            while (j > 0 && v[j] > x) { v[j + 1] = v[j]; j-- }
            v[j + 1] = x
        }
        printf "%d %d\n", m, (n > 0) ? v[int((n + 1) / 2)] : 0
    }')"
gping_stall=$(( ${gping_gap:-99999} - ${gping_cad:-0} ))
gping_span_ms=$(awk -v a="${GPING_START:-0}" -v b="${GPING_END:-0}" \
                'BEGIN { printf "%d", (b - a) * 1000 }')
echo "force_ms=${force_ms:-none} guest_ping_count=$GUEST_PING_COUNT\
 guest_ping_tx=${gping_tx:-none} guest_ping_rx=${gping_rx:-none}\
 guest_ping_start=${GPING_START:-none} guest_ping_end=${GPING_END:-none}\
 guest_ping_span_ms=$gping_span_ms max_reply_gap_ms=$gping_gap\
 guest_gap_scope=all_probes guest_cadence_ms=$gping_cad guest_stall_ms=$gping_stall\
 stall_fixed_ms=$STALL_CAP_MS guest_stall_fixed=$( [ "$gping_stall" -lt "$STALL_CAP_MS" ] && echo pass || echo fail)\
 stall_cap_ms=$STALL_CAP_MS half_force_ms=$HALF_FORCE_MS allowed_stall_ms=$ALLOW_MS"
if [ "${gping_tx:-0}" = "$GUEST_PING_COUNT" ] && [ "$gping_rx" = "$gping_tx" ]
then
    pass "aeth0's back-to-back guest ping: all $gping_tx sent and answered\
 over ${gping_span_ms} ms"
else
    fail "aeth0's guest ping stopped short or lost: ${gping_rx:-?} answered of\
 ${gping_tx:-0} sent, $GUEST_PING_COUNT asked"
fi
if spans "$GPING_START" "$GPING_END"; then
    pass "and that run spanned the FORCE window ($GPING_START..$GPING_END\
 around $FORCE_START..$FORCE_END)"
else
    fail "the guest ping did not span the FORCE window ($GPING_START..$GPING_END\
 against $FORCE_START..$FORCE_END)"
fi
if [ "$gping_stall" -lt "$ALLOW_MS" ]; then
    pass "and its largest reply gap over all its probes, not only the window,\
 ${gping_gap} ms, is ${gping_stall} ms over\
 its ${gping_cad} ms cadence, under the ${ALLOW_MS} ms allowed\
 (min($STALL_CAP_MS, ${force_ms:-?}/2 = $HALF_FORCE_MS))"
else
    fail "a reply gap of ${gping_gap} ms, ${gping_stall} ms over its\
 ${gping_cad} ms cadence and the ${ALLOW_MS} ms allowed: aeth0 stalled"
fi

# The peer's ping to aeth0 runs on a fixed clock, so a stall shows as late or
# lost replies, not as a send gap.  ifs_host_window walks every probe SENT
# (see it, above); probes before the window are the baseline, those inside it
# are judged.  The window is the host-observed one, moved into the peer's
# clock and widened by POLL_MS and the clock uncertainty at each end, so
# neither a late poll nor the offset can drop a probe from it.
if [ "$PEER_LEG" != 0 ]; then
    echo "host_ping_verdict=SKIP reason=\"$peer_why\""
    echo "  SKIP host ping leg: $peer_why"
    # Two checks fewer, said out loud above: not passed, not counted.
    MIN_CHECKS=$((MIN_CHECKS - 2))
else
PEER_OFF2=$(peer_offset_read)
# Into the peer's clock: offset from before the run, widened by the larger
# of the two reads' uncertainty and the drift between them.
read -r P_OFF P_ERR <<< "$PEER_OFF"
read -r P_OFF2 P_ERR2 <<< "$PEER_OFF2"
P_WIDEN=$(awk -v e1="$P_ERR" -v e2="$P_ERR2" -v o1="$P_OFF" -v o2="$P_OFF2" '
    BEGIN { d = o2 - o1; if (d < 0) d = -d; m = e1
            if (e2 + 0 > m) m = e2; if (d > m) m = d
            if (o1 == "none" || o2 == "none") m = 1
            printf "%.3f", m }')
WIN_S=$(awk -v s="${FORCE_START:-0}" -v p="$POLL_MS" -v o="$P_OFF" -v w="$P_WIDEN" \
        'BEGIN { printf "%.3f", s + o - p / 1000 - w }')
WIN_E=$(awk -v e="${FORCE_END:-0}" -v p="$POLL_MS" -v o="$P_OFF" -v w="$P_WIDEN" \
        'BEGIN { printf "%.3f", e + o + p / 1000 + w }')
HPING_END_PEER=$(awk -v e="${HPING_END:-0}" -v o="$P_OFF" 'BEGIN { printf "%.3f", e + o }')
hp=$(ifs_host_window "$HOSTPING" "$WIN_S" "$WIN_E" "$HOST_PING_INTERVAL_MS" \
                     "$HPING_END_PEER")
read -r hp_have hp_tx hp_rx hp_nb hp_bmin hp_med hp_bmax hp_wmax hp_sent \
    hp_summary hp_last <<< "${hp:-0 0 0 0 0 0 0 0 0 0 0}"
echo "force_ms=${force_ms:-none} force_ms_source=guest_datestamp\
 force_ms_err=20 window_edges=host_observed poll_ms=$POLL_MS\
 host_ping_from=$PEER peer_clock_offset_s=$P_OFF peer_clock_err_s=$P_ERR\
 peer_clock_offset_after_s=$P_OFF2 peer_clock_err_after_s=$P_ERR2\
 peer_window_widen_s=$P_WIDEN peer_window_start=$WIN_S peer_window_end=$WIN_E\
 host_ping_interval_ms=$HOST_PING_INTERVAL_MS\
 host_ping_start=${HPING_START:-none} host_ping_end=${HPING_END:-none}\
 host_ping_sent=$hp_sent host_ping_window_tx=$hp_tx host_ping_window_rx=$hp_rx\
 baseline_probes=$hp_nb baseline_min_rtt_ms=$hp_bmin baseline_rtt_ms=$hp_med\
 baseline_max_rtt_ms=$hp_bmax window_max_rtt_ms=$hp_wmax max_rtt_ms=$hp_wmax\
 host_ping_summary=$hp_summary host_ping_last_send=$hp_last\
 host_stall_ms=$((hp_wmax - hp_med)) host_stall_vs_baseline_max_ms=$((hp_wmax - hp_bmax))\
 stall_cap_ms=$STALL_CAP_MS half_force_ms=$HALF_FORCE_MS allowed_stall_ms=$ALLOW_MS\
 stall_fixed_ms=$STALL_CAP_MS host_stall_fixed=$( [ $((hp_wmax - hp_med)) -lt "$STALL_CAP_MS" ] && echo pass || echo fail)"
if why=$(ifs_host_verdict "$hp" "$WIN_E" "$ALLOW_MS" "${force_ms:-0}"); then
    echo "host_ping_verdict=PASS"
    pass "peer ($PEER) ping to aeth0 every ${HOST_PING_INTERVAL_MS} ms over the\
 FORCE window (host-observed edges, widened ${POLL_MS} ms and ${P_WIDEN} s of\
 clock uncertainty each side, in the peer's clock): $why (baseline\
 min/median/max $hp_bmin/$hp_med/$hp_bmax ms over $hp_nb probes)"
else
    echo "host_ping_verdict=FAIL"
    fail "peer ($PEER) ping to aeth0 over the FORCE window: $why"
fi
# A sanity check only: the probe runs for the whole leg.  Host clock both sides.
if spans "$HPING_START" "$HPING_END"; then
    pass "and the peer's ping spanned the FORCE window"
else
    fail "the peer's ping did not span the FORCE window ($HPING_START..$HPING_END\
 against $FORCE_START..$FORCE_END)"
fi
fi

status3=$(block "SYS:ShowNetStatus" 3)
gw3=$(gateway_of "$status3")
if [ -n "$gw3" ] && [ "$gw3" != 0.0.0.0 ]; then
    pass "the machine still has a default route after FORCE: $gw3"
else
    fail "THE DEFAULT ROUTE IS GONE after FORCE (read '$gw3')"
fi
if [ "$dns_up" -gt 0 ]; then
    if resolved "$(block "SYS:nslookup example.edu $OFFLINK" 1)" example.edu
    then
        pass "a name still resolves over aeth0 after FORCE"
    else
        fail "NO NAME RESOLVES over aeth0 after FORCE removed zforce"
    fi
fi

last=$(block "SYS:RemoveNetInterface aeth0" 1)
if printf '%s\n' "$last" | grep -qiE "removed|no longer|^----- rc 0"; then
    pass "RemoveNetInterface aeth0 was accepted"
else
    fail "RemoveNetInterface aeth0 did not report success"
fi

end=$(block "SYS:netstat -i" 3)
if printf '%s\n' "$end" | grep -qE "^(aeth0|zeth1|zforce)[[:space:]]"; then
    fail "an interface is still live after both were removed"
else
    pass "no interface is left holding the unit"
fi

# THE FIX MUST NOT BE "NEVER OFFLINE ANYTHING".  The last one out does issue
# S2_OFFLINE, and an S2_OFFLINE that is refused is NETEVENT_OFFLINE_FAILED's to
# report; the drawer entries go back to `defined` either way.
table=$(block "SYS:ShowNetStatus INTERFACES" 1 |
        sed -n '/^Interfaces$/,/^$/p' |
        grep -vE '^(Interfaces|Name[[:space:]]+State)')
detached=0
for n in aeth0 zeth1; do
    printf '%s\n' "$table" | grep -qE "^${n}[[:space:]]+defined" &&
        detached=$((detached + 1))
done
if [ "$detached" = 2 ]; then
    pass "both definitions are back to 'defined'"
else
    fail "$detached of 2 definitions went back to 'defined' after removal"
fi
if block "SYS:ShowNetStatus EVENTS" 1 | grep -qi "offline.*fail"; then
    fail "the last interface out could not take the unit offline"
else
    pass "the last one out took the unit offline without a refusal"
fi

final_status=$(block "SYS:ShowNetStatus EVENTS" 1)
if printf '%s\n' "$final_status" | grep -qE '^Default route:[[:space:]]+none$'; then
    pass "ShowNetStatus reports no live route after the last interface is gone"
else
    fail "ShowNetStatus substituted a configured gateway after all live routes were removed"
fi

printf 'ifsurvive: %d checks, %d failures\n' "$TOTAL" "$BAD" >> "$CHECKS"
echo
echo "ifsurvive: $TOTAL checks, $BAD failures"

verdict_guest ifsurvive "$MIN_CHECKS" 0 "$CHECKS"
exit $?
