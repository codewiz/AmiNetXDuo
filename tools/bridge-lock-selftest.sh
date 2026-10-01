#!/usr/bin/env bash
#
# Does tools/amiberry-run.sh keep bridged guests apart, end to end?
#
#   tools/bridge-lock-selftest.sh
#
# Two scratch checkouts and a stub emulator, so it needs no Amiberry, no ROM,
# no toolchain and no network, and never waits on a live guest: the bridge
# lock is a file of its own.  It replays 2026-10-01 -- a manual and a CI copy
# of one arm, one tag, two checkouts, bridged on one NIC -- and asserts:
#
#   bridge_serial   the second bridged boot starts only after the first exits,
#                   and within a few seconds of it
#   bridge_released after a normal exit a new contender gets it without waiting
#   mac_per_tag     by default the two share the tag's MAC (no new leases)
#   mac_per_run     AMINETXDUO_MAC_PER_RUN=1 gives two invocations two MACs
#   same_tree_hd    a second bridged run of the same tag in the same checkout
#                   leaves the running guest's drive alone while it waits
#   bridge_kill9    the wrapper killed with -9 while its guest runs: the lock
#                   stays held until the GUEST exits, then the next one boots
#   bridge_refuse   a boot that outwaits AMINETXDUO_BRIDGE_WAIT exits 6 unbooted
#   noflock_rc      no flock(1) on PATH is a missing ingredient (2), never 6
#   unwritable_rc   a lock path that cannot be created is 2, never 6
#   slirp_parallel  two SLIRP boots run at the same time
#   mac_pinned      AMINETXDUO_AMIBERRY_MAC is used as given
#
# Output is key=value and an exit code: 0 all held, 1 one did not, 3 not
# evaluable here (no flock(1) or python3).
#
# SPDX-License-Identifier: MIT

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v flock > /dev/null 2>&1 && command -v python3 > /dev/null 2>&1 || {
    echo "bridge_selftest=unproven reason=needs-flock(1)-and-python3"
    exit 3
}

S=$(mktemp -d "${TMPDIR:-/tmp}/bridge-selftest.XXXXXX")
# Scoped to this scratch tree: the -9 case orphans a reader on purpose.
trap 'pkill -P $$ 2> /dev/null; pkill -f "$S/" 2> /dev/null; rm -rf "$S"' EXIT

# What tools/amiberry-run.sh reads from its own tree, and nothing else.
for c in A B C D; do
    mkdir -p "$S/$c/tools/envsetup" "$S/$c/build"
    for f in amiberry-run.sh amiberry-resolve.sh emu-board.sh emu-watch.sh \
             emu-rig-lock.sh emu-mac.sh emu-bridge.sh logcap.sh \
             serial-timestamp.py envsetup/envsetup.c; do
        cp "$ROOT/tools/$f" "$S/$c/tools/$f"
    done
    printf '#!/bin/sh\n' > "$S/$c/build/envsetup-m68020"
    chmod +x "$S/$c/build/envsetup-m68020"
done
: > "$S/kick.rom"
: > "$S/Guest"

# The emulator: says it opened the backend, binds the serial port, writes
# DH0:.done after STUB_SECS, and logs start and end -- with the MAC it was
# given and the time -- to one file every instance appends to.  STUB_LIFE
# makes it exit on its own, as a guest outliving a killed wrapper would.
cat > "$S/amiberry" <<'PY'
#!/usr/bin/env python3
import os, re, signal, socket, sys, time
cfg = open(sys.argv[-1]).read()
def g(p):
    m = re.search(p, cfg, re.M)
    return m.group(1) if m else ""
hd = g(r"^uaehf0=dir,rw,DH0:DH0:(.*),0$")
port = int(g(r"^serial_port=tcp://127\.0\.0\.1:(\d+)/wait$"))
mac = g(r"^a2065_rom_options=mac=([^,]*),")
backend = g(r"^a2065_rom_options=mac=[^,]*,([^,\n]*)")
who = os.environ["STUB_WHO"]
def log(s):
    with open(os.environ["STUB_EVENTS"], "a") as f:
        f.write("%s t=%.2f\n" % (s, time.time()))
def term(*_):
    log("end %s" % who)
    sys.exit(0)
signal.signal(signal.SIGTERM, term)
log("start %s mac=%s" % (who, mac))
open(os.path.join(hd, "stub-alive"), "w").write("1\n")
print("UAENET: '%s' open successful" % backend, flush=True)
s = socket.socket()
s.bind(("127.0.0.1", port))
s.listen(1)
t0 = time.time()
life = float(os.environ.get("STUB_LIFE", "0"))
secs = float(os.environ.get("STUB_SECS", "2"))
while time.time() - t0 < secs:
    if life and time.time() - t0 >= life:
        term()
    time.sleep(0.2)
open(os.path.join(hd, ".done"), "w").write("0\n")
while not life or time.time() - t0 < life:
    time.sleep(0.2)
term()
PY
chmod +x "$S/amiberry"

EV="$S/events"
: > "$EV"

# run <checkout> <who> <backend> [VAR=value...]
run() {
    local c="$1" who="$2" be="$3"; shift 3
    env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
        AMIBERRY="$S/amiberry" AMINETXDUO_KICKSTART="$S/kick.rom" \
        AMINETXDUO_RIG_LOCKDIR="$S/rig" \
        AMINETXDUO_BRIDGE_LOCK="$S/bridge.lock" \
        AMINETXDUO_RUN_TAG=ifsurvive AMINETXDUO_ALLOW_SLIRP=1 \
        STUB_EVENTS="$EV" STUB_WHO="$who" "$@" \
        "$S/$c/tools/amiberry-run.sh" -N a2065 -B "$be" -t 30 "$S/Guest" \
        > "$S/$who.out" 2>&1
    echo $? > "$S/$who.rc"
}

WRONG=0
kv() { printf '%s=%s\n' "$1" "$2"; [ "$2" = ok ] || WRONG=$((WRONG + 1)); }

# --------------------------------------------- two bridged, one tag, two trees
# Job control on, so each is its own process group, as two invocations from
# two shells are: that is what emu_run_id tells apart.
set -m
run A manual ens18 STUB_SECS=3 &
sleep 1
run B ci ens18 STUB_SECS=1 &
wait
set +m
cp "$EV" "$S/events.pair"

order=$(awk '{print $1 "-" $2}' "$EV" | tr '\n' ' ')
# How long the lock sat free between the first guest's exit and the second's
# start: the waiter is woken by the release, not by a poll.
gap=$(awk '$1 == "end" && $2 == "manual" { e = substr($NF, 3) }
           $1 == "start" && $2 == "ci" { s = substr($NF, 3) }
           END { printf "%.1f", s - e }' "$EV")
if [ "$order" = "start-manual end-manual start-ci end-ci " ] &&
   [ "$(cat "$S/manual.rc")" = 0 ] && [ "$(cat "$S/ci.rc")" = 0 ] &&
   grep -q 'another bridged guest is up' "$S/ci.out" &&
   awk -v g="$gap" 'BEGIN { exit !(g >= 0 && g < 3) }'; then
    kv bridge_serial ok
else
    kv bridge_serial "wrong:order=[$order]:gap=${gap}s:rc=$(cat "$S/manual.rc"),$(cat "$S/ci.rc")"
fi
echo "bridge_handover_s=$gap"

# Released on a normal exit: a new contender with no wait to spare boots.
: > "$EV"
run C after ens18 STUB_SECS=0.5 AMINETXDUO_BRIDGE_WAIT=1
if [ "$(cat "$S/after.rc")" = 0 ] && grep -q '^start after' "$EV" &&
   ! grep -q 'another bridged guest is up' "$S/after.out"; then
    kv bridge_released ok
else
    kv bridge_released "wrong:rc=$(cat "$S/after.rc")"
fi

mac_a=$(sed -n 's/^start manual mac=\([^ ]*\) .*/\1/p' "$S/events.pair")
mac_b=$(sed -n 's/^start ci mac=\([^ ]*\) .*/\1/p' "$S/events.pair")
if [ -n "$mac_a" ] && [ "$mac_a" = "$mac_b" ] &&
   case "$mac_a" in 02:*) true ;; *) false ;; esac; then
    kv mac_per_tag ok
else
    kv mac_per_tag "wrong:$mac_a,$mac_b"
fi

# The opt-in: two invocations, each its own process group as from two shells.
: > "$EV"
set -m
run A perrun1 ens18 STUB_SECS=0.5 AMINETXDUO_MAC_PER_RUN=1 &
wait
run B perrun2 ens18 STUB_SECS=0.5 AMINETXDUO_MAC_PER_RUN=1 &
wait
set +m
mac_a=$(sed -n 's/^start perrun1 mac=\([^ ]*\) .*/\1/p' "$EV")
mac_b=$(sed -n 's/^start perrun2 mac=\([^ ]*\) .*/\1/p' "$EV")
if [ -n "$mac_a" ] && [ -n "$mac_b" ] && [ "$mac_a" != "$mac_b" ] &&
   case "$mac_a$mac_b" in 02:*02:*) true ;; *) false ;; esac; then
    kv mac_per_run ok
else
    kv mac_per_run "wrong:$mac_a,$mac_b"
fi

# One checkout, one tag, the first guest up: the second must not wipe its
# drive on the way to waiting.  The stub leaves a marker in DH0: at start.
: > "$EV"
run A holder ens18 STUB_SECS=4 &
HOLD=$!
for _ in $(seq 1 50); do grep -q '^start holder' "$EV" && break; sleep 0.2; done
HDA="$S/A/build/amiberry-testhd-ifsurvive"
run A sametree ens18 AMINETXDUO_BRIDGE_WAIT=1
if [ -e "$HDA/stub-alive" ] && [ "$(cat "$S/sametree.rc")" = 6 ]; then
    kv same_tree_hd ok
else
    kv same_tree_hd "wrong:marker=$([ -e "$HDA/stub-alive" ] && echo kept || echo gone):rc=$(cat "$S/sametree.rc")"
fi
wait "$HOLD"

# ------------------- the wrapper is killed with -9 while its guest is running
: > "$EV"
run A doomed ens18 STUB_SECS=60 STUB_LIFE=5 &
for _ in $(seq 1 50); do grep -q '^start doomed' "$EV" && break; sleep 0.2; done
WRAP=$(pgrep -f "^[^ ]*bash $S/A/tools/amiberry-run.sh" | head -1)
[ -n "$WRAP" ] || WRAP=$(pgrep -f "$S/A/tools/amiberry-run.sh" | head -1)
kill -9 "$WRAP" 2> /dev/null
wait
alive=$(pgrep -f "$S/amiberry" | head -1)
run B heir ens18 STUB_SECS=0.5 AMINETXDUO_BRIDGE_WAIT=30
order=$(awk '{print $1 "-" $2}' "$EV" | tr '\n' ' ')
if [ -n "$WRAP" ] && [ -n "$alive" ] &&
   [ "$order" = "start-doomed end-doomed start-heir end-heir " ] &&
   [ "$(cat "$S/heir.rc")" = 0 ] &&
   grep -q 'another bridged guest is up' "$S/heir.out"; then
    kv bridge_kill9 ok
else
    kv bridge_kill9 "wrong:wrapper=${WRAP:-none}:guest_after_kill=${alive:-none}:order=[$order]:rc=$(cat "$S/heir.rc")"
fi

# ----------------------------------- a missing ingredient is not a busy rig
# PATH with everything on it except flock(1).
mkdir -p "$S/noflock"
IFS=: read -r -a _dirs <<< "$PATH"
for d in "${_dirs[@]}"; do
    for x in "$d"/*; do
        n=${x##*/}
        [ "$n" = flock ] || [ -e "$S/noflock/$n" ] || [ ! -x "$x" ] ||
            ln -s "$x" "$S/noflock/$n" 2> /dev/null
    done
done
fn_rc=$(PATH="$S/noflock" AMINETXDUO_BRIDGE_LOCK="$S/bridge.lock" bash -c '
    . "$1/tools/emu-rig-lock.sh"
    rig_claim_bridge ens18 noflock > /dev/null 2>&1
    echo $?' _ "$ROOT")
: > "$EV"
PATH="$S/noflock" run C noflock ens18
if [ "$fn_rc" = 2 ] && [ "$(cat "$S/noflock.rc")" = 2 ] && [ ! -s "$EV" ]; then
    kv noflock_rc ok
else
    kv noflock_rc "wrong:function=$fn_rc:run=$(cat "$S/noflock.rc")"
fi

: > "$EV"
run C unwritable ens18 AMINETXDUO_BRIDGE_LOCK="$S/no/such/dir/bridge.lock"
if [ "$(cat "$S/unwritable.rc")" = 2 ] && [ ! -s "$EV" ] &&
   grep -q 'cannot create the bridge lock' "$S/unwritable.out"; then
    kv unwritable_rc ok
else
    kv unwritable_rc "wrong:rc=$(cat "$S/unwritable.rc")"
fi

# ------------------------------- a boot that cannot get the bridge in time
: > "$EV"
(
    AMINETXDUO_BRIDGE_LOCK="$S/bridge.lock"
    export AMINETXDUO_BRIDGE_LOCK
    # shellcheck source=emu-rig-lock.sh
    . "$ROOT/tools/emu-rig-lock.sh"
    rig_claim_bridge ens18 "a-held-rig" > /dev/null 2>&1 &&
        touch "$S/held"
    sleep 8
) &
HOLDER=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -e "$S/held" ] && break; sleep 0.2; done
run C refused ens18 AMINETXDUO_BRIDGE_WAIT=2
if [ "$(cat "$S/refused.rc")" = 6 ] && [ ! -s "$EV" ] &&
   grep -q 'a-held-rig' "$S/refused.out"; then
    kv bridge_refuse ok
else
    kv bridge_refuse "wrong:rc=$(cat "$S/refused.rc"):events=$(wc -l < "$EV")"
fi

# ---------------------------- SLIRP is not held back, even beside a holder
run C slirp1 slirp STUB_SECS=3 AMINETXDUO_AMIBERRY_MAC=02:41:4d:49:aa:bb &
sleep 0.5
run D slirp2 slirp STUB_SECS=3 &
wait "$!"
wait
kill "$HOLDER" 2> /dev/null
order=$(awk '{print $1}' "$EV" | tr '\n' ' ')
if [ "$order" = "start start end end " ] &&
   [ "$(cat "$S/slirp1.rc")" = 0 ] && [ "$(cat "$S/slirp2.rc")" = 0 ]; then
    kv slirp_parallel ok
else
    kv slirp_parallel "wrong:order=[$order]"
fi
if grep -q '^start slirp1 mac=02:41:4d:49:aa:bb ' "$EV"; then
    kv mac_pinned ok
else
    kv mac_pinned "wrong:$(grep '^start slirp1' "$EV")"
fi

echo "bridge_selftest=$WRONG"
[ "$WRONG" = 0 ] || {
    for f in "$S"/*.out; do echo "---- $f"; tail -15 "$f"; done
    exit 1
}
exit 0
