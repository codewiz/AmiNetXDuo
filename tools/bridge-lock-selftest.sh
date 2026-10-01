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
#   bridge_serial   the second bridged boot starts only after the first exits
#   bridge_mac      the two get different MACs although they share a tag
#   bridge_refuse   a boot that outwaits AMINETXDUO_BRIDGE_WAIT exits 6 unbooted
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
trap 'pkill -P $$ 2> /dev/null; rm -rf "$S"' EXIT

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
# given -- to one file every instance appends to.
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
        f.write(s + "\n")
def term(*_):
    log("end %s" % who)
    sys.exit(0)
signal.signal(signal.SIGTERM, term)
log("start %s mac=%s" % (who, mac))
print("UAENET: '%s' open successful" % backend, flush=True)
s = socket.socket()
s.bind(("127.0.0.1", port))
s.listen(1)
time.sleep(float(os.environ.get("STUB_SECS", "2")))
open(os.path.join(hd, ".done"), "w").write("0\n")
while True:
    time.sleep(1)
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

order=$(awk '{print $1 "-" $2}' "$EV" | tr '\n' ' ')
if [ "$order" = "start-manual end-manual start-ci end-ci " ] &&
   [ "$(cat "$S/manual.rc")" = 0 ] && [ "$(cat "$S/ci.rc")" = 0 ] &&
   grep -q 'another bridged guest is up' "$S/ci.out"; then
    kv bridge_serial ok
else
    kv bridge_serial "wrong:order=[$order]:rc=$(cat "$S/manual.rc"),$(cat "$S/ci.rc")"
fi

mac_a=$(sed -n 's/^start manual mac=//p' "$EV")
mac_b=$(sed -n 's/^start ci mac=//p' "$EV")
if [ -n "$mac_a" ] && [ -n "$mac_b" ] && [ "$mac_a" != "$mac_b" ] &&
   case "$mac_a$mac_b" in 02:*02:*) true ;; *) false ;; esac; then
    kv bridge_mac ok
else
    kv bridge_mac "wrong:$mac_a,$mac_b"
fi
echo "bridge_macs=$mac_a,$mac_b"

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
if grep -qx 'start slirp1 mac=02:41:4d:49:aa:bb' "$EV"; then
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
