#!/usr/bin/env bash
#
# One MAC address per run tag, for every harness that puts a guest on the
# bridge.
#
#   . tools/emu-mac.sh
#   MAC=$(emu_mac_for_tag "$TAG")    # the same in every run
#   MAC=$(emu_mac_for_run "$TAG")    # fresh per invocation
#   MAC=$(emu_mac_default "$TAG")    # per tag; per run with AMINETXDUO_MAC_PER_RUN=1
#
# The fifth byte is never 0x00 and never 0x0d, which is what keeps a derived
# address clear of every harness that pins its own: tools/demo.sh 00:77 and the
# tests/tools runs on 00:xx are fifth-byte 0x00, run-dnsguard.sh the only 0x0d.
#
# SPDX-License-Identifier: MIT

# $1 = the run tag.  Prints one MAC address.
emu_mac_for_tag() {
    local tag="$1" hash fifth

    hash=$(printf '%s' "$tag" | cksum | cut -d' ' -f1)
    fifth=$(( (hash / 256) % 254 + 1 ))
    if [ "$fifth" -eq 13 ]; then
        fifth=255
    fi
    printf '02:41:4d:49:%02x:%02x\n' "$fifth" "$((hash % 256))"
}

# THE INVOCATION, for a MAC that is fresh per run and not only per tag.  The
# same for every boot of one harness run, so a matrix that shares one
# AMINETXDUO_MAC_TAG still puts one address on the LAN; different between two
# runs, so a manual arm and CI's copy of it never share one.
#
# AMINETXDUO_RUN_ID wins.  Under GitHub Actions it is the run, its attempt and
# the job.  Otherwise it is this host, the process group and its leader's start
# time: an interactive shell gives every command line its own group, and a
# script started over ssh or by nohup is the leader of its own; the start time
# keeps a recycled group id from repeating an old run's address.
emu_run_id() {
    if [ -n "${AMINETXDUO_RUN_ID:-}" ]; then
        printf '%s\n' "$AMINETXDUO_RUN_ID"
        return 0
    fi
    if [ -n "${GITHUB_RUN_ID:-}" ]; then
        printf 'gh:%s:%s:%s\n' "$GITHUB_RUN_ID" "${GITHUB_RUN_ATTEMPT:-1}" \
               "${GITHUB_JOB:-}"
        return 0
    fi
    local pg start
    pg=$(ps -o pgid= -p "$$" 2> /dev/null | tr -d ' ')
    start=$(ps -o lstart= -p "${pg:-$$}" 2> /dev/null)
    printf '%s:%s:%s\n' "$(uname -n)" "${pg:-$$}" "$start"
}

# $1 = the run tag.  One MAC for this tag in this invocation.
emu_mac_for_run() {
    emu_mac_for_tag "$1@$(emu_run_id)"
}

# What a harness uses when the caller pinned nothing.  Per TAG: every fresh
# address is a new lease from a DHCP pool the bench, the A1200 and the
# printers share, and the bridge lock already keeps two runs of a tag off the
# segment together.  AMINETXDUO_MAC_PER_RUN=1 opts into a fresh one.
emu_mac_default() {
    if [ "${AMINETXDUO_MAC_PER_RUN:-0}" = 1 ]; then
        emu_mac_for_run "$1"
    else
        emu_mac_for_tag "$1"
    fi
}
