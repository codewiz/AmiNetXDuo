# The host-ping verdict of tests/tools/run-ifsurvive.sh's FORCE leg, sourced
# by it and by tests/tools/ifsurvive-verdict-selftest.sh.
#
# SPDX-License-Identifier: MIT

# ifs_host_window <iputils -D output> <window start> <window end> <interval ms>
#                 <host ping stop>
#   -> "have tx rx base_n base_min base_med base_max win_max sent summary
#       last_send"
#
# Every SENT probe is walked, not only those up to the last reply: iputils
# sends on a fixed clock, so the first reply (its -D stamp less its RTT, and
# its icmp_seq) anchors the schedule, and the count sent is the summary's
# "N packets transmitted", or, without one, the schedule run to the stop time.
# A probe on the schedule with no reply line is lost, wherever it falls; a
# guest that goes silent at FORCE start therefore loses every window probe.
ifs_host_window() {
    awk -v s="$2" -v e="$3" -v iv="$4" -v stop="$5" '
    /^\[[0-9.]+\] .* icmp_seq=[0-9]+ .*time=/ {
        ts = substr($1, 2, length($1) - 2) + 0
        q = $0; sub(/.*icmp_seq=/, "", q); sub(/ .*/, "", q); q += 0
        t = $0; sub(/.*time=/, "", t); sub(/ .*/, "", t); t += 0
        rtt[q] = t; got[q] = 1
        if (!have) { have = 1; q0 = q; t0 = ts - t / 1000 }
    }
    / packets transmitted, / { n = $1 + 0; summary = 1 }
    END {
        tx = 0; rx = 0; nb = 0; bmin = 0; bmax = 0; wmax = 0
        if (have && n == 0 && stop > t0)
            n = q0 + int((stop - t0) * 1000 / iv)
        if (have)
            for (q = 1; q <= n; q++) {
                send = t0 + (q - q0) * iv / 1000
                if (send < s) {
                    if (got[q]) {
                        b[++nb] = rtt[q]
                        if (nb == 1 || rtt[q] < bmin) bmin = rtt[q]
                        if (rtt[q] > bmax) bmax = rtt[q]
                    }
                } else if (send <= e) {
                    tx++
                    if (got[q]) { rx++; if (rtt[q] > wmax) wmax = rtt[q] }
                }
            }
        for (i = 2; i <= nb; i++) {
            v = b[i]; j = i - 1
            while (j > 0 && b[j] > v) { b[j + 1] = b[j]; j-- }
            b[j + 1] = v
        }
        med = (nb > 0) ? b[int((nb + 1) / 2)] : 0
        last_send = have ? t0 + (n - q0) * iv / 1000 : 0
        printf "%d %d %d %d %d %d %d %d %d %d %.3f\n", have, tx, rx, nb, bmin, \
               med, bmax, wmax, n, summary, last_send
    }' "$1" 2> /dev/null
}

# ifs_host_verdict <ifs_host_window output> <window end> <allowed ms>
#                  <force ms>  -> 0 pass; the reason on stdout either way.
#
# FAILS CLOSED: an empty stream, no iputils summary (the ping did not end the
# way the watcher stops it), or a stream whose last send falls before the
# window's end decides nothing and so fails.  The window must hold at least
# max(1, force_ms/200 - 1) probes, and 2 once force_ms >= 400, so one probe
# cannot carry a long removal.  The stall is the window's worst RTT less the
# baseline MEDIAN: one slow baseline probe must not hide a regression.
ifs_host_verdict() {
    local have tx rx nb bmin med bmax wmax sent summary last need
    read -r have tx rx nb bmin med bmax wmax sent summary last <<< "$1"
    need=$(( $4 / 200 - 1 )); [ "$need" -lt 1 ] && need=1
    [ "$4" -ge 400 ] && [ "$need" -lt 2 ] && need=2
    if [ "${have:-0}" != 1 ] || [ "${nb:-0}" = 0 ]; then
        echo "no reply from aeth0 before the FORCE: the host cannot see the guest"
        return 1
    fi
    if [ "${summary:-0}" != 1 ]; then
        echo "the host ping has no summary line: its output is truncated"
        return 1
    fi
    if awk -v l="$last" -v e="$2" 'BEGIN { exit !(l < e) }'; then
        echo "the host ping's last send, $last, is before the window's end, $2"
        return 1
    fi
    if [ "$tx" -lt "$need" ]; then
        echo "$tx probe(s) inside the FORCE window, $need needed for a $4 ms\
 removal"
        return 1
    fi
    if [ "$rx" != "$tx" ]; then
        echo "$rx of $tx probes sent inside the FORCE window answered"
        return 1
    fi
    if [ $(( wmax - med )) -ge "$3" ]; then
        echo "window max RTT $wmax ms is $(( wmax - med )) ms over the baseline\
 median $med ms, not under the $3 ms allowed"
        return 1
    fi
    echo "all $tx window probes answered ($need needed), window max RTT $wmax\
 ms, $(( wmax - med )) ms over the baseline median $med ms, under $3 ms"
    return 0
}
