#!/usr/bin/env python3
"""Send TCP payload repeatedly to SweepRx on an Amiga. Python 3, no packages.

The receiver controls each trial's duration and closes the connection when
finished. Reconnects tolerate the OFFLINE/apply/ONLINE interval between trials.
This is a sender only: it changes no configuration and opens no remote shell.
SPDX-License-Identifier: MIT
"""
import argparse
import ipaddress
import socket
import time

PAYLOAD = (b"0123456789" * 6554)[:65536]


def send_trials(host, port=5001, duration=1800, retry=0.5, report=print):
    """Return the number of connections carrying data within a bounded session."""
    deadline = time.monotonic() + duration
    completed = 0
    next_notice = 0.0
    while time.monotonic() < deadline:
        total = 0
        started = time.monotonic()
        try:
            with socket.create_connection((host, port),
                                          timeout=min(3.0, deadline - started)) as conn:
                started = time.monotonic()
                # A single stalled send is bounded too. No future connection
                # is queued while the current trial is still receiving.
                while time.monotonic() < deadline:
                    conn.settimeout(max(0.001, min(3.0, deadline - time.monotonic())))
                    sent = conn.send(PAYLOAD)
                    if not sent:
                        break
                    total += sent
        except OSError as exc:
            if not total and time.monotonic() >= next_notice:
                report("Waiting for SweepRx at %s:%d (%s)" % (host, port, exc))
                next_notice = time.monotonic() + 10
        if total:
            completed += 1
            report("connection=%d sent_bytes=%d elapsed_ms=%d" % (
                completed, total, int((time.monotonic() - started) * 1000)))
        time.sleep(max(0, min(retry, deadline - time.monotonic())))
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("amiga_ip", type=ipaddress.IPv4Address,
                        help="IPv4 address of the Amiga interface being tested")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--duration", type=int, default=1800,
                        help="maximum session seconds (default 1800)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.duration <= 86400:
        parser.error("port must be 1..65535; duration must be 1..86400")
    print("Sending to %s:%d for at most %d seconds; Ctrl-C stops.\n"
          "Use the Amiga's received-byte results, not this sender's counts."
          % (args.amiga_ip, args.port, args.duration), flush=True)
    try:
        count = send_trials(str(args.amiga_ip), args.port, args.duration,
                            report=lambda s: print(s, flush=True))
    except KeyboardInterrupt:
        return 130
    return 0 if count else 1


if __name__ == "__main__":
    raise SystemExit(main())
