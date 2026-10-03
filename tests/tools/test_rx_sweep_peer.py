#!/usr/bin/env python3
"""Local TCP checks for the shipping sender; no Amiga or lab rig required."""
import importlib.util
from pathlib import Path
import socket
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location(
    "rx_sweep_peer", Path(__file__).resolve().parents[2] /
    "install/examples/ReceiveSweep/rx-sweep-peer.py")
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


class PeerTest(unittest.TestCase):
    def test_reconnect_after_receiver_closes_each_trial(self):
        received = []
        ready = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)

            def receiver():
                ready.set()
                for _ in range(3):
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(1)
                        received.append(conn.recv(4096))

            thread = threading.Thread(target=receiver)
            thread.start()
            ready.wait(1)
            count = peer.send_trials("127.0.0.1", listener.getsockname()[1],
                                     duration=0.4, retry=0.05, report=lambda _: None)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertGreaterEqual(count, 3)
            self.assertEqual(len(received), 3)
            self.assertTrue(all(data and peer.PAYLOAD.startswith(data) for data in received))

    def test_missing_receiver_is_bounded(self):
        # Bound but not listening: reserves the port throughout this check.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            start = time.monotonic()
            self.assertEqual(peer.send_trials(
                "127.0.0.1", reserved.getsockname()[1], duration=0.2,
                retry=0.03, report=lambda _: None), 0)
            self.assertLess(time.monotonic() - start, 1)


if __name__ == "__main__":
    unittest.main()
