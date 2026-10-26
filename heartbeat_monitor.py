"""Heartbeat Monitor: an independent process that detects when the auth service crashes.

The service pushes a UDP heartbeat every T ms. If no valid beat arrives for
N * T (the timeout window W), the monitor declares the service DOWN, prints a
timestamped alert, and appends it to the incident log.

The monitor only listens on a socket and never touches the service process,
so it keeps running when the service dies.

Usage:
    python3 monitor.py                 # baseline: accepts plain "HEARTBEAT"
    python3 monitor.py --secure        # requires HMAC-signed, non-replayed beats
    python3 monitor.py --quiet         # hide the per-beat lines, show only events
"""
import argparse
import socket
import sys
import time
from datetime import datetime

import config
from protocol import parse_heartbeat

# Colours make the video demo easier to follow; disabled when output is piped.
_COLOURS = {"UP": "32", "RECOVERED": "32", "ALERT": "31", "REJECTED": "33", "BEAT": "90"}
_USE_COLOUR = sys.stdout.isatty()


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log(event: str, message: str, to_file: bool = True) -> None:
    """Print one timestamped line, and also append it to the incident log."""
    line = f"[{_now_str()}] {event:<9} {message}"
    if _USE_COLOUR and event in _COLOURS:
        print(f"\033[{_COLOURS[event]}m{line}\033[0m", flush=True)
    else:
        print(line, flush=True)
    if to_file:
        try:
            with open(config.INCIDENT_LOG, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            # Failing to write the log must not take the monitor down.
            print(f"[{_now_str()}] WARN      could not write incident log: {e}", flush=True)


class HeartbeatMonitor:
    # States: WAITING (no beat seen yet), UP, DOWN.

    def __init__(self, port: int, interval_ms: int, threshold: int, secure: bool, verbose: bool):
        self.port = port
        self.interval_s = interval_ms / 1000
        self.threshold = threshold
        self.timeout_s = self.interval_s * threshold  # W = N * T
        self.secure = secure
        self.verbose = verbose

        self.state = "WAITING"
        self.last_beat_at = None  # time.monotonic() of the last valid beat
        self.down_since = None
        self.beats_accepted = 0
        self.beats_rejected = 0
        # Secure mode: highest sequence number seen for each (node_id, boot_id).
        self.last_seq = {}

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((config.HOST, self.port))
        # Wake up several times per interval so a timeout is caught promptly
        # even when no packets arrive.
        sock.settimeout(self.interval_s / 4)

        mode = "SECURE (HMAC + replay protection)" if self.secure else "BASELINE (plaintext)"
        log("START", f"monitor on udp://{config.HOST}:{self.port}  mode={mode}  "
                     f"T={self.interval_s * 1000:.0f}ms  N={self.threshold}  W={self.timeout_s:.2f}s")
        log("WAITING", "waiting for first heartbeat...", to_file=False)

        try:
            while True:
                try:
                    try:
                        data, addr = sock.recvfrom(4096)
                    except socket.timeout:
                        data, addr = None, None
                    now = time.monotonic()
                    if data is not None:
                        self._handle_packet(data, addr, now)
                    self._check_timeout(now)
                except Exception as e:
                    # Keep running whatever happens: a bad packet or bug must
                    # not kill the monitor.
                    log("ERROR", f"unexpected error, continuing: {e!r}")
        except KeyboardInterrupt:
            log("STOP", f"monitor stopped. accepted={self.beats_accepted} "
                        f"rejected={self.beats_rejected} final_state={self.state}")
        finally:
            sock.close()

    def _handle_packet(self, data: bytes, addr, now: float) -> None:
        sender = f"{addr[0]}:{addr[1]}"
        try:
            beat = parse_heartbeat(data, self.secure)
        except ValueError as reason:
            self._reject(sender, str(reason))
            return

        if self.secure:
            key = (beat.node_id, beat.boot_id)
            if beat.seq <= self.last_seq.get(key, -1):
                self._reject(sender, f"replayed/out-of-order seq={beat.seq} "
                                     f"(last={self.last_seq[key]})")
                return
            self.last_seq[key] = beat.seq

        self.beats_accepted += 1
        self.last_beat_at = now

        if self.state == "WAITING":
            self.state = "UP"
            log("UP", f"service is UP (first heartbeat from {sender})")
        elif self.state == "DOWN":
            downtime = now - self.down_since
            self.state = "UP"
            log("RECOVERED", f"heartbeats resumed from {sender}; "
                             f"down for {downtime:.2f}s after detection")

        if self.verbose:
            detail = f" node={beat.node_id} seq={beat.seq}" if self.secure else ""
            log("BEAT", f"#{self.beats_accepted} from {sender}{detail}", to_file=False)

    def _reject(self, sender: str, reason: str) -> None:
        self.beats_rejected += 1
        log("REJECTED", f"from {sender}: {reason}")

    def _check_timeout(self, now: float) -> None:
        if self.state != "UP":
            return
        silence = now - self.last_beat_at
        if silence > self.timeout_s:
            self.state = "DOWN"
            self.down_since = now
            missed = int(silence / self.interval_s)
            log("ALERT", f"SERVICE DOWN: no valid heartbeat for {silence:.2f}s "
                         f"(~{missed} missed beats, threshold N={self.threshold})")
            self.on_failure()

    def on_failure(self) -> None:
        """Called once each time the service is declared DOWN.

        Part 1: detection only, so this does nothing extra.
        Part 2: launch the standby node here (load checkpoint, take over port).
        """
        pass


def main() -> None:
    p = argparse.ArgumentParser(description="Heartbeat monitor for the CS456 auth service.")
    p.add_argument("--secure", action="store_true",
                   help="require HMAC-signed beats and reject replays")
    p.add_argument("--port", type=int, default=config.MONITOR_PORT)
    p.add_argument("--interval", type=int, default=config.HEARTBEAT_INTERVAL_MS,
                   help="heartbeat interval T in ms (default %(default)s)")
    p.add_argument("--threshold", type=int, default=config.MISSED_BEAT_THRESHOLD,
                   help="missed-beat threshold N (default %(default)s)")
    p.add_argument("--quiet", action="store_true", help="don't print every accepted beat")
    args = p.parse_args()

    HeartbeatMonitor(args.port, args.interval, args.threshold, args.secure,
                     verbose=not args.quiet).run()


if __name__ == "__main__":
    main()
