"""Heartbeat Monitor and Failover Controller for the auth service.

Part 1 (detection): the service pushes a UDP heartbeat every T ms. If no
valid beat arrives for N * T (the timeout window W), the monitor declares the
service DOWN, prints a timestamped alert, and appends it to the incident log.

Part 2 (recovery): on each DOWN, the monitor launches the standby
(config.STANDBY_SCRIPT), which loads the latest checkpoint and takes over the
service port. The log shows the full timeline:
    [Crash Detected] -> [Failover Triggered] -> [Service Restored]

The monitor only listens on a socket and never touches the service process,
so it keeps running when the service dies.

Usage:
    python3 heartbeat_monitor.py                 # baseline: accepts plain "HEARTBEAT"
    python3 heartbeat_monitor.py --secure        # requires HMAC-signed, non-replayed beats
    python3 heartbeat_monitor.py --no-failover   # Part 1 behaviour: detect and alert only
    python3 heartbeat_monitor.py --quiet         # hide the per-beat lines, show only events
"""
import argparse
import socket
import subprocess
import sys
import time
from datetime import datetime

import config
from protocol import parse_heartbeat

# Colours make the video demo easier to follow; disabled when output is piped.
_COLOURS = {"UP": "32", "RECOVERED": "32", "RESTORED": "32", "ALERT": "31",
            "FAILOVER": "36", "STANDBY": "33", "REJECTED": "33", "BEAT": "90"}
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

    def __init__(self, port: int, interval_ms: int, threshold: int, secure: bool,
                 verbose: bool, failover: bool):
        self.port = port
        self.interval_s = interval_ms / 1000
        self.threshold = threshold
        self.timeout_s = self.interval_s * threshold  # W = N * T
        self.secure = secure
        self.verbose = verbose
        self.failover = failover

        self.state = "WAITING"
        self.last_beat_at = None  # time.monotonic() of the last valid beat
        self.down_since = None    # when the current outage was detected
        self.beats_accepted = 0
        self.beats_rejected = 0
        # Secure mode: highest sequence number seen for each (node_id, boot_id).
        self.last_seq = {}

        # Failover state.
        self.standby_proc = None          # the standby we launched most recently
        self.standby_exit_reported = False
        self.launched_this_outage = False

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((config.HOST, self.port))
        # Wake up several times per interval so a timeout is caught promptly
        # even when no packets arrive.
        sock.settimeout(self.interval_s / 4)

        mode = "SECURE (HMAC + replay protection)" if self.secure else "BASELINE (plaintext)"
        failover = f"on ({config.STANDBY_SCRIPT})" if self.failover else "off"
        log("START", f"monitor on udp://{config.HOST}:{self.port}  mode={mode}  "
                     f"T={self.interval_s * 1000:.0f}ms  N={self.threshold}  "
                     f"W={self.timeout_s:.2f}s  failover={failover}")
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
                    self._check_standby_exit()
                except Exception as e:
                    # Keep running whatever happens: a bad packet or bug must
                    # not kill the monitor.
                    log("ERROR", f"unexpected error, continuing: {e!r}")
        except KeyboardInterrupt:
            log("STOP", f"monitor stopped. accepted={self.beats_accepted} "
                        f"rejected={self.beats_rejected} final_state={self.state}")
            if self._standby_running():
                pid = self.standby_proc.pid
                log("STOP", f"standby (pid {pid}) is still serving; stop it with: kill {pid}")
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

        node = f" node={beat.node_id}" if self.secure else ""
        self.beats_accepted += 1

        if self.state == "WAITING":
            self.state = "UP"
            log("UP", f"service is UP (first heartbeat from {sender}{node})")
        elif self.state == "DOWN":
            since_detect = now - self.down_since
            outage = now - self.last_beat_at
            self.state = "UP"
            if self.launched_this_outage and self._standby_running():
                log("RESTORED", f"[Service Restored] standby is serving (heartbeat from "
                                f"{sender}{node}); {since_detect:.2f}s after detection, "
                                f"total outage {outage:.2f}s")
            else:
                # Beats came back without a working failover, e.g. the
                # original primary was only delayed (a false failover).
                log("RECOVERED", f"heartbeats resumed from {sender}{node}; "
                                 f"{since_detect:.2f}s after detection, "
                                 f"total outage {outage:.2f}s")
            self.launched_this_outage = False

        self.last_beat_at = now

        if self.verbose:
            detail = f"{node} seq={beat.seq}" if self.secure else ""
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
            log("ALERT", f"[Crash Detected] SERVICE DOWN: no valid heartbeat for "
                         f"{silence:.2f}s (~{missed} missed beats, threshold N={self.threshold})")
            self.on_failure()

    def on_failure(self) -> None:
        """Called once each time the service is declared DOWN: launch the standby.

        The standby loads the latest checkpoint and takes over the service
        port. It is launched again on every outage, so if it crashes too, the
        next standby restores from the checkpoint it was writing.
        """
        if not self.failover:
            return
        if self._standby_running():
            # Never run two standbys at once.
            log("FAILOVER", f"standby (pid {self.standby_proc.pid}) is already running; "
                            f"not launching another")
            return

        cmd = [sys.executable, config.STANDBY_SCRIPT] + (["--secure"] if self.secure else [])
        shown = "python3 " + " ".join(cmd[1:])
        try:
            with open(config.STANDBY_LOG, "a") as out:
                # New session: a Ctrl-C in the monitor's terminal must not
                # also kill the service that just took over.
                self.standby_proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                                                     start_new_session=True)
        except OSError as e:
            log("ERROR", f"[Failover Failed] could not launch `{shown}`: {e}")
            return

        self.standby_exit_reported = False
        self.launched_this_outage = True
        log("FAILOVER", f"[Failover Triggered] launched standby `{shown}` "
                        f"(pid {self.standby_proc.pid}, output in {config.STANDBY_LOG})")

    def _standby_running(self) -> bool:
        return self.standby_proc is not None and self.standby_proc.poll() is None

    def _check_standby_exit(self) -> None:
        """Log once when a standby we launched exits, with its exit code.

        A standby that exits straight after launch usually means the original
        primary still holds the service port (false failover), or the
        standby script is missing; its output in STANDBY_LOG says which.
        """
        if self.standby_proc is None or self.standby_exit_reported:
            return
        code = self.standby_proc.poll()
        if code is not None:
            self.standby_exit_reported = True
            log("STANDBY", f"standby (pid {self.standby_proc.pid}) exited with code {code}; "
                           f"see {config.STANDBY_LOG}")


def main() -> None:
    p = argparse.ArgumentParser(description="Heartbeat monitor and failover controller "
                                            "for the CS456 auth service.")
    p.add_argument("--secure", action="store_true",
                   help="require HMAC-signed beats and reject replays")
    p.add_argument("--port", type=int, default=config.MONITOR_PORT)
    p.add_argument("--interval", type=int, default=config.HEARTBEAT_INTERVAL_MS,
                   help="heartbeat interval T in ms (default %(default)s)")
    p.add_argument("--threshold", type=int, default=config.MISSED_BEAT_THRESHOLD,
                   help="missed-beat threshold N (default %(default)s)")
    p.add_argument("--no-failover", action="store_true",
                   help="detect and alert only (Part 1); don't launch the standby")
    p.add_argument("--quiet", action="store_true", help="don't print every accepted beat")
    args = p.parse_args()

    HeartbeatMonitor(args.port, args.interval, args.threshold, args.secure,
                     verbose=not args.quiet, failover=not args.no_failover).run()


if __name__ == "__main__":
    main()
