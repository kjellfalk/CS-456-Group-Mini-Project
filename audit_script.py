"""CS456 adversarial audit: Part 1 spoof/replay; Part 2 false failover/checkpoint tampering.

Run only against the team's own localhost demonstration service.
"""
import argparse
import json
import socket
import time
from pathlib import Path

import config
from protocol import PLAIN_BEAT


def spoof_heartbeats(duration, interval):
    target = (config.HOST, config.MONITOR_PORT)
    print(f"[ATTACK] spoof -> {target} (every {interval}s)", flush=True)
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            sock.sendto(PLAIN_BEAT, target)
            count += 1
            print(f"[SPOOF] fake heartbeat #{count}", flush=True)
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
    print(f"[DONE] {count} fake heartbeats", flush=True)


def replay_heartbeats(duration, monitor_port):
    if monitor_port == config.MONITOR_PORT:
        raise ValueError("monitor port must differ from listening port")
    print(f"[ATTACK] replay: listen UDP {config.MONITOR_PORT}, forward to UDP {monitor_port}", flush=True)
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((config.HOST, config.MONITOR_PORT))
        sock.settimeout(0.5)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if not data.startswith(b"HEARTBEAT|"):
                continue
            count += 1
            sock.sendto(data, (config.HOST, monitor_port))
            print(f"[FORWARD] genuine heartbeat #{count}", flush=True)
            time.sleep(0.1)
            sock.sendto(data, (config.HOST, monitor_port))
            print(f"[REPLAY] exact duplicate #{count}", flush=True)
    print(f"[DONE] forwarded/replayed {count}", flush=True)


def _probe_primary():
    """A successful TCP LOGIN during the blackout proves primary is alive."""
    try:
        with socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall((json.dumps({"type": "LOGIN", "username": "student", "password": "cs456-demo"}) + "\n").encode())
            with sock.makefile("rb") as stream:
                raw = stream.readline()
        response = json.loads(raw)
        if response.get("status") == "OK":
            print("[PRIMARY STILL SERVING] TCP login succeeded while heartbeats are blocked", flush=True)
        else:
            print(f"[PRIMARY PROBE] received {response}", flush=True)
    except (OSError, ValueError) as exc:
        print(f"[PRIMARY PROBE] failed ({exc})", flush=True)


def false_failover(monitor_port, forward_seconds, drop_seconds, resume_seconds):
    """Proxy real service heartbeats, deliberately blacking them out temporarily.

    Start monitor with --secure --port 5002; then this relay; then primary --secure.
    While dropping beats, primary continues handling TCP requests on port 5000.
    """
    if monitor_port == config.MONITOR_PORT:
        raise ValueError("relay and monitor cannot listen on the same UDP port")
    print(f"[ATTACK] false failover. Proxy UDP {config.MONITOR_PORT} -> {monitor_port}", flush=True)
    print(f"[PLAN] forward {forward_seconds}s / DROP {drop_seconds}s / resume {resume_seconds}s", flush=True)
    forwarded = dropped = 0
    started = None
    probed = False
    final_time = forward_seconds + drop_seconds + resume_seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((config.HOST, config.MONITOR_PORT))
        sock.settimeout(0.4)
        print("[WAITING] Start auth_service.py --secure now", flush=True)
        while True:
            now = time.monotonic()
            if started is not None:
                elapsed = now - started
                if elapsed >= final_time:
                    break
                if forward_seconds <= elapsed < forward_seconds + drop_seconds and not probed and elapsed >= forward_seconds + 2:
                    probed = True
                    _probe_primary()
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if started is None:
                started = time.monotonic()
                print("[START] received first genuine heartbeat", flush=True)
            elapsed = time.monotonic() - started
            if elapsed < forward_seconds:
                sock.sendto(data, (config.HOST, monitor_port))
                forwarded += 1
                print(f"[FORWARD] heartbeat #{forwarded}", flush=True)
            elif elapsed < forward_seconds + drop_seconds:
                dropped += 1
                print(f"[DROP] primary heartbeat discarded #{dropped}; primary TCP service remains alive", flush=True)
            else:
                sock.sendto(data, (config.HOST, monitor_port))
                forwarded += 1
                print(f"[RESUME] heartbeat forwarded #{forwarded}", flush=True)
    print(f"[DONE] forwarded {forwarded}, dropped {dropped}. Inspect monitor and standby.log", flush=True)


def tamper_checkpoint(kind, path):
    """Local controlled checkpoint integrity test, run AFTER a successful LOGIN."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"No checkpoint at {target}. Log in first.")
    original = target.read_bytes()
    if kind == "delete":
        target.unlink()
    elif kind == "truncate":
        target.write_bytes(b'{"state":')
    elif kind == "corrupt":
        target.write_bytes(b'{"state": "not-a-valid-state", "hmac": "0000"}')
    elif kind == "forge":
        doc = json.loads(original)
        state = doc["state"]
        state["tickets"]["attacker-created-ticket"] = "student"
        # We intentionally do NOT update the HMAC; the secondary must reject it.
        target.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"[TAMPER] {kind}: modified {target} ({len(original)} original bytes)", flush=True)
    print("[NEXT] Trigger PRIMARY crash; secondary must reject damaged state and refuse old tickets", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["spoof", "replay", "false-failover", "tamper-checkpoint"], default="spoof")
    parser.add_argument("--duration", type=float, default=15)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--monitor-port", type=int, default=5002)
    parser.add_argument("--forward-seconds", type=float, default=5)
    parser.add_argument("--drop-seconds", type=float, default=9)
    parser.add_argument("--resume-seconds", type=float, default=5)
    parser.add_argument("--tamper-kind", choices=["corrupt", "forge", "truncate", "delete"], default="forge")
    parser.add_argument("--checkpoint-path", default=config.CHECKPOINT_FILE)
    args = parser.parse_args()
    if args.duration <= 0 or args.interval <= 0 or min(args.forward_seconds, args.drop_seconds, args.resume_seconds) < 0:
        parser.error("All durations/intervals must be positive (phase durations may be 0)")
    if args.mode == "spoof":
        spoof_heartbeats(args.duration, args.interval)
    elif args.mode == "replay":
        replay_heartbeats(args.duration, args.monitor_port)
    elif args.mode == "false-failover":
        false_failover(args.monitor_port, args.forward_seconds, args.drop_seconds, args.resume_seconds)
    else:
        tamper_checkpoint(args.tamper_kind, args.checkpoint_path)


if __name__ == "__main__":
    main()
