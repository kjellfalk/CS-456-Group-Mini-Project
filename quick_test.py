"""Run end-to-end classroom recovery/audit checks; no third-party packages required.

Expected runtime ~45-75 seconds, uses localhost TCP 5000 / UDP 5001,5002.
Does not permanently modify source files. Cleanup all launched processes.
"""
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "test_logs"
LOGS.mkdir(exist_ok=True)
PROCESSES = []


def spawn(tag, *args, env=None):
    out = open(LOGS / f"{tag}.log", "w", encoding="utf-8")
    proc = subprocess.Popen([sys.executable, *args], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                            env={**os.environ, **(env or {})})
    PROCESSES.append((proc, out))
    return proc


def stop_all():
    # Standbys spawned by the monitor are independent processes.
    monitor_log = (LOGS / "monitor.log")
    if monitor_log.exists():
        for pid in set(int(n) for n in re.findall(r"pid (\d+)", monitor_log.read_text(errors="replace"))):
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
    for proc, output in PROCESSES:
        if proc.poll() is None:
            proc.terminate()
    for proc, output in PROCESSES:
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        output.close()
    PROCESSES.clear()
    time.sleep(0.4)


def clear_state():
    stop_all()
    for name in ("checkpoint.json", "standby.log", "incidents.log"):
        (ROOT / name).unlink(missing_ok=True)
    (LOGS / "monitor.log").unlink(missing_ok=True)


def request(obj, timeout=2):
    with socket.create_connection(("127.0.0.1", 5000), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((json.dumps(obj) + "\n").encode())
        with sock.makefile("rb") as source:
            result = source.readline()
        return json.loads(result)


def login():
    return request({"type": "LOGIN", "username": "student", "password": "cs456-demo"})


def validate(ticket):
    return request({"type": "VALIDATE", "ticket": ticket})


def until(predicate, timeout=15, interval=0.2, explain="condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(interval)
    raise AssertionError(f"Timed out waiting for: {explain}")


def text_log(tag):
    path = LOGS / f"{tag}.log"
    return path.read_text(errors="replace") if path.exists() else ""


def test_recovery():
    print("TEST 1: primary crash -> standby recovery -> same ticket valid", flush=True)
    clear_state()
    spawn("monitor", "heartbeat_monitor.py", "--secure")
    time.sleep(0.4)
    primary = spawn("primary", "auth_service.py", "--secure", env={"CRASH_PROBABILITY": "0"})
    until(lambda: "service is UP" in text_log("monitor"), explain="UP heartbeat")
    response = login()
    assert response["status"] == "OK", response
    ticket = response["ticket"]
    assert validate(ticket)["status"] == "OK"
    assert (ROOT / "checkpoint.json").exists(), "checkpoint missing after LOGIN"
    primary.kill()
    primary.wait()
    until(lambda: "[Service Restored]" in text_log("monitor"), timeout=16, explain="recovery heartbeat")
    assert validate(ticket)["status"] == "OK", "PRE-CRASH TICKET WAS LOST"
    print("PASS: pre-crash ticket accepted after automatic failover", flush=True)


def test_tamper():
    print("TEST 2: forged checkpoint -> fail closed on failover", flush=True)
    clear_state()
    spawn("monitor", "heartbeat_monitor.py", "--secure")
    time.sleep(0.4)
    primary = spawn("primary", "auth_service.py", "--secure", env={"CRASH_PROBABILITY": "0"})
    until(lambda: "service is UP" in text_log("monitor"), explain="UP heartbeat")
    original = login()["ticket"]
    from audit_script import tamper_checkpoint
    tamper_checkpoint("forge", ROOT / "checkpoint.json")
    primary.kill()
    primary.wait()
    until(lambda: "[Service Restored]" in text_log("monitor"), timeout=16, explain="restored service")
    assert validate(original)["status"] == "ERROR", "tampered checkpoint should not retain old ticket"
    assert validate("attacker-created-ticket")["status"] == "ERROR", "FORGED TICKET ACCEPTED"
    standby_log = (ROOT / "standby.log").read_text(errors="replace")
    assert "HMAC mismatch" in standby_log, standby_log
    print("PASS: checkpoint tampering detected; old and forged tickets rejected", flush=True)


def test_false_failover():
    print("TEST 3: dropped heartbeats -> false failover -> no double primary", flush=True)
    clear_state()
    spawn("monitor", "heartbeat_monitor.py", "--secure", "--port", "5002")
    time.sleep(0.4)
    spawn("audit", "audit_script.py", "--mode", "false-failover", "--monitor-port", "5002",
          "--forward-seconds", "5", "--drop-seconds", "9", "--resume-seconds", "5")
    time.sleep(0.4)
    primary = spawn("primary", "auth_service.py", "--secure", env={"CRASH_PROBABILITY": "0"})
    until(lambda: "service is UP" in text_log("monitor"), explain="UP after relay forward")
    until(lambda: "[Crash Detected]" in text_log("monitor"), timeout=18, explain="false failure detection")
    until(lambda: "standby (pid" in text_log("monitor") and "exited with code" in text_log("monitor"), timeout=8,
          explain="secondary denied occupied port")
    assert primary.poll() is None, "Primary unexpectedly died"
    assert login()["status"] == "OK", "Primary not serving during false alarm"
    until(lambda: "heartbeats resumed" in text_log("monitor"), timeout=12, explain="RECOVERED after relay resumes")
    secondary_log = (ROOT / "standby.log").read_text(errors="replace")
    assert "SPLIT-BRAIN BLOCKED" in secondary_log, secondary_log
    print("PASS: original primary remained alive; competing secondary rejected port", flush=True)


if __name__ == "__main__":
    try:
        test_recovery()
        test_tamper()
        test_false_failover()
        print("ALL 3 INTEGRATION TESTS PASSED", flush=True)
    except Exception as exc:
        print(f"TEST FAILED: {exc}", flush=True)
        for name in ("monitor", "primary", "audit"):
            print(f"--- {name} ---\n{text_log(name)[-3500:]}", flush=True)
        path = ROOT / "standby.log"
        if path.exists():
            print(f"--- standby ---\n{path.read_text(errors='replace')[-3500:]}", flush=True)
        sys.exit(1)
    finally:
        stop_all()
