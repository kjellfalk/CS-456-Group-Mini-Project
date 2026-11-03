"""TCP authentication/ticket service and periodic heartbeat sender, CS456 Part 2.

Primary crashes probabilistically; the promoted secondary reuses the same
handler but restores its ticket state and does not inject random crashes.
"""
import json
import os
import random
import secrets
import socket
import sys
import threading

import config
from checkpoint import save_checkpoint, load_checkpoint, CheckpointError
from protocol import build_heartbeat

DUMMY_USERS = {"student": "cs456-demo"}
ACTIVE_TICKETS = {}


def handle_request(request, crash_probability=0.05):
    """Process one JSON request. LOGIN state is checkpointed before responding."""
    if random.random() < crash_probability:
        print("[CRASH] Simulated hard process termination", flush=True)
        os._exit(1)

    request_type = request.get("type")
    if request_type == "LOGIN":
        username = request.get("username")
        password = request.get("password")
        if DUMMY_USERS.get(username) != password:
            return {"status": "ERROR", "message": "Invalid username or password"}
        ticket = secrets.token_urlsafe(16)
        ACTIVE_TICKETS[ticket] = username
        try:
            save_checkpoint(ACTIVE_TICKETS)
        except CheckpointError as exc:
            ACTIVE_TICKETS.pop(ticket, None)
            print(f"[CHECKPOINT] ERROR: {exc}", flush=True)
            return {"status": "ERROR", "message": "Could not safely persist ticket"}
        return {"status": "OK", "message": "Login successful", "ticket": ticket}

    if request_type == "VALIDATE":
        username = ACTIVE_TICKETS.get(request.get("ticket"))
        if username is None:
            return {"status": "ERROR", "message": "Invalid ticket"}
        return {"status": "OK", "message": "Ticket valid", "username": username}
    return {"status": "ERROR", "message": "Unknown request type"}


def heartbeat_loop(stop_event, secure, node_id):
    boot_id = secrets.token_hex(4)
    seq = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as beat_sock:
        while not stop_event.is_set():
            try:
                beat_sock.sendto(build_heartbeat(node_id, boot_id, seq, secure),
                                 (config.HOST, config.MONITOR_PORT))
                seq += 1
            except OSError as exc:
                print(f"[HEARTBEAT] send failed: {exc}", flush=True)
            stop_event.wait(config.HEARTBEAT_INTERVAL_MS / 1000)


def run_server(secure=False, restore=False, crash_probability=0.05, node_id="primary"):
    if not (0 <= crash_probability <= 1):
        raise ValueError("Crash probability must be between 0 and 1")
    global ACTIVE_TICKETS
    if restore:
        ACTIVE_TICKETS, status = load_checkpoint()
        print(f"[CHECKPOINT] {status}", flush=True)
        if status.startswith("REJECTED"):
            print("[ALERT] Checkpoint integrity failed; refusing all old tickets", flush=True)
    else:
        ACTIVE_TICKETS = {}

    stop_event = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # On Windows, SO_EXCLUSIVEADDRUSE prevents two live servers on port 5000.
        # On POSIX, REUSEADDR allows rapid restart but not simultaneous TCP listeners.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((config.HOST, config.SERVICE_PORT))
        except OSError as exc:
            print(f"[SPLIT-BRAIN BLOCKED] Cannot take primary port {config.SERVICE_PORT}: {exc}", flush=True)
            return 2
        server.listen(10)
        print(f"[SERVICE] {node_id} listening on tcp://{config.HOST}:{config.SERVICE_PORT}", flush=True)
        heartbeat_thread = threading.Thread(target=heartbeat_loop,
                                            args=(stop_event, secure, node_id), daemon=True)
        # Heartbeats begin only AFTER successful TCP port ownership.
        heartbeat_thread.start()
        try:
            while True:
                connection, address = server.accept()
                with connection:
                    print(f"[CLIENT] connected from {address}", flush=True)
                    with connection.makefile("rwb") as stream:
                        while True:
                            try:
                                line = stream.readline()
                            except (ConnectionError, OSError):
                                break
                            if not line:
                                break
                            try:
                                request = json.loads(line.decode("utf-8"))
                                if not isinstance(request, dict):
                                    raise ValueError("request must be object")
                                response = handle_request(request, crash_probability)
                            except (ValueError, UnicodeError):
                                response = {"status": "ERROR", "message": "Invalid JSON request"}
                            print(f"[RESPONSE] {response}", flush=True)
                            try:
                                stream.write((json.dumps(response) + "\n").encode("utf-8"))
                                stream.flush()
                            except (ConnectionError, OSError):
                                break
        except KeyboardInterrupt:
            print(f"[SERVICE] {node_id} shutting down", flush=True)
        finally:
            stop_event.set()
            heartbeat_thread.join(timeout=3)
    return 0


def main():
    secure = "--secure" in sys.argv
    try:
        probability = float(os.environ.get("CRASH_PROBABILITY", "0.05"))
    except ValueError:
        raise SystemExit("CRASH_PROBABILITY must be a number between 0 and 1")
    return run_server(secure=secure, crash_probability=probability, node_id="primary")


if __name__ == "__main__":
    sys.exit(main())
