"""Part 2 client: retries after a crash and validates the SAME original ticket."""
import json
import socket
import time

import config


def connect_with_retry(timeout_s=30, delay_s=0.5):
    started = time.monotonic()
    attempt = 0
    while time.monotonic() - started < timeout_s:
        attempt += 1
        try:
            sock = socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2)
            sock.settimeout(5)
            print(f"[CLIENT] connected after {time.monotonic()-started:.2f}s; attempt {attempt}", flush=True)
            return sock, sock.makefile("rb")
        except OSError:
            print(f"[CLIENT] reconnect attempt {attempt}", flush=True)
            time.sleep(delay_s)
    return None, None


def send_request(sock, stream, request):
    try:
        sock.sendall((json.dumps(request) + "\n").encode())
        raw = stream.readline()
        return json.loads(raw) if raw else None
    except (OSError, ValueError):
        return None


def _close(sock, stream):
    if stream is not None:
        stream.close()
    if sock is not None:
        sock.close()


def main():
    sock, stream = connect_with_retry()
    if not sock:
        print("[CLIENT] initial connection failed", flush=True)
        return
    try:
        response = send_request(sock, stream, {"type": "LOGIN", "username": "student", "password": "cs456-demo"})
        if not response or response.get("status") != "OK":
            print(f"[CLIENT] login failed: {response}", flush=True)
            return
        ticket = response["ticket"]
        print(f"[CLIENT] TICKET ISSUED: {ticket} (will reuse after failover)", flush=True)
        count = 0
        recovered = False
        while True:
            count += 1
            response = send_request(sock, stream, {"type": "VALIDATE", "ticket": ticket})
            if response is None:
                print("[CLIENT] connection lost; waiting for automated recovery...", flush=True)
                _close(sock, stream)
                sock, stream = connect_with_retry()
                if not sock:
                    print("[CLIENT] recovery failed: no service after 30s", flush=True)
                    return
                recovered = True
                continue
            print(f"[CLIENT] VALIDATE #{count}: {response}", flush=True)
            if recovered:
                if response.get("status") == "OK":
                    print("[PASS] SAME pre-crash ticket accepted by recovered secondary", flush=True)
                else:
                    print("[FAIL] Pre-crash ticket was NOT restored", flush=True)
                recovered = False
            time.sleep(1)
    except KeyboardInterrupt:
        print("[CLIENT] stopped", flush=True)
    finally:
        _close(sock, stream)


if __name__ == "__main__":
    main()
