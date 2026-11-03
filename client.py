"""
client.py
Test client for the Authentication/Ticket Service (Part 2 - Recovery).
"""

import socket
import json
import time
import config

def connect_with_retry(timeout_s=30, delay_s=0.5):
    """Keep trying to connect until the service (or its standby) answers."""
    start = time.monotonic()
    attempt = 0
    while time.monotonic() - start < timeout_s:
        attempt += 1
        try:
            sock = socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2)
            elapsed = time.monotonic() - start
            print(f"[+] Reconnected after {elapsed:.1f}s")
            return sock, sock.makefile("rb")
        except OSError:
            print(f"[*] Reconnect attempt {attempt}...")
            time.sleep(delay_s)
    return None, None

def send_request(sock, stream, request_dict):
    """Encodes a dictionary as JSON, sends it, and parses the JSON response by line."""
    try:
        line = json.dumps(request_dict) + "\n"
        sock.sendall(line.encode("utf-8"))
        
        # Read the response by line to avoid split/merged replies
        response_line = stream.readline()
        if not response_line:
            return None
        return json.loads(response_line.decode("utf-8"))
    except (OSError, json.JSONDecodeError):
        # Treats broken pipes, connection resets, and half-received JSON as a lost connection
        return None

def main():
    print(f"Connecting to Authentication Service at {config.HOST}:{config.SERVICE_PORT}...\n")
    
    try:
        sock = socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2)
        stream = sock.makefile("rb")
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is service.py running on port {config.SERVICE_PORT}?")
        return
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        return

    try:
        # --- 1. LOGIN ---
        login_req = {
            "type": "LOGIN",
            "username": "student",
            "password": "cs456-demo"
        }
        print(f"[*] Sending LOGIN Request: {login_req}")
        resp = send_request(sock, stream, login_req)
        print(f"[*] Response Received: {resp}\n")
        
        if not resp or resp.get("status") != "OK":
            print("[!] Login failed. Exiting.")
            sock.close()
            return
        
        ticket = resp.get("ticket")
        print(f"[*] Ticket issued: {ticket}\n")
        
        # --- 2. VALIDATE (Looping to trigger server crash) ---
        validate_req = {
            "type": "VALIDATE",
            "ticket": ticket
        }
        
        req_count = 1
        was_reconnected = False
        
        while True:
            if was_reconnected:
                print(f"[Request {req_count}] Same ticket {ticket[:7]}... -> ", end="", flush=True)
            else:
                print(f"[Request {req_count}] Sending VALIDATE Request...")
                
            resp = send_request(sock, stream, validate_req)
            
            if not resp:
                print("\n[!] Connection lost - service crashed. Reconnecting...")
                sock.close()
                
                # Initiate automated reconnect sequence
                sock, stream = connect_with_retry()
                if not sock:
                    print("[!] Failed to reconnect after 30 seconds. Exiting.")
                    break
                
                was_reconnected = True
                continue
            
            if was_reconnected:
                print(f"{resp}")
                was_reconnected = False
            else:
                print(f"    Received: {resp}")
            
            # Verify if the failover preserved our state
            if resp.get("status") == "ERROR" and resp.get("message") == "Invalid ticket":
                print("[!] Ticket rejected after failover - state was NOT preserved.")
            
            req_count += 1
            time.sleep(1)  # Sleep briefly to space out requests
            
    except KeyboardInterrupt:
        print("\nClient stopped by user.")
        if sock:
            sock.close()

if __name__ == "__main__":
    main()