"""
client.py
Test client for the Authentication/Ticket Service.
"""

import socket
import json
import time
import sys
import config

def send_request(sock, request_dict):
    """Encodes a dictionary as JSON, sends it, and parses the JSON response."""
    try:
        line = json.dumps(request_dict) + "\n"
        sock.sendall(line.encode("utf-8"))
        
        # Read the response
        response_line = sock.recv(4096)
        if not response_line:
            return None
        return json.loads(response_line.decode("utf-8"))
    except (ConnectionResetError, BrokenPipeError):
        return None

def main():
    print(f"Connecting to Authentication Service at {config.HOST}:{config.SERVICE_PORT}...\n")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((config.HOST, config.SERVICE_PORT))
            
            # --- 1. LOGIN ---
            login_req = {
                "type": "LOGIN",
                "username": "student",
                "password": "cs456-demo"
            }
            print(f"[*] Sending LOGIN Request: {login_req}")
            resp = send_request(sock, login_req)
            print(f"[*] Response Received: {resp}\n")
            
            if not resp or resp.get("status") != "OK":
                print("[!] Login failed. Exiting.")
                return
            
            ticket = resp.get("ticket")
            
            # --- 2. VALIDATE (Looping to trigger server crash) ---
            validate_req = {
                "type": "VALIDATE",
                "ticket": ticket
            }
            
            req_count = 1
            while True:
                print(f"[Request {req_count}] Sending VALIDATE Request...")
                resp = send_request(sock, validate_req)
                
                if not resp:
                    # An empty response or connection error indicates the server crashed
                    print("\n[!] Connection lost! The authentication service crashed.")
                    print("[!] Check the Heartbeat Monitor to see if it detects the failure.")
                    break
                
                print(f"    Received: {resp}")
                req_count += 1
                time.sleep(1)  # Sleep briefly to space out requests
                
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the auth_service.py running on port {config.SERVICE_PORT}?")
    except KeyboardInterrupt:
        print("\nClient stopped by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()