
# Authentication and ticket service
# Milestone 3: Heartbeat thread
import sys
import json
import secrets
import socket
import threading

from protocol import build_heartbeat

HOST = "127.0.0.1"
PORT = 5000

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 5001
HEARTBEAT_INTERVAL = 2

SECURE_HEARTBEAT = "--secure" in sys.argv
NODE_ID = "primary"

DUMMY_USERS = {
    "student": "cs456-demo"
}

ACTIVE_TICKETS = {}


def handle_request(request):
    """Process one JSON request and return a JSON response."""
    # Simulating a hard crash so the monitor triggers.
    if random.random() < 0.15:
        print("\n[!] FATAL: Simulated memory corruption! Crashing process now.\n")
        os._exit(1)
    
    request_type = request.get("type")

    if request_type == "LOGIN":
        username = request.get("username")
        password = request.get("password")

        if DUMMY_USERS.get(username) != password:
            return {
                "status": "ERROR",
                "message": "Invalid username or password"
            }

        ticket = secrets.token_urlsafe(16)
        ACTIVE_TICKETS[ticket] = username

        return {
            "status": "OK",
            "message": "Login successful",
            "ticket": ticket
        }

    if request_type == "VALIDATE":
        ticket = request.get("ticket")
        username = ACTIVE_TICKETS.get(ticket)

        if username is None:
            return {
                "status": "ERROR",
                "message": "Invalid ticket"
            }

        return {
            "status": "OK",
            "message": "Ticket valid",
            "username": username
        }

    return {
        "status": "ERROR",
        "message": "Unknown request type"
    }


def heartbeat_loop(stop_event):
    """Send periodic UDP heartbeats to the monitor."""
    boot_id = secrets.token_hex(4)
    seq = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as heartbeat_socket:
        while not stop_event.is_set():
            try:
                beat = build_heartbeat(NODE_ID, boot_id, seq, SECURE_HEARTBEAT)
                heartbeat_socket.sendto(beat, (MONITOR_HOST, MONITOR_PORT))
                seq += 1
            except OSError as error:
                print(f"Heartbeat send failed: {error}")

            # Wait between heartbeats, but allow prompt shutdown.
            stop_event.wait(HEARTBEAT_INTERVAL)


def main():
    """Run the TCP authentication service and heartbeat thread."""
    stop_event = threading.Event()

    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        args=(stop_event,),
        name="heartbeat-thread",
        daemon=True
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )

            server.bind((HOST, PORT))
            server.listen()

            print(f"Authentication service listening on {HOST}:{PORT}")
            print(
                f"Sending UDP heartbeats to "
                f"{MONITOR_HOST}:{MONITOR_PORT}"
            )

            heartbeat_thread.start()

            while True:
                connection, address = server.accept()

                with connection:
                    print(f"Connected by {address}")

                    with connection.makefile("rwb") as stream:
                        while True:
                            line = stream.readline()

                            if not line:
                                break

                            try:
                                request = json.loads(
                                    line.decode("utf-8")
                                )

                                if not isinstance(request, dict):
                                    raise ValueError(
                                        "Request must be a JSON object"
                                    )

                                response = handle_request(request)

                            except (
                                json.JSONDecodeError,
                                UnicodeDecodeError,
                                ValueError
                            ):
                                response = {
                                    "status": "ERROR",
                                    "message": "Invalid JSON request"
                                }

                            print(f"Response: {response}")

                            response_line = (
                                json.dumps(response) + "\n"
                            ).encode("utf-8")

                            stream.write(response_line)
                            stream.flush()

    except KeyboardInterrupt:
        print("\nAuthentication service shutting down.")

    finally:
        stop_event.set()
        heartbeat_thread.join(timeout=3)


if __name__ == "__main__":
    main()
