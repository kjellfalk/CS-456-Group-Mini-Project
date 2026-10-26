
# Authentication and ticket service
# Milestone 2: LOGIN and VALIDATE

import json
import secrets
import socket

HOST = "127.0.0.1"
PORT = 5000

# Dummy credentials for the classroom prototype.
DUMMY_USERS = {
    "student": "cs456-demo"
}

# Maps issued ticket strings to usernames.
ACTIVE_TICKETS = {}


def handle_request(request):
    """Process one JSON request and return a JSON response."""
    request_type = request.get("type")

    if request_type == "LOGIN":
        username = request.get("username")
        password = request.get("password")

        if DUMMY_USERS.get(username) != password:
            return {
                "status": "ERROR",
                "message": "Invalid username or password"
            }

        # Generate a difficult-to-guess ticket.
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


def main():
    """Run the TCP authentication service."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((HOST, PORT))
        server.listen()

        print(f"Authentication service listening on {HOST}:{PORT}")

        try:
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
                                request = json.loads(line.decode("utf-8"))

                                if not isinstance(request, dict):
                                    raise ValueError(
                                        "Request must be a JSON object"
                                    )

                                response = handle_request(request)

                            except (json.JSONDecodeError, UnicodeDecodeError,
                                    ValueError):
                                response = {
                                    "status": "ERROR",
                                    "message": "Invalid JSON request"
                                }

                            print(f"Request: {request if 'request' in locals() else 'Invalid input'}")

                            response_line = (
                                json.dumps(response) + "\n"
                            ).encode("utf-8")

                            stream.write(response_line)
                            stream.flush()

        except KeyboardInterrupt:
            print("\nAuthentication service shutting down.")


if __name__ == "__main__":
    main()
