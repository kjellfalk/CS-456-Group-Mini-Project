# 1) A working TCP Server

import socket

HOST = "127.0.0.1"
PORT = 5000


def main():
    # Create a TCP socket.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # Allow the address to be reused after the server stops.
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the local address and port.
        server.bind((HOST, PORT))

        # Begin listening for incoming connections.
        server.listen()
        print(f"Authentication service listening on {HOST}:{PORT}")

        try:
            while True:
                # Accept the next client connection.
                connection, address = server.accept()

                with connection:
                    print(f"Connected by {address}")

                    # Read one newline-terminated request.
                    with connection.makefile("rwb") as stream:
                        request = stream.readline()

                        if not request:
                            continue

                        print(f"Received: {request.decode('utf-8').rstrip()}")

                        # Send a placeholder response.
                        response = (
                            b'{"status":"OK",'
                            b'"message":"Placeholder response"}\n'
                        )
                        stream.write(response)
                        stream.flush()
        except KeyboardInterrupt:
            print("\nAuthentication service shutting down.")

if __name__ == "__main__":
    main()

# 2) Authentication and ticket handling

# 3) Heartbeat thread

# 4) Randomized crash injection