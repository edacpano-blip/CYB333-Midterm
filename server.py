#!/usr/bin/env python3
"""
server.py - Simple TCP (Transmission Control Protocol) echo server.

CYB333 Midterm, Part 1: Socket Connection Implementation.

The server binds to a host and port, waits for a client, receives messages,
and sends back an acknowledgement for each one. The client can end the
session by sending "quit". Press Ctrl+C on the server to shut it down.

Usage:
    python server.py                    # listens on 127.0.0.1:65432
    python server.py --host 127.0.0.1 --port 5000
"""

import argparse
import socket
import sys
from datetime import datetime

BUFFER_SIZE = 1024        # Max bytes read per recv() call
ENCODING = "utf-8"        # Text encoding used for all messages
QUIT_COMMAND = "quit"     # Message the client sends to disconnect


def log(message: str) -> None:
    """Print a timestamped log line (timestamps help verify screenshots)."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] [SERVER] {message}", flush=True)


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Receive messages from one connected client and reply to each one."""
    log(f"Connection established with {addr[0]}:{addr[1]}")

    # 'with conn' guarantees the client socket is closed when we leave
    with conn:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
            except ConnectionResetError:
                log("Client reset the connection unexpectedly.")
                break

            # recv() returns b"" when the client closes its side
            if not data:
                log("Client closed the connection.")
                break

            message = data.decode(ENCODING, errors="replace").strip()
            log(f"Received from client: {message!r}")

            if message.lower() == QUIT_COMMAND:
                conn.sendall("Goodbye! Closing connection.".encode(ENCODING))
                log("Client requested disconnect. Session closed cleanly.")
                break

            # Build and send the response back to the client
            response = f"Server received your message: {message}"
            conn.sendall(response.encode(ENCODING))
            log(f"Sent response: {response!r}")

    log(f"Disconnected from {addr[0]}:{addr[1]}")


def run_server(host: str, port: int) -> None:
    """Create the listening socket and accept clients one at a time."""
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        # Lets us restart the server right away without "Address already in use"
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((host, port))
        except OSError as err:
            log(f"ERROR: Could not bind to {host}:{port} ({err})")
            sys.exit(1)

        server_sock.listen(1)  # Backlog of 1 pending connection

        # On Windows, a blocking accept() ignores Ctrl+C until a client connects.
        # A 1-second timeout lets the loop wake up regularly so Ctrl+C is noticed.
        server_sock.settimeout(1.0)
        log(f"Listening for connections on {host}:{port} (Ctrl+C to stop)")

        try:
            while True:
                try:
                    conn, addr = server_sock.accept()  # Waits up to 1s for a client
                except socket.timeout:
                    continue  # No client yet; loop again (and check for Ctrl+C)
                conn.settimeout(None)  # Client socket goes back to normal blocking mode
                handle_client(conn, addr)
                log("Waiting for the next connection...")
        except KeyboardInterrupt:
            log("Shutdown requested (Ctrl+C). Closing server socket.")

    log("Server stopped.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP echo server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Address to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=65432,
                        help="Port to listen on (default: 65432)")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    run_server(arguments.host, arguments.port)
