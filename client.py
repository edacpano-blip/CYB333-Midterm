#!/usr/bin/env python3
"""
client.py - Simple TCP (Transmission Control Protocol) client.

CYB333 Midterm, Part 1: Socket Connection Implementation.

Connects to server.py, sends messages typed by the user, and prints the
server's responses. Type "quit" to disconnect cleanly.

Usage:
    python client.py                    # connects to 127.0.0.1:65432
    python client.py --host 127.0.0.1 --port 5000
"""

import argparse
import socket
import sys
from datetime import datetime

BUFFER_SIZE = 1024
ENCODING = "utf-8"
QUIT_COMMAND = "quit"
CONNECT_TIMEOUT = 5  # Seconds to wait before giving up on the server


def log(message: str) -> None:
    """Print a timestamped log line."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] [CLIENT] {message}", flush=True)


def run_client(host: str, port: int) -> None:
    """Connect to the server and run the send/receive loop."""
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except ConnectionRefusedError:
        # Most common case: server.py is not running
        log(f"ERROR: Connection refused by {host}:{port}. Is the server running?")
        sys.exit(1)
    except socket.timeout:
        log(f"ERROR: Connection to {host}:{port} timed out after {CONNECT_TIMEOUT}s.")
        sys.exit(1)
    except socket.gaierror:
        log(f"ERROR: Could not resolve host '{host}'.")
        sys.exit(1)
    except OSError as err:
        log(f"ERROR: Could not connect to {host}:{port} ({err})")
        sys.exit(1)

    # 'with sock' guarantees the socket is closed however we exit
    with sock:
        log(f"Connected to server at {host}:{port}")
        log(f"Type a message and press Enter. Type '{QUIT_COMMAND}' to disconnect.")

        while True:
            try:
                message = input("> ").strip()
            except (KeyboardInterrupt, EOFError):
                # Treat Ctrl+C / Ctrl+D as a polite quit
                print()
                message = QUIT_COMMAND

            if not message:
                continue  # Ignore empty input

            try:
                sock.sendall(message.encode(ENCODING))
                reply = sock.recv(BUFFER_SIZE)
            except (ConnectionResetError, BrokenPipeError):
                log("ERROR: Lost connection to the server.")
                break
            except socket.timeout:
                log("ERROR: Server did not respond in time.")
                break

            if not reply:
                log("Server closed the connection.")
                break

            log(f"Server says: {reply.decode(ENCODING, errors='replace')}")

            if message.lower() == QUIT_COMMAND:
                break

    log("Disconnected. Socket closed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP client")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=65432,
                        help="Server port (default: 65432)")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    run_client(arguments.host, arguments.port)
