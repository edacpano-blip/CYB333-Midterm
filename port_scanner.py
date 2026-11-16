#!/usr/bin/env python3
"""
port_scanner.py - Simple TCP connect port scanner.

CYB333 Midterm, Part 2: Port Scanner Implementation.

Scans a list or range of TCP ports on an AUTHORIZED target and reports
which ports are open. Only localhost and scanme.nmap.org are allowed,
per the assignment's scanning rules.

Usage examples:
    python port_scanner.py 127.0.0.1 -p 21,22,80,443
    python port_scanner.py localhost -p 1-1024
    python port_scanner.py scanme.nmap.org -p 22,80,443,9929
    python port_scanner.py 127.0.0.1 -p 1-100 --timeout 0.3 --delay 0.05
"""

import argparse
import socket
import sys
import time
import csv
from datetime import datetime

# Targets we have permission to scan (assignment rules)
AUTHORIZED_TARGETS = {"localhost", "127.0.0.1", "scanme.nmap.org"}

MIN_PORT, MAX_PORT = 1, 65535
MAX_PORTS_REMOTE = 100  # Keep scans of scanme.nmap.org small and polite


def log(message: str) -> None:
    """Print a timestamped line so screenshots show when the scan ran."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def parse_ports(port_spec: str) -> list:
    """
    Turn a port spec like '22,80,443' or '1-1024' or '20-25,80' into a
    sorted list of unique ints. Raises ValueError on bad input.
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.replace("-", "").isdigit():
            raise ValueError(f"'{part}' is not a number or a range like 1-1024")
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)  # ValueError if not numeric
            if start > end:
                raise ValueError(f"Range start is greater than end in '{part}'")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("No ports were given.")

    bad = [p for p in ports if not MIN_PORT <= p <= MAX_PORT]
    if bad:
        raise ValueError(f"Port(s) out of range {MIN_PORT}-{MAX_PORT}: {sorted(bad)[:5]}")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address. Exits if it can't be resolved."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        log(f"ERROR: Host '{target}' could not be resolved (unreachable or does not exist).")
        sys.exit(1)


def check_authorized(target: str, ip: str) -> None:
    """Refuse to scan anything outside the authorized list."""
    allowed_ips = {"127.0.0.1"}
    try:
        allowed_ips.add(socket.gethostbyname("scanme.nmap.org"))
    except socket.gaierror:
        pass  # If DNS fails we simply can't add it

    if target.lower() not in AUTHORIZED_TARGETS and ip not in allowed_ips:
        log(f"ERROR: '{target}' ({ip}) is not an authorized target.")
        log("Only localhost/127.0.0.1 and scanme.nmap.org may be scanned.")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float) -> str:
    """
    Try a full TCP connect to one port.
    Returns 'open', 'closed' (actively refused), or 'filtered' (no answer).

    Windows note: on the loopback address Windows retries a refused connection
    for about 2 seconds before reporting it, so a closed local port can look
    like a timeout. Nothing filters traffic on loopback, so for 127.0.0.1 any
    port that does not answer is reported as closed.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))  # 0 means the handshake worked
        except (socket.timeout, OSError):
            return "closed" if ip.startswith("127.") else "filtered"

    if result == 0:
        return "open"
    if ip.startswith("127."):
        return "closed"  # Loopback has no firewall in between (see note above)
    # ECONNREFUSED (111 Linux, 61 macOS, 10061 Windows) means a closed port
    if result in (111, 61, 10061):
        return "closed"
    return "filtered"


def service_name(port: int) -> str:
    """Look up the well-known service name for a port, if there is one."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def run_scan(target: str, ports: list, timeout: float, delay: float, show_closed: bool, output: str | None = None) -> None:
    ip = resolve_target(target)
    check_authorized(target, ip)

    is_remote = ip != "127.0.0.1"
    if is_remote and len(ports) > MAX_PORTS_REMOTE:
        log(f"ERROR: Remote scans are limited to {MAX_PORTS_REMOTE} ports to stay polite.")
        sys.exit(1)

    log(f"Starting scan of {target} ({ip}) | {len(ports)} port(s) | "
        f"timeout={timeout}s delay={delay}s")
    print("-" * 52)
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE'}")
    print("-" * 52)

    counts = {"open": 0, "closed": 0, "filtered": 0}
    results = []

    start = time.perf_counter()
    try:
        for port in ports:
            state = scan_port(ip, port, timeout)
            counts[state] += 1
            results.append([port, state, service_name(port)])
            if state == "open" or show_closed:
                print(f"{str(port) + '/tcp':<10}{state:<12}{service_name(port)}")
            time.sleep(delay)  # Rate limiting between attempts
    except KeyboardInterrupt:
        print()
        log("Scan interrupted by user.")

    elapsed = time.perf_counter() - start
    print("-" * 52)
    log(f"Scan complete in {elapsed:.2f}s | open={counts['open']} "
        f"closed={counts['closed']} filtered={counts['filtered']}")
    if output is not None:
        try:
            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["port", "state", "service"])
                writer.writerows(results)
            log(f"Scan results saved to {output}")
        except OSError as err:
            log(f"ERROR: Could not save CSV file: {err}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple TCP connect port scanner (authorized targets only)")
    parser.add_argument("target", help="localhost, 127.0.0.1, or scanme.nmap.org")
    parser.add_argument("-p", "--ports", default="21,22,23,25,53,80,110,143,443,3389",
                        help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: common ports)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Seconds to wait per port (default: 0.5)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Seconds to pause between ports (default: 0.1)")
    parser.add_argument("--open-only", action="store_true",
                        help="Only print open ports")
    parser.add_argument("--output", type=str, default=None,
                        help="Save scan results to a CSV file")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")
    if args.delay < 0:
        parser.error("Delay cannot be negative.")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    try:
        port_list = parse_ports(arguments.ports)
    except ValueError as err:
        log(f"ERROR: Invalid port specification '{arguments.ports}': {err}")
        sys.exit(1)

    run_scan(arguments.target, port_list, arguments.timeout,
         arguments.delay, show_closed=not arguments.open_only,
         output=arguments.output)
