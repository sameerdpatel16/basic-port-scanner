#!/usr/bin/env python3
"""
Basic Port Scanner
==================
A TCP Connect scanner — the same technique nmap uses with the -sT flag.

How it works:
  For each port in the range, we attempt a full TCP 3-way handshake:
    1. SYN  →  (we knock)
    2. ← SYN-ACK  (port is open and responds)
    3. ACK  →  (connection established)
  If the handshake completes, the port is OPEN.
  If we get a RST or a timeout, the port is CLOSED or FILTERED.

Author: sameerdpatel16
"""

import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# STEP 1: Resolve the target
# ---------------------------------------------------------------------------
# Before we can scan, we need the target's IP address.
# socket.gethostbyname() converts a hostname (e.g. "google.com") to an IP.
# If the user already gave an IP, it just returns it unchanged.

def resolve_target(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# STEP 2: Scan a single port
# ---------------------------------------------------------------------------
# This is the core of the scanner. For each port we:
#   - Create a TCP socket  (AF_INET = IPv4, SOCK_STREAM = TCP)
#   - Set a timeout so we don't wait forever on filtered ports
#   - Try to connect — if it succeeds, the port is open
#   - Optionally grab the banner (the service's greeting message)

def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    result = {"port": port, "open": False, "banner": None}

    try:
        # Create a fresh TCP socket for this port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex() returns 0 on success (port open), non-zero on failure
        # This is safer than connect() which raises an exception on failure
        connection_result = sock.connect_ex((ip, port))

        if connection_result == 0:
            result["open"] = True

            # Banner grabbing: some services send a greeting when you connect.
            # e.g. SSH sends "SSH-2.0-OpenSSH_8.9", FTP sends "220 FTP ready"
            # We try to read it — if nothing comes, that's fine too.
            try:
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner if banner else None
            except Exception:
                pass  # No banner, not a problem

        sock.close()

    except socket.error:
        pass  # Connection completely failed — port is closed/filtered

    return result


# ---------------------------------------------------------------------------
# STEP 3: Scan a range of ports with threading
# ---------------------------------------------------------------------------
# Scanning ports one-by-one is slow — each connection waits up to `timeout`
# seconds. Threading lets us knock on many doors simultaneously.
#
# ThreadPoolExecutor manages a pool of worker threads. We submit one scan
# job per port and collect results as they finish.

def scan_range(ip: str, start_port: int, end_port: int, timeout: float, threads: int) -> list:
    open_ports = []
    total = end_port - start_port + 1

    print(f"\n[*] Scanning {ip} — ports {start_port} to {end_port}")
    print(f"[*] Threads: {threads}  |  Timeout: {timeout}s per port\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scan jobs at once
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        completed = 0
        for future in as_completed(futures):
            result = future.result()
            completed += 1

            # Progress indicator every 100 ports
            if completed % 100 == 0 or completed == total:
                print(f"    Progress: {completed}/{total} ports scanned", end="\r")

            if result["open"]:
                open_ports.append(result)

    # Sort results by port number for clean output
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ---------------------------------------------------------------------------
# STEP 4: Common port names
# ---------------------------------------------------------------------------
# nmap has a huge database of port→service mappings. We keep a small one
# for the most common ports so our output is human-readable.

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

def get_service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


# ---------------------------------------------------------------------------
# STEP 5: Print results
# ---------------------------------------------------------------------------

def print_results(target: str, ip: str, open_ports: list, start_time: datetime):
    duration = (datetime.now() - start_time).total_seconds()

    print(f"\n\n{'='*55}")
    print(f"  Scan Results for: {target} ({ip})")
    print(f"{'='*55}")

    if not open_ports:
        print("  No open ports found.")
    else:
        print(f"  {'PORT':<10} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'-'*50}")
        for p in open_ports:
            port     = p["port"]
            service  = get_service_name(port)
            banner   = p["banner"] or ""
            # Truncate long banners
            if len(banner) > 40:
                banner = banner[:37] + "..."
            print(f"  {port:<10} {service:<15} {banner}")

    print(f"\n  {len(open_ports)} open port(s) found in {duration:.2f}s")
    print(f"{'='*55}\n")


# ---------------------------------------------------------------------------
# STEP 6: CLI interface
# ---------------------------------------------------------------------------
# argparse handles command-line arguments so users can run the scanner like:
#   python scanner.py 192.168.100.x -p 1-1000 -t 100

def main():
    parser = argparse.ArgumentParser(
        description="Basic TCP Connect Port Scanner",
        epilog="Example: python scanner.py 192.168.1.1 -p 1-1000 -t 100"
    )
    parser.add_argument("target",              help="Target IP address or hostname")
    parser.add_argument("-p", "--ports",       default="1-1024",   help="Port range, e.g. 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads",     default=100, type=int, help="Number of threads (default: 100)")
    parser.add_argument("--timeout",           default=1.0, type=float, help="Timeout per port in seconds (default: 1.0)")

    args = parser.parse_args()

    # Parse port range
    try:
        parts = args.ports.split("-")
        start_port = int(parts[0])
        end_port   = int(parts[1]) if len(parts) > 1 else start_port
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
    except (ValueError, IndexError):
        print("[!] Invalid port range. Use format: 1-1024")
        sys.exit(1)

    # Resolve and scan
    ip         = resolve_target(args.target)
    start_time = datetime.now()

    print(f"[*] Target   : {args.target} ({ip})")
    print(f"[*] Ports    : {start_port} - {end_port}")
    print(f"[*] Started  : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    open_ports = scan_range(ip, start_port, end_port, args.timeout, args.threads)
    print_results(args.target, ip, open_ports, start_time)


if __name__ == "__main__":
    main()
