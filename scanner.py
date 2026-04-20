#!/usr/bin/env python3
"""
TCP connect port scanner. Same idea as nmap -sT — attempt a full handshake
on each port and report what answers back.

Usage: python scanner.py <target> -p 1-1024 -t 100
Author: sameerdpatel16
"""

import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_target(host: str) -> str:
    # accepts either a hostname or raw IP
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {host}")
        sys.exit(1)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    result = {"port": port, "open": False, "banner": None}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 on success, errno otherwise
        if sock.connect_ex((ip, port)) == 0:
            result["open"] = True

            # try to grab whatever the service sends on connect (SSH version, FTP banner, etc.)
            try:
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner or None
            except Exception:
                pass

        sock.close()

    except socket.error:
        pass

    return result


def scan_range(ip: str, start_port: int, end_port: int, timeout: float, threads: int) -> list:
    open_ports = []
    total = end_port - start_port + 1

    print(f"\n[*] Scanning {ip} — ports {start_port} to {end_port}")
    print(f"[*] Threads: {threads}  |  Timeout: {timeout}s\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        completed = 0
        for future in as_completed(futures):
            result = future.result()
            completed += 1

            if completed % 100 == 0 or completed == total:
                print(f"    Progress: {completed}/{total}", end="\r")

            if result["open"]:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# small lookup so output shows "SSH" instead of "unknown" for port 22
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

def get_service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


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
            port    = p["port"]
            service = get_service_name(port)
            banner  = p["banner"] or ""
            if len(banner) > 40:
                banner = banner[:37] + "..."
            print(f"  {port:<10} {service:<15} {banner}")

    print(f"\n  {len(open_ports)} open port(s) found in {duration:.2f}s")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Basic TCP Connect Port Scanner",
        epilog="Example: python scanner.py 192.168.1.1 -p 1-1000 -t 100"
    )
    parser.add_argument("target",          help="Target IP or hostname")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-t", "--threads", default=100, type=int, help="Thread count (default: 100)")
    parser.add_argument("--timeout",       default=1.0, type=float, help="Per-port timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    try:
        parts = args.ports.split("-")
        start_port = int(parts[0])
        end_port   = int(parts[1]) if len(parts) > 1 else start_port
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError
    except (ValueError, IndexError):
        print("[!] Invalid port range. Use format: 1-1024")
        sys.exit(1)

    ip         = resolve_target(args.target)
    start_time = datetime.now()

    print(f"[*] Target  : {args.target} ({ip})")
    print(f"[*] Ports   : {start_port} - {end_port}")
    print(f"[*] Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    open_ports = scan_range(ip, start_port, end_port, args.timeout, args.threads)
    print_results(args.target, ip, open_ports, start_time)


if __name__ == "__main__":
    main()
