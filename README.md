# Basic Port Scanner

A TCP Connect port scanner written in Python demonstrating how tools like nmap work at a fundamental level.

## How It Works

Every computer has 65,535 ports. A port scanner probes each one to find which services are listening.

This scanner uses a **TCP Connect Scan** — the same technique as `nmap -sT`:

1. **SYN** → scanner knocks on the port
2. **SYN-ACK** ← port is open and responds
3. **ACK** → connection established → **port is OPEN**
4. If we get **RST** or a timeout → **port is CLOSED / FILTERED**

Threading is used to scan many ports simultaneously instead of waiting for each one sequentially.

## Usage

```bash
# Scan default ports 1-1024
python scanner.py <target>

# Scan a custom port range
python scanner.py 192.168.1.1 -p 1-65535

# Faster scan with more threads
python scanner.py 192.168.1.1 -p 1-1000 -t 200

# Adjust timeout (useful for slow networks)
python scanner.py 192.168.1.1 -p 1-1024 --timeout 2.0
```

## Example Output

```
[*] Target   : 192.168.100.5 (192.168.100.5)
[*] Ports    : 1 - 1024
[*] Started  : 2025-11-01 14:22:01

[*] Scanning 192.168.100.5 — ports 1 to 1024
[*] Threads: 100  |  Timeout: 1.0s per port

=======================================================
  Scan Results for: 192.168.100.5 (192.168.100.5)
=======================================================
  PORT       SERVICE         BANNER
  --------------------------------------------------
  22         SSH             SSH-2.0-OpenSSH_8.9p1
  80         HTTP
  3306       MySQL

  3 open port(s) found in 4.31s
=======================================================
```

## Key Concepts

| Concept | Description |
|---|---|
| TCP Socket | A connection endpoint — `AF_INET` (IPv4) + `SOCK_STREAM` (TCP) |
| connect_ex() | Returns 0 if connection succeeded (port open), non-zero if failed |
| Banner grabbing | Reading the service's greeting message to identify what's running |
| Threading | Scanning ports in parallel instead of one-by-one |
| Timeout | How long to wait before deciding a port is filtered |

## Compared to nmap

| Feature | This Scanner | nmap -sT | nmap -sS |
|---|---|---|---|
| Method | Full TCP Connect | Full TCP Connect | Half-open SYN |
| Root needed | No | No | Yes |
| Speed | Medium | Medium | Fast |
| Detectable | Yes | Yes | Harder |
| Banner grabbing | Yes | Optional | No |

## Legal Notice

Only scan systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.
