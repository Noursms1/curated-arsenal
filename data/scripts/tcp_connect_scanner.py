#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP Connect Scanner - Scans open TCP ports on a target.

Usage:
    python tcp_connect_scanner.py example.com --ports 80,443
    python tcp_connect_scanner.py example.com --ports 1-1000
    python tcp_connect_scanner.py 1.1.1.1 --ports 22,80,443,8080
"""
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def parse_ports(spec):
    """Parse '80', '1-1000', '80,443' into sorted list of ints."""
    spec = str(spec).strip().replace(" ", "")
    if not spec:
        raise ValueError("Ports spec is empty")
    ports = set()
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start_i = int(start_str)
                end_i = int(end_str)
            except ValueError:
                raise ValueError("Invalid range: " + part)
            if not (1 <= start_i <= 65535):
                raise ValueError("Port out of range (1-65535): " + part)
            if not (1 <= end_i <= 65535):
                raise ValueError("Port out of range (1-65535): " + part)
            if start_i > end_i:
                raise ValueError("Start port > end port: " + part)
            for p in range(start_i, end_i + 1):
                ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError("Invalid port '" + part + "'. Use a number (80) or range (1-1000).")
            if not (1 <= p <= 65535):
                raise ValueError("Port out of range (1-65535): " + part)
            ports.add(p)
    if not ports:
        raise ValueError("No valid ports in: " + spec)
    return sorted(ports)


def scan_port(target_ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            return {
                "port": port,
                "service": COMMON_SERVICES.get(port, "unknown"),
                "state": "open",
            }
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(
        description="TCP Connect Port Scanner",
        epilog="Example: python tcp_connect_scanner.py example.com --ports 80,443",
    )
    parser.add_argument("target", help="Target host or IP")
    parser.add_argument("--ports", required=True,
                        help="Ports spec: 80 | 1-1000 | 22,80,443")
    parser.add_argument("--timeout", type=float, default=1.5,
                        help="Connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=100,
                        help="Number of concurrent threads")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(json.dumps({"error": str(e), "target": args.target}, ensure_ascii=False))
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(json.dumps({"error": "DNS failed for " + args.target}, ensure_ascii=False))
        sys.exit(1)

    print("[*] Scanning " + args.target + " (" + target_ip + ") - " + str(len(ports)) + " ports", file=sys.stderr)

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(scan_port, target_ip, p, args.timeout) for p in ports]
        for f in as_completed(futures):
            r = f.result()
            if r:
                open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])

    result = {
        "target": args.target,
        "ip": target_ip,
        "scanned_ports": len(ports),
        "open_count": len(open_ports),
        "open_ports": open_ports,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()