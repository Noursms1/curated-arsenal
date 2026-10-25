#!/usr/bin/env python3
"""
أداة فحص فتح المنفذ TCP لمجموعة عناوين IPv4.
تستقبل CIDR ورقم المنفذ وتطبع قائمة العناوين المفتوحة بصيغة JSON.
"""

import sys
import json
import socket
import ipaddress


def scan_host(host, port, timeout=1):
    """تحاول الاتصال بالمضيف على المنفذ المحدد وتعيد True إذا كان مفتوحًا."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((str(host), port))
            return True
        except (socket.timeout, socket.error):
            return False


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: {} <cidr> <port>\n".format(sys.argv[0]))
        sys.exit(1)
    network = ipaddress.ip_network(sys.argv[1], strict=False)
    try:
        port = int(sys.argv[2])
    except ValueError:
        sys.stderr.write("Port must be an integer\n")
        sys.exit(1)

    open_hosts = []
    closed_hosts = []
    for ip in network.hosts():
        if scan_host(ip, port):
            open_hosts.append(str(ip))
        else:
            closed_hosts.append(str(ip))

    result = {"open": open_hosts, "closed": closed_hosts}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
