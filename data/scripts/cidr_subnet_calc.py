#!/usr/bin/env python3
"""CIDR Subnet Calculator.

Accepts a CIDR notation via command line argument or stdin and prints JSON
with network address, broadcast address, total hosts, usable hosts, and the
first/last usable IPs.
"""

import sys
import json
import ipaddress

def main():
    # Get input
    if len(sys.argv) > 1:
        cidr = sys.argv[1].strip()
    else:
        cidr = sys.stdin.read().strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        result = {'error': str(e)}
        json.dump(result, sys.stdout, ensure_ascii=False)
        sys.exit(1)

    total_hosts = net.num_addresses
    # For IPv4, usable hosts exclude network and broadcast if more than 2 addresses
    if net.version == 4 and total_hosts > 2:
        usable = total_hosts - 2
        first_usable = str(list(net.hosts())[0])
        last_usable = str(list(net.hosts())[-1])
    else:
        usable = total_hosts
        first_usable = None
        last_usable = None

    result = {
        'cidr': cidr,
        'network_address': str(net.network_address),
        'broadcast_address': str(net.broadcast_address) if net.version == 4 else None,
        'total_hosts': total_hosts,
        'usable_hosts': usable,
        'first_usable_ip': first_usable,
        'last_usable_ip': last_usable
    }
    json.dump(result, sys.stdout, ensure_ascii=False)

if __name__ == '__main__':
    main()
