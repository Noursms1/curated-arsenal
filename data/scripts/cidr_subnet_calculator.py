'''"""CIDR Subnet Calculator
Calculates network details for a given CIDR.
"""
import sys, json, ipaddress

def main():
    if len(sys.argv) > 1:
        cidr = sys.argv[1]
    else:
        cidr = sys.stdin.read().strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        first = str(hosts[0]) if hosts else str(net.network_address)
        last = str(hosts[-1]) if hosts else str(net.broadcast_address)
        total = net.num_addresses
        # For IPv4 subtract network and broadcast addresses if more than 2 addresses
        if net.version == 4 and total > 2:
            usable = total - 2
        else:
            usable = total
        result = {
            "cidr": cidr,
            "network": str(net.network_address),
            "netmask": str(net.netmask),
            "broadcast": str(net.broadcast_address),
            "first_host": first,
            "last_host": last,
            "total_hosts": usable
        }
    except Exception as e:
        result = {"error": str(e)}
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
'''