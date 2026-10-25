'''IPv6 HTTP scanner.

Scans an IPv6 network for hosts that respond to an HTTP GET request.
'''
import sys
import json
import ipaddress
import requests

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "IPv6 network CIDR required"}))
        sys.exit(1)
    try:
        net = ipaddress.IPv6Network(sys.argv[1], strict=False)
    except ValueError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    responsive = []
    for ip in net.hosts():
        url = f"http://[{ip}]"
        try:
            r = requests.get(url, timeout=10, verify=False)
            if r.status_code < 400:
                responsive.append(str(ip))
        except requests.RequestException:
            continue

    print(json.dumps({"responsive": responsive}, ensure_ascii=False))

if __name__ == "__main__":
    main()