# CATEGORY: Recon - Subdomain Enumeration Tool
import argparse
import json
import sys
import time
import socket
from urllib.parse import quote_plus

import requests
import dns.resolver
import dns.query
import dns.exception

TOOL_NAME = "PySubEnum"
VERSION = "1.0.0"

# Small built‑in wordlist for brute‑force
BRUTE_WORDLIST = [
    "www", "mail", "ftp", "ns1", "ns2", "dev", "test",
    "api", "admin", "portal", "shop", "blog", "staging"
]

def resolve_subdomain(name):
    try:
        answers = dns.resolver.resolve(name, "A")
        return True
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False
    except Exception:
        return False

def brute_force_subdomains(domain):
    found = set()
    for prefix in BRUTE_WORDLIST:
        sub = f"{prefix}.{domain}"
        if resolve_subdomain(sub):
            found.add(sub)
        time.sleep(0.5)
    return sorted(found)

def crtsh_subdomains(domain):
    found = set()
    url = f"https://crt.sh/?q=%25.{quote_plus(domain)}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.splitlines():
                name = name.strip()
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name.lower())
        time.sleep(0.5)
    except Exception:
        pass
    return sorted(found)

def zone_transfer_subdomains(domain):
    found = set()
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_servers = [r.to_text() for r in ns_answers]
    except Exception:
        ns_servers = []
    for ns in ns_servers:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.query.xfr(ns_ip, domain, timeout=10)
            if zone:
                for name, node in zone.nodes.items():
                    sub = f"{name.to_text()}.{domain}".replace("..", ".")
                    found.add(sub.rstrip('.'))
            time.sleep(0.5)
        except Exception:
            continue
    return sorted(found)

def run_enumeration(target):
    results = {}
    findings = set()

    # Capability 1: Brute‑force
    bf = brute_force_subdomains(target)
    results["brute_force"] = bf
    findings.update(bf)

    # Capability 2: Certificate Transparency (crt.sh)
    ct = crtsh_subdomains(target)
    results["crtsh"] = ct
    findings.update(ct)

    # Capability 3: DNS Zone Transfer
    zt = zone_transfer_subdomains(target)
    results["zone_transfer"] = zt
    findings.update(zt)

    return sorted(findings), results

def self_test():
    test_target = "example.com"
    findings, results = run_enumeration(test_target)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_target,
        "status": "self-test completed",
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument("target", nargs="?", help="Domain to enumerate")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test")
    args = parser.parse_args()

    if args.self_test:
        self_test()

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error: no target provided",
            "findings": [],
            "results": {}
        }, indent=2))
        sys.exit(1)

    target = args.target.strip().lower()
    try:
        findings, results = run_enumeration(target)
        status = "completed"
    except Exception as e:
        findings = []
        results = {}
        status = f"error: {str(e)}"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()