# CATEGORY: Recon
import argparse
import json
import socket
import sys
import time
from collections import defaultdict

import dns.resolver
import dns.zone
import dns.query
import requests

TOOL_NAME = "SubEnum"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5
DEFAULT_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "ns",
    "dev",
    "test",
    "api",
    "admin",
    "portal",
    "beta",
    "static",
    "cdn",
    "blog",
    "shop",
    "login",
]


def sleep():
    time.sleep(SLEEP_INTERVAL)


def dns_query(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []


def brute_force(target, wordlist):
    found = set()
    for prefix in wordlist:
        sub = f"{prefix}.{target}"
        ips = dns_query(sub)
        if ips:
            found.add(sub)
        sleep()
    return list(found)


def crt_sh_lookup(target):
    found = set()
    url = "https://crt.sh/?q=%25.{0}&output=json".format(target)
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name = entry.get("name_value")
            if name:
                # crt.sh may return wildcard entries like *.example.com
                for line in name.splitlines():
                    if "*" not in line:
                        found.add(line.strip())
        sleep()
    except Exception:
        pass
    return list(found)


def dns_zone_transfer(target):
    found = set()
    try:
        ns_records = dns.resolver.resolve(target, "NS")
        for ns in ns_records:
            ns_name = ns.to_text()
            try:
                axfr = dns.query.xfr(ns_name, target, timeout=10)
                zone = dns.zone.from_xfr(axfr)
                if zone:
                    for name, node in zone.nodes.items():
                        sub = f"{name}.{target}"
                        found.add(sub.rstrip('.'))
                sleep()
            except Exception:
                continue
    except Exception:
        pass
    return list(found)


def enumerate_subdomains(target, wordlist):
    results = defaultdict(list)
    findings = set()

    # Capability 1: DNS brute force
    bf = brute_force(target, wordlist)
    results["brute_force"] = bf
    findings.update(bf)

    # Capability 2: Certificate Transparency via crt.sh
    ct = crt_sh_lookup(target)
    results["crt_sh"] = ct
    findings.update(ct)

    # Capability 3: DNS zone transfer attempt
    zt = dns_zone_transfer(target)
    results["zone_transfer"] = zt
    findings.update(zt)

    return list(findings), dict(results)


def self_test():
    test_target = "example.com"
    findings, results = enumerate_subdomains(test_target, DEFAULT_WORDLIST)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_target,
        "status": "completed",
        "findings": findings,
        "results": results,
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument("target", nargs="?", help="Domain to enumerate")
    parser.add_argument(
        "--wordlist",
        help="Path to a custom wordlist (one prefix per line)",
        default=None,
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps(
            {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": None,
                "status": "error",
                "findings": [],
                "results": {},
                "error": "No target domain provided",
            },
            indent=2,
        ))
        sys.exit(1)

    if args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(json.dumps(
                {
                    "tool": TOOL_NAME,
                    "version": VERSION,
                    "target": args.target,
                    "status": "error",
                    "findings": [],
                    "results": {},
                    "error": f"Failed to read wordlist: {e}",
                },
                indent=2,
            ))
            sys.exit(1)
    else:
        wordlist = DEFAULT_WORDLIST

    try:
        findings, results = enumerate_subdomains(args.target, wordlist)
        status = "completed"
    except Exception as e:
        findings, results = [], {}
        status = f"error: {e}"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()