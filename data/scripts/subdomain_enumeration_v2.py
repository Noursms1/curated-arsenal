# CATEGORY: Recon
# PREMORTEM:
# failure_mode: API rate limiting or change in crt.sh response format leads to empty certificate findings
# failure_mode: DNS resolver timeouts or network partitions cause brute‑force enumeration to miss subdomains
# failure_mode: Zone‑transfer attempts hang indefinitely if the target does not respond promptly
# early_warning: consecutive network exception count > 3 triggers warning and graceful abort

import argparse
import json
import sys
import time
import socket
from collections import defaultdict

import requests
import dns.resolver
import dns.zone
import dns.query

TOOL_NAME = "SubEnum"
VERSION = "1.0.0"
REQUEST_TIMEOUT = 10  # seconds
SLEEP_BETWEEN_REQUESTS = 0.5
MAX_CONSECUTIVE_ERRORS = 3

# Small built‑in wordlist for brute‑force enumeration
BRUTE_WORDLIST = [
    "www", "mail", "ftp", "ns", "api", "dev", "test", "admin", "portal",
    "blog", "shop", "staging", "cdn", "static", "login", "vpn"
]

def safe_request(method, url, **kwargs):
    """Wrapper around requests with timeout, error handling and sleep."""
    try:
        response = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        response.raise_for_status()
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        return response
    except Exception as e:
        raise RuntimeError(f"Request to {url} failed: {e}")

def brute_force_subdomains(domain):
    found = set()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = REQUEST_TIMEOUT
    consecutive_errors = 0

    for sub in BRUTE_WORDLIST:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            found.add(fqdn.rstrip('.'))
            consecutive_errors = 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # No such subdomain – not an error
            consecutive_errors = 0
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                # Early warning: too many consecutive errors
                raise RuntimeError(f"Brute‑force stopped after {consecutive_errors} consecutive errors: {e}")
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    return found

def crtsh_subdomains(domain):
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = safe_request("GET", url, headers={"User-Agent": "SubEnum/1.0"})
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            # crt.sh may return wildcard entries or multiple names separated by newlines
            for name in name_value.splitlines():
                name = name.strip()
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(domain):
                    found.add(name.rstrip('.'))
    except Exception as e:
        raise RuntimeError(f"crt.sh enumeration failed: {e}")
    return found

def zone_transfer_subdomains(domain):
    found = set()
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_name = ns.to_text()
            try:
                # Resolve NS host to IP
                ns_ip = dns.resolver.resolve(ns_name, "A")[0].to_text()
                # Attempt AXFR
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=REQUEST_TIMEOUT))
                if zone:
                    for name, node in zone.nodes.items():
                        sub = f"{name}.{domain}"
                        found.add(sub.rstrip('.'))
                time.sleep(SLEEP_BETWEEN_REQUESTS)
            except Exception:
                # Most zones will refuse AXFR; ignore per‑server failures
                continue
    except Exception as e:
        raise RuntimeError(f"Zone‑transfer enumeration failed: {e}")
    return found

def run_self_test():
    test_domain = "example.com"
    results = {}
    try:
        results["brute"] = list(brute_force_subdomains(test_domain))
    except Exception as e:
        results["brute_error"] = str(e)
    try:
        results["crtsh"] = list(crtsh_subdomains(test_domain))
    except Exception as e:
        results["crtsh_error"] = str(e)
    try:
        results["zonetransfer"] = list(zone_transfer_subdomains(test_domain))
    except Exception as e:
        results["zonetransfer_error"] = str(e)

    # Simple sanity checks
    if not results.get("crtsh"):
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": test_domain,
            "status": "failure",
            "findings": [],
            "results": results
        }, indent=2))
        sys.exit(1)

    print(json.dumps({
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_domain,
        "status": "success",
        "findings": [],
        "results": results
    }, indent=2))
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()

    if not args.target:
        print("Target domain is required.", file=sys.stderr)
        sys.exit(1)

    target = args.target.strip().lower()
    overall_findings = set()
    capability_results = defaultdict(list)
    overall_status = "success"

    # Brute‑force
    try:
        brute = brute_force_subdomains(target)
        overall_findings.update(brute)
        capability_results["brute_force"] = sorted(brute)
    except Exception as e:
        overall_status = "partial_failure"
        capability_results["brute_force_error"] = str(e)

    # crt.sh
    try:
        crt = crtsh_subdomains(target)
        overall_findings.update(crt)
        capability_results["crtsh"] = sorted(crt)
    except Exception as e:
        overall_status = "partial_failure"
        capability_results["crtsh_error"] = str(e)

    # Zone transfer
    try:
        zt = zone_transfer_subdomains(target)
        overall_findings.update(zt)
        capability_results["zone_transfer"] = sorted(zt)
    except Exception as e:
        overall_status = "partial_failure"
        capability_results["zone_transfer_error"] = str(e)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": overall_status,
        "findings": sorted(overall_findings),
        "results": capability_results
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()