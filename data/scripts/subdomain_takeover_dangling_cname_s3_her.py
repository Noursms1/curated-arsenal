#!/usr/bin/env python3
"""
CATEGORY: Recon / Subdomain Takeover Detection
TECHNIQUES: DNS enumeration, CNAME analysis, HTTP fingerprinting
CHAIN_CONTRIBUTIONS: Integrates DNS resolution (dnspython), HTTP probing (requests), and JSON reporting.
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import requests

# Global constants
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds
MAX_WORKERS = 10

# Known service fingerprint signatures for unclaimed resources
UNCLAIMED_SIGNATURES = {
    "s3.amazonaws.com": "NoSuchBucket",
    "amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "No such app",
    "github.io": "There isn’t a GitHub Pages site here.",
    "azurewebsites.net": "The resource you are looking for has been removed",
    "cloudfront.net": "The specified bucket does not exist",
}


def rate_limited():
    """Enforce a simple rate limit between external calls."""
    time.sleep(RATE_LIMIT)


def resolve_cname(domain):
    """Resolve CNAME for a given domain. Returns the target or None."""
    try:
        rate_limited()
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=TIMEOUT)
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None
    except Exception:
        return None


def http_probe(url):
    """Fetch URL and return response text (truncated) and status code."""
    try:
        rate_limited()
        resp = requests.get(url, timeout=TIMEOUT, verify=True, headers={"User-Agent": "Mozilla/5.0"})
        text = resp.text[:500]  # limit size for fingerprinting
        return resp.status_code, text
    except requests.RequestException:
        return None, None


def is_unclaimed(service, status_code, body):
    """Determine if the response matches an unclaimed service signature."""
    if status_code is None or body is None:
        return False
    signature = UNCLAIMED_SIGNATURES.get(service.lower())
    if signature and signature.lower() in body.lower():
        return True
    # Generic 404/401 patterns
    generic = ["not found", "no such", "does not exist", "error 404"]
    return any(g in body.lower() for g in generic)


def detect_takeover(domain):
    """
    Detect potential subdomain takeover for a single domain.
    Returns dict with detection details.
    """
    result = {
        "domain": domain,
        "cname": None,
        "service": None,
        "status_code": None,
        "unclaimed": False,
        "evidence": None,
    }

    cname = resolve_cname(domain)
    if not cname:
        return result
    result["cname"] = cname

    # Identify known service by suffix matching
    service = None
    for suffix in UNCLAIMED_SIGNATURES.keys():
        if cname.lower().endswith(suffix):
            service = suffix
            break
    if not service:
        return result
    result["service"] = service

    # Build probing URL
    probe_url = f"http://{domain}"
    status, body = http_probe(probe_url)
    result["status_code"] = status
    result["evidence"] = body[:200] if body else None

    if is_unclaimed(service, status, body):
        result["unclaimed"] = True

    return result


def enumerate_subdomains(base_domain, wordlist=None):
    """
    Simple subdomain enumeration using a provided wordlist.
    Returns a set of candidate subdomains.
    """
    if wordlist is None:
        # Minimal built‑in wordlist
        wordlist = ["www", "mail", "dev", "test", "api", "staging", "beta", "admin"]
    candidates = set()
    for prefix in wordlist:
        sub = f"{prefix}.{base_domain}"
        try:
            # Quick A record check to filter non‑existent names
            rate_limited()
            dns.resolver.resolve(sub, "A", lifetime=TIMEOUT)
            candidates.add(sub)
        except Exception:
            continue
    return candidates


def run_scan(target, wordlist=None):
    """
    Orchestrates full scan:
    1. Enumerate subdomains.
    2. Resolve CNAMEs.
    3. Detect dangling CNAME takeovers.
    Returns standardized JSON dict.
    """
    findings = []
    subdomains = enumerate_subdomains(target, wordlist)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_sub = {executor.submit(detect_takeover, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                res = future.result()
                if res["unclaimed"]:
                    findings.append(res)
            except Exception:
                continue

    output = {
        "tool": "TakeoverDetect",
        "version": "1.0.0",
        "target": target,
        "status": "completed",
        "technologies": list(set(f["service"] for f in findings if f["service"])),
        "findings": len(findings),
        "results": findings,
    }
    return output


def self_test():
    """Basic self‑test using a known safe domain (example.com)."""
    test_target = "example.com"
    print(json.dumps(run_scan(test_target), indent=2))


def main():
    parser = argparse.ArgumentParser(description="Detect dangling CNAME subdomain takeover vulnerabilities.")
    parser.add_argument("target", nargs="?", help="Base domain to scan (e.g., example.com)")
    parser.add_argument("--wordlist", help="Path to custom subdomain wordlist")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print("Error: target domain required.", file=sys.stderr)
        sys.exit(1)

    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Failed to read wordlist: {e}", file=sys.stderr)
            sys.exit(1)

    result = run_scan(args.target, wordlist)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()