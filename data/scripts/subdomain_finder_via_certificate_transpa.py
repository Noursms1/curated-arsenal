#!/usr/bin/env python3
"""
CATEGORY: Recon
TECHNIQUES: Certificate Transparency (crt.sh), AlienVault OTX, URLScan.io, Live HTTP probing, Technology fingerprinting
CHAIN_CONTRIBUTIONS: Aggregates subdomains from multiple sources, validates their existence, and identifies underlying web technologies.
"""

import argparse
import json
import sys
import time
import socket
from urllib.parse import urlparse

import requests

TOOL_NAME = "SubDomainCT"
VERSION = "1.0"
REQUEST_TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def rate_limited_get(url, params=None, headers=None):
    """Perform a GET request respecting rate limiting and timeout."""
    try:
        time.sleep(RATE_LIMIT)
        response = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        return None


def fetch_crtsh(domain):
    """Fetch subdomains from crt.sh for a given domain."""
    url = "https://crt.sh/"
    params = {"q": f"%25.{domain}", "output": "json"}
    resp = rate_limited_get(url, params=params)
    subdomains = set()
    if resp and resp.content:
        try:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value")
                if name:
                    for sub in name.splitlines():
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub.endswith(domain):
                            subdomains.add(sub.lower())
        except (ValueError, KeyError):
            pass
    return list(subdomains)


def fetch_otx(domain, otx_key):
    """Fetch subdomains from AlienVault OTX."""
    if not otx_key:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": otx_key}
    resp = rate_limited_get(url, headers=headers)
    subdomains = set()
    if resp and resp.content:
        try:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname and hostname.endswith(domain):
                    subdomains.add(hostname.lower())
        except (ValueError, KeyError):
            pass
    return list(subdomains)


def fetch_urlscan(domain, urlscan_key):
    """Fetch subdomains discovered by URLScan.io for a given domain."""
    if not urlscan_key:
        return []
    search_url = "https://urlscan.io/api/v1/search/"
    query = f"domain:{domain}"
    params = {"q": query, "size": 100}
    headers = {"API-Key": urlscan_key}
    resp = rate_limited_get(search_url, params=params, headers=headers)
    subdomains = set()
    if resp and resp.content:
        try:
            data = resp.json()
            for result in data.get("results", []):
                page_url = result.get("page", {}).get("url")
                if page_url:
                    parsed = urlparse(page_url)
                    hostname = parsed.hostname
                    if hostname and hostname.endswith(domain):
                        subdomains.add(hostname.lower())
        except (ValueError, KeyError):
            pass
    return list(subdomains)


def live_check(subdomains):
    """Check if subdomains resolve and are reachable via HTTP/HTTPS."""
    live = {}
    for sub in subdomains:
        entry = {"resolved": False, "http": False, "https": False, "technologies": []}
        # DNS resolution
        try:
            socket.gethostbyname(sub)
            entry["resolved"] = True
        except socket.gaierror:
            live[sub] = entry
            continue

        # HTTP probe
        for scheme in ("http", "https"):
            url = f"{scheme}://{sub}"
            try:
                resp = rate_limited_get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp:
                    entry[scheme] = True
                    # Simple tech detection
                    tech = []
                    server = resp.headers.get("Server")
                    if server:
                        tech.append(server.strip())
                    x_powered = resp.headers.get("X-Powered-By")
                    if x_powered:
                        tech.append(x_powered.strip())
                    entry["technologies"] = list(set(entry["technologies"] + tech))
            except Exception:
                continue
        live[sub] = entry
    return live


def aggregate(domain, otx_key=None, urlscan_key=None):
    """Run full enumeration pipeline."""
    findings = {
        "crtsh": [],
        "otx": [],
        "urlscan": [],
        "live": {}
    }

    # 1. Gather subdomains
    crtsh_subs = fetch_crtsh(domain)
    findings["crtsh"] = crtsh_subs

    otx_subs = fetch_otx(domain, otx_key) if otx_key else []
    findings["otx"] = otx_subs

    urlscan_subs = fetch_urlscan(domain, urlscan_key) if urlscan_key else []
    findings["urlscan"] = urlscan_subs

    # 2. Merge unique subdomains
    all_subs = set(crtsh_subs + otx_subs + urlscan_subs)

    # 3. Live check + tech detection
    live_results = live_check(all_subs)
    findings["live"] = live_results

    # 4. Compile technology list
    tech_set = set()
    for sub, data in live_results.items():
        tech_set.update(data.get("technologies", []))

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": domain,
        "status": "complete",
        "technologies": sorted(tech_set),
        "findings": {
            "crtsh": crtsh_subs,
            "otx": otx_subs,
            "urlscan": urlscan_subs,
            "live": live_results
        },
        "results": {
            "total_subdomains": len(all_subs),
            "live_subdomains": sum(1 for v in live_results.values() if v["resolved"])
        }
    }


def run_self_test():
    """Simple self‑test using a well‑known domain."""
    test_domain = "example.com"
    result = aggregate(test_domain)
    # Expect at least one subdomain (example.com itself may appear)
    if not result["findings"]["crtsh"] and not result["findings"]["otx"] and not result["findings"]["urlscan"]:
        print(json.dumps({"tool": TOOL_NAME, "version": VERSION, "target": test_domain,
                          "status": "self-test-failed", "message": "No subdomains found"}))
        sys.exit(1)
    print(json.dumps(result, indent=2))
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration via CRT.SH, OTX, URLScan.io with live validation and tech detection.")
    parser.add_argument("domain", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("--otx-key", help="AlienVault OTX API key")
    parser.add_argument("--urlscan-key", help="URLScan.io API key")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()

    if not args.domain:
        parser.error("the following arguments are required: domain")

    result = aggregate(args.domain, otx_key=args.otx_key, urlscan_key=args.urlscan_key)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()