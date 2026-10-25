#!/usr/bin/env python3
"""
CATEGORY: Recon
TECHNIQUES: DNS resolution, ASN lookup via public API, IP grouping, reverse DNS
CHAIN_CONTRIBUTIONS: Domain → IPs → ASN/Org mapping → Infrastructure summary
"""

import argparse
import json
import sys
import time
import logging
import socket
from collections import defaultdict

import requests
import dns.resolver
import ipaddress

# Configuration
REQUEST_TIMEOUT = 10  # seconds
RATE_DELAY = 0.5      # seconds between external requests
USER_AGENT = "asn-mapper/1.0 (+https://github.com/yourorg/asn-mapper)"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("asn_mapper")

def rate_limited_request(method, url, **kwargs):
    """Perform HTTP request respecting rate limit."""
    try:
        response = requests.request(method, url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, **kwargs)
        time.sleep(RATE_DELAY)
        response.raise_for_status()
        return response
    except Exception as e:
        logger.error(f"Request to {url} failed: {e}")
        return None

def resolve_domain(domain):
    """Resolve A records for a domain, return set of IPv4 strings."""
    ips = set()
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=REQUEST_TIMEOUT)
        for rdata in answers:
            ips.add(rdata.to_text())
        time.sleep(RATE_DELAY)
    except Exception as e:
        logger.error(f"DNS resolution failed for {domain}: {e}")
    return ips

def reverse_dns(ip):
    """Perform reverse DNS lookup, return hostname or None."""
    try:
        result = socket.gethostbyaddr(ip)
        time.sleep(RATE_DELAY)
        return result[0]
    except Exception:
        return None

def get_asn_info(ip):
    """
    Query iptoasn API for ASN information.
    Returns dict with keys: asn, org, network (CIDR), ip.
    """
    url = f"https://api.iptoasn.com/v1/as/ip/{ip}"
    resp = rate_limited_request("GET", url)
    if not resp:
        return None
    try:
        data = resp.json()
        if data.get("as_number") is None:
            return None
        return {
            "ip": ip,
            "asn": data.get("as_number"),
            "org": data.get("as_description"),
            "network": data.get("as_prefix")
        }
    except Exception as e:
        logger.error(f"Parsing ASN info failed for {ip}: {e}")
        return None

def group_by_asn(asn_records):
    """Group ASN records by ASN number."""
    groups = defaultdict(list)
    for rec in asn_records:
        if rec:
            groups[rec["asn"]].append(rec)
    return groups

def build_output(domain, asn_groups):
    """Construct standardized JSON output."""
    findings = []
    results = {}
    for asn, records in asn_groups.items():
        org_names = {r["org"] for r in records if r["org"]}
        networks = {r["network"] for r in records if r["network"]}
        ips = {r["ip"] for r in records}
        findings.append({
            "asn": asn,
            "organizations": list(org_names),
            "networks": list(networks),
            "ip_count": len(ips)
        })
        results[asn] = {
            "organization": list(org_names),
            "networks": list(networks),
            "ips": list(ips)
        }
    output = {
        "tool": "asn_mapper",
        "version": "1.0",
        "target": domain,
        "status": "success" if findings else "error",
        "technologies": ["dns", "asn_api", "reverse_dns"],
        "findings": findings,
        "results": results
    }
    return output

def process_domain(domain):
    """Full pipeline: resolve → ASN lookup → grouping → output."""
    ips = resolve_domain(domain)
    if not ips:
        return {
            "tool": "asn_mapper",
            "version": "1.0",
            "target": domain,
            "status": "error",
            "technologies": ["dns"],
            "findings": [],
            "results": {}
        }
    asn_records = []
    for ip in ips:
        rec = get_asn_info(ip)
        if rec:
            rec["reverse_dns"] = reverse_dns(ip)
        asn_records.append(rec)
    groups = group_by_asn(asn_records)
    return build_output(domain, groups)

def self_test():
    """Run a basic self‑test on example.com."""
    test_domain = "example.com"
    logger.info("Running self‑test...")
    output = process_domain(test_domain)
    required_keys = {"tool", "version", "target", "status", "technologies", "findings", "results"}
    missing = required_keys - output.keys()
    if missing:
        logger.error(f"Self‑test failed: missing keys {missing}")
        sys.exit(1)
    if output["target"] != test_domain:
        logger.error("Self‑test failed: target mismatch")
        sys.exit(1)
    if output["status"] not in {"success", "error"}:
        logger.error("Self‑test failed: invalid status")
        sys.exit(1)
    logger.info("Self‑test passed.")
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="ASN/IP range mapper for a given domain.")
    parser.add_argument("domain", nargs="?", help="Target domain to map.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.domain:
        parser.error("Domain argument is required unless --self-test is used.")
    output = process_domain(args.domain)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()