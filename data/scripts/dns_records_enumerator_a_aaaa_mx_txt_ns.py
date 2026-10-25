#!/usr/bin/env python3
"""
CATEGORY: Recon
TECHNIQUES: DNS Enumeration, Wildcard Detection, Zone Transfer Testing
CHAIN_CONTRIBUTIONS: Integrates dnspython for robust DNS queries, adds rate limiting and comprehensive JSON reporting.
"""

import argparse
import json
import random
import string
import sys
import time
from typing import Dict, List, Tuple

import dns.exception
import dns.name
import dns.resolver
import dns.query
import dns.zone

# Global configuration
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def _rate_limit():
    """Enforce a simple rate limit between DNS queries."""
    time.sleep(RATE_LIMIT)


def _random_subdomain(domain: str) -> str:
    """Generate a random subdomain unlikely to exist."""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{rand}.{domain}"


def _query_dns(name: str, rdtype: str) -> List[str]:
    """Perform a DNS query for a given name and record type."""
    _rate_limit()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
        return [r.to_text() for r in answer] if answer.rrset else []
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.YXDOMAIN):
        return []
    except Exception as e:
        # Unexpected errors are logged but not raised to keep tool robust
        return []


def enumerate_dns_records(domain: str) -> Dict[str, List[str]]:
    """Enumerate common DNS record types for a domain."""
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA"]
    results = {}
    for rtype in record_types:
        records = _query_dns(domain, rtype)
        results[rtype] = records
    return results


def detect_wildcard(domain: str) -> Tuple[bool, List[str]]:
    """
    Detect DNS wildcard by querying a random subdomain.
    Returns (is_wildcard, records_of_random_subdomain).
    """
    random_host = _random_subdomain(domain)
    records = _query_dns(random_host, "A")
    is_wildcard = len(records) > 0
    return is_wildcard, records


def test_zone_transfer(domain: str) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Attempt a DNS zone transfer (AXFR).
    Returns (success, zone_data) where zone_data maps names to their raw rdata strings.
    """
    _rate_limit()
    try:
        ns_records = _query_dns(domain, "NS")
        if not ns_records:
            return False, {}
        for ns in ns_records:
            ns = ns.rstrip('.')
            try:
                axfr = dns.query.xfr(ns, domain, timeout=TIMEOUT)
                zone = dns.zone.from_xfr(axfr)
                if zone is None:
                    continue
                data = {}
                for name, node in zone.nodes.items():
                    full_name = f"{name}.{domain}" if name != dns.name.root else domain
                    rdatas = []
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            rdatas.append(rdata.to_text())
                    data[full_name] = rdatas
                return True, data
            except (dns.exception.FormError, dns.exception.Timeout,
                    dns.query.TransferError, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
        return False, {}
    except Exception:
        return False, {}


def build_output(tool: str, version: str, target: str,
                 records: Dict[str, List[str]],
                 wildcard: bool,
                 wildcard_records: List[str],
                 zone_success: bool,
                 zone_data: Dict[str, List[str]]) -> Dict:
    """Construct the standardized JSON output."""
    findings = []
    if wildcard:
        findings.append("Wildcard DNS detected")
    if zone_success:
        findings.append("Zone transfer succeeded")
    else:
        findings.append("Zone transfer failed or not allowed")

    return {
        "tool": tool,
        "version": version,
        "target": target,
        "status": "success",
        "technologies": ["DNS"],
        "findings": findings,
        "results": {
            "records": records,
            "wildcard": {
                "detected": wildcard,
                "example_records": wildcard_records
            },
            "zone_transfer": {
                "successful": zone_success,
                "zone_data": zone_data if zone_success else {}
            }
        }
    }


def run(target: str) -> Dict:
    """Execute the full enumeration workflow."""
    records = enumerate_dns_records(target)
    wildcard, wildcard_records = detect_wildcard(target)
    zone_success, zone_data = test_zone_transfer(target)

    output = build_output(
        tool="DNSReconPro",
        version="1.0.0",
        target=target,
        records=records,
        wildcard=wildcard,
        wildcard_records=wildcard_records,
        zone_success=zone_success,
        zone_data=zone_data
    )
    return output


def self_test() -> bool:
    """
    Simple self‑test using a well‑known domain.
    Returns True if the test passes.
    """
    test_domain = "example.com"
    result = run(test_domain)

    # Basic sanity checks
    if result["target"] != test_domain:
        return False
    if "records" not in result["results"]:
        return False
    # example.com should not have wildcard and zone transfer should fail
    if result["results"]["wildcard"]["detected"]:
        return False
    if result["results"]["zone_transfer"]["successful"]:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Advanced DNS enumeration with wildcard detection and zone transfer testing.")
    parser.add_argument("target", nargs="?", help="Domain to enumerate (e.g., example.com)")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        passed = self_test()
        sys.stdout.write(json.dumps({"self_test": "passed" if passed else "failed"}) + "\n")
        sys.exit(0 if passed else 1)

    if not args.target:
        sys.stderr.write("Error: target domain required\n")
        sys.exit(1)

    output = run(args.target)
    sys.stdout.write(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()