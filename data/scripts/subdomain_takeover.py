# CATEGORY: Cloud - Subdomain Takeover Detection Tool
import argparse
import json
import sys
import time
import re
from urllib.parse import urlparse

import dns.resolver
import requests

TOOL_NAME = "SubTakeoverScanner"
VERSION = "1.0.0"

# Known vulnerable CNAME patterns and their service identifiers
VULN_CNAME_PATTERNS = {
    r".*\.s3-website\..*\.amazonaws\.com\.?": "AWS S3 Website",
    r".*\.cloudfront\.net\.?": "AWS CloudFront",
    r".*\.azurewebsites\.net\.?": "Azure Web Apps",
    r".*\.github\.io\.?": "GitHub Pages",
    r".*\.herokuapp\.com\.?": "Heroku",
    r".*\.netlify\.app\.?": "Netlify",
    r".*\.pages\.dev\.?": "Google Firebase Hosting",
}

# Fingerprint strings that indicate a placeholder page for takeover
VULN_HTTP_FINGERPRINTS = {
    "There isn’t a GitHub Pages site": "GitHub Pages",
    "NoSuchBucket": "AWS S3",
    "Sorry, this shop is currently unavailable": "Shopify",
    "404 Not Found": "Generic",
    "The site you are looking for could not be found": "Azure",
    "Oops! That page can’t be found.": "WordPress.com",
    "Sorry, this page could not be found": "GitLab Pages",
    "This site can’t be reached": "Heroku",
    "We could not find the page you’re looking for": "Netlify",
}

def resolve_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cnames = [rdata.target.to_text().rstrip('.') for rdata in answers]
        time.sleep(0.5)
        return cnames
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return []

def http_check(url):
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(0.5)
        return resp.status_code, resp.text[:2000]  # limit body size for fingerprinting
    except requests.RequestException:
        return None, ""

def match_cname_patterns(cnames):
    findings = []
    for cname in cnames:
        for pattern, service in VULN_CNAME_PATTERNS.items():
            if re.fullmatch(pattern, cname, re.IGNORECASE):
                findings.append({"cname": cname, "service": service})
    return findings

def fingerprint_body(body):
    findings = []
    for fingerprint, service in VULN_HTTP_FINGERPRINTS.items():
        if fingerprint.lower() in body.lower():
            findings.append({"fingerprint": fingerprint, "service": service})
    return findings

def scan_subdomain(subdomain):
    results = {"subdomain": subdomain, "cname_findings": [], "http_findings": []}
    cnames = resolve_cname(subdomain)
    if cnames:
        results["cname_findings"] = match_cname_patterns(cnames)

    # Build URL (try HTTPS first, fallback to HTTP)
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        status, body = http_check(url)
        if status:
            http_findings = fingerprint_body(body)
            if http_findings:
                results["http_findings"] = http_findings
            results["http_status"] = status
            break
    else:
        results["http_status"] = None

    return results

def aggregate_findings(scans):
    agg = {"potential_takeover": []}
    for scan in scans:
        if scan["cname_findings"] or scan["http_findings"]:
            agg["potential_takeover"].append(scan)
    return agg

def run_self_test():
    test_subdomains = ["example.com", "nonexistent.invalid"]
    scans = []
    for sub in test_subdomains:
        scans.append(scan_subdomain(sub))
    agg = aggregate_findings(scans)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "completed",
        "findings": agg,
        "results": scans
    }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover detection tool")
    parser.add_argument("--target", help="Target domain to enumerate subdomains for", required=False)
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if not args.target:
        parser.error("the following arguments are required: --target (unless --self-test is used)")

    # Simple subdomain enumeration placeholder (could be replaced with a proper wordlist)
    subdomains = [f"www.{args.target}", f"api.{args.target}", f"dev.{args.target}"]
    scans = []
    for sub in subdomains:
        scans.append(scan_subdomain(sub))

    findings = aggregate_findings(scans)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": "completed",
        "findings": findings,
        "results": scans
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()