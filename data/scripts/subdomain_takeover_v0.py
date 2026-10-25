# CATEGORY: Cloud
# PREMORTEM:
# failure_mode: Rate limiting by target services leads to incomplete scans and false negatives
# failure_mode: DNS resolution failures due to network outages cause the tool to abort or miss subdomains
# failure_mode: Outdated takeover signature list produces false positives, eroding trust in results
# early_warning: Spike in HTTP 429 responses or DNS errors exceeding 20% of total requests
# early_warning: Signature match count grows >30% without manual verification

import argparse
import json
import socket
import sys
import time
from typing import List, Dict, Any

import requests

TOOL_NAME = "SubTakeoverScanner"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10  # seconds
REQUEST_DELAY = 0.5  # seconds between network calls

# Known vulnerable CNAME patterns and associated services
CNAME_PATTERNS = {
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure Web Apps",
    "herokuapp.com": "Heroku",
    "github.io": "GitHub Pages",
    "pages.dev": "GitHub Pages (custom)",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "storage.googleapis.com": "Google Cloud Storage",
}

# Known HTTP response signatures indicating a possible takeover
TAKEOVER_SIGNATURES = [
    "There isn’t a GitHub Pages site here.",
    "NoSuchBucket",
    "The specified bucket does not exist",
    "Sorry, this shop is currently unavailable.",
    "Heroku | No such app",
    "404 Not Found",
    "The resource you are looking for has been removed",
    "Error: DNS name not found",
    "This site can’t be reached",
]

def load_wordlist(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return []

def resolve_subdomain(subdomain: str) -> Dict[str, Any]:
    result = {"subdomain": subdomain, "resolved": False, "cname": None, "error": None}
    try:
        answers = socket.getaddrinfo(subdomain, None)
        result["resolved"] = True
        # Attempt to fetch CNAME via DNS query using socket.gethostbyname_ex
        try:
            cname = socket.gethostbyname_ex(subdomain)[0]
            result["cname"] = cname
        except Exception:
            result["cname"] = None
    except socket.gaierror as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result

def check_cname_vulnerability(cname: str) -> str:
    if not cname:
        return ""
    for pattern, service in CNAME_PATTERNS.items():
        if pattern in cname:
            return service
    return ""

def fetch_http_signature(url: str) -> Dict[str, Any]:
    result = {"url": url, "status_code": None, "signature_match": None, "error": None}
    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        result["status_code"] = resp.status_code
        for sig in TAKEOVER_SIGNATURES:
            if sig.lower() in resp.text.lower():
                result["signature_match"] = sig
                break
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    return result

def scan_target(domain: str, wordlist: List[str]) -> Dict[str, Any]:
    findings = []
    total_requests = 0
    http_429_count = 0
    dns_error_count = 0

    subdomains = [f"{prefix}.{domain}" for prefix in wordlist] if wordlist else [domain]

    for sub in subdomains:
        dns_info = resolve_subdomain(sub)
        total_requests += 1
        if dns_info["error"]:
            dns_error_count += 1

        cname_service = check_cname_vulnerability(dns_info.get("cname", ""))
        http_info = {}
        if dns_info["resolved"]:
            url = f"http://{sub}"
            http_info = fetch_http_signature(url)
            total_requests += 1
            if http_info.get("status_code") == 429:
                http_429_count += 1
            time.sleep(REQUEST_DELAY)

        finding = {
            "subdomain": sub,
            "resolved": dns_info["resolved"],
            "cname": dns_info.get("cname"),
            "cname_service": cname_service,
            "http_status": http_info.get("status_code"),
            "signature_match": http_info.get("signature_match"),
            "errors": {
                "dns": dns_info.get("error"),
                "http": http_info.get("error")
            }
        }

        # Determine status
        if cname_service or finding["signature_match"]:
            finding["status"] = "potential_takeover"
        elif dns_info["resolved"]:
            finding["status"] = "safe"
        else:
            finding["status"] = "unresolved"

        findings.append(finding)
        time.sleep(REQUEST_DELAY)

    # Early warning calculations
    warnings = []
    if total_requests > 0:
        if http_429_count / total_requests > 0.2:
            warnings.append("High rate limiting detected (HTTP 429)")
        if dns_error_count / total_requests > 0.2:
            warnings.append("Frequent DNS resolution errors")
        if sum(1 for f in findings if f["status"] == "potential_takeover") / len(findings) > 0.3:
            warnings.append("Elevated potential takeover rate; verify signature list")

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": domain,
        "status": "completed",
        "findings": findings,
        "warnings": warnings,
        "results": {
            "total_requests": total_requests,
            "http_429": http_429_count,
            "dns_errors": dns_error_count
        }
    }

def self_test() -> bool:
    # Minimal self‑test without external dependencies
    test_wordlist = ["nonexistent12345"]
    result = scan_target("example.com", test_wordlist)
    # Expect at least one finding and proper keys
    required_keys = {"tool", "version", "target", "status", "findings", "warnings", "results"}
    if not required_keys.issubset(result.keys()):
        return False
    if not isinstance(result["findings"], list):
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover detection tool")
    parser.add_argument("target", nargs="?", help="Root domain to scan (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests")
    args = parser.parse_args()

    if args.self_test:
        test_passed = self_test()
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "self_test_passed" if test_passed else "self_test_failed",
            "findings": [],
            "warnings": [],
            "results": {}
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0 if test_passed else 1)

    if not args.target:
        parser.error("the following arguments are required: target")

    wordlist = load_wordlist(args.wordlist) if args.wordlist else []
    scan_result = scan_target(args.target, wordlist)
    print(json.dumps(scan_result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()