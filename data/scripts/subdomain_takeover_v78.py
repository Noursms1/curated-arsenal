# CATEGORY: Cloud - Subdomain Takeover Detection Tool
import argparse
import json
import socket
import sys
import time
from urllib.parse import urlparse

import requests

TOOL_NAME = "SubTakeoverDetect"
VERSION = "1.0.0"

# Simple wordlist for subdomain enumeration
WORDLIST = [
    "www",
    "mail",
    "dev",
    "test",
    "api",
    "admin",
    "beta",
    "staging",
    "shop",
    "blog",
]

# Known takeover fingerprint strings per provider
FINGERPRINTS = {
    "github.io": "There isn’t a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "azurewebsites.net": "404 - Not Found",
    "cloudfront.net": "The specified bucket does not exist",
    "digitaloceanspaces.com": "NoSuchBucket",
    "netlify.app": "The page you are looking for doesn’t exist",
}


def resolve_dns(subdomain):
    """Resolve DNS for a subdomain and return (aliases, ips)."""
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(subdomain)
        time.sleep(0.5)
        return aliaslist, ipaddrlist
    except Exception:
        time.sleep(0.5)
        return [], []


def fetch_http(subdomain):
    """Perform HTTP GET request and return response text and status code."""
    url = f"https://{subdomain}"
    try:
        resp = requests.get(url, timeout=5)
        time.sleep(0.5)
        return resp.text, resp.status_code
    except requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        try:
            url = f"http://{subdomain}"
            resp = requests.get(url, timeout=5)
            time.sleep(0.5)
            return resp.text, resp.status_code
        except Exception:
            time.sleep(0.5)
            return "", None
    except Exception:
        time.sleep(0.5)
        return "", None


def fingerprint_response(content):
    """Check response content against known fingerprints."""
    findings = []
    for provider, marker in FINGERPRINTS.items():
        if marker.lower() in content.lower():
            findings.append(provider)
    return findings


def enumerate_subdomains(domain):
    """Generate full subdomains from the wordlist."""
    return [f"{prefix}.{domain}" for prefix in WORDLIST]


def analyze_subdomain(subdomain):
    """Run DNS and HTTP checks on a subdomain and return findings."""
    result = {
        "subdomain": subdomain,
        "dns_aliases": [],
        "dns_ips": [],
        "http_status": None,
        "fingerprints": [],
    }

    aliases, ips = resolve_dns(subdomain)
    result["dns_aliases"] = aliases
    result["dns_ips"] = ips

    content, status = fetch_http(subdomain)
    result["http_status"] = status

    if content:
        result["fingerprints"] = fingerprint_response(content)

    return result


def run_detection(target):
    findings = []
    results = {}

    subdomains = enumerate_subdomains(target)
    for sub in subdomains:
        data = analyze_subdomain(sub)
        results[sub] = data
        if data["fingerprints"]:
            findings.append(
                {
                    "subdomain": sub,
                    "potential_takeover": True,
                    "providers": data["fingerprints"],
                }
            )
        else:
            findings.append(
                {
                    "subdomain": sub,
                    "potential_takeover": False,
                    "providers": [],
                }
            )
    return findings, results


def self_test():
    """Perform basic sanity checks."""
    test_results = {}
    status = "success"
    try:
        # DNS test
        aliases, ips = resolve_dns("example.com")
        test_results["dns"] = {"aliases": aliases, "ips": ips}
        # HTTP test
        content, code = fetch_http("example.com")
        test_results["http"] = {"status_code": code, "has_content": bool(content)}
        # Fingerprint test (should be empty)
        fp = fingerprint_response(content or "")
        test_results["fingerprint"] = fp
    except Exception as e:
        status = "error"
        test_results["error"] = str(e)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": status,
        "findings": [],
        "results": test_results,
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Subdomain takeover detection tool")
    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")
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
                "results": {"error": "No target domain provided"},
            },
            indent=2,
        ))
        sys.exit(1)

    try:
        findings, results = run_detection(args.target)
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target,
            "status": "completed",
            "findings": findings,
            "results": results,
        }
    except Exception as exc:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "findings": [],
            "results": {"error": str(exc)},
        }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()