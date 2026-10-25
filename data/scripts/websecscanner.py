"""
CATEGORY: Web Security Scanner
A production-ready Python tool that performs:
1. CORS misconfiguration detection
2. HTTP methods enumeration
3. Security headers verification
It outputs a single JSON object with the scan results.
"""

import argparse
import json
import sys
import time
from urllib.parse import urlparse

import requests

TOOL_NAME = "WebSecScanner"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
SLEEP_INTERVAL = 0.5

EXPECTED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def normalize_url(target: str) -> str:
    """Ensure the target has a scheme and no trailing slash."""
    parsed = urlparse(target)
    if not parsed.scheme:
        target = "https://" + target
    target = target.rstrip("/")
    return target


def fetch_url(url: str, method: str = "GET"):
    """Perform an HTTP request with error handling and a pause."""
    try:
        time.sleep(SLEEP_INTERVAL)
        if method.upper() == "OPTIONS":
            response = requests.options(url, timeout=DEFAULT_TIMEOUT)
        else:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        return response
    except requests.RequestException as e:
        return e


def scan_cors(url: str) -> dict:
    """Detect common CORS misconfigurations."""
    result = {
        "allowed_origin": None,
        "allow_credentials": None,
        "issues": [],
    }
    resp = fetch_url(url, "GET")
    if isinstance(resp, Exception):
        result["issues"].append(f"Request error: {str(resp)}")
        return result

    origin = resp.headers.get("Access-Control-Allow-Origin")
    credentials = resp.headers.get("Access-Control-Allow-Credentials")
    result["allowed_origin"] = origin
    result["allow_credentials"] = credentials

    if origin == "*":
        result["issues"].append("Wildcard Access-Control-Allow-Origin (*)")
    elif origin and "example.com" not in origin:
        # Heuristic: allow any subdomain without restriction
        result["issues"].append(f"Broad Access-Control-Allow-Origin: {origin}")

    if credentials == "true" and origin == "*":
        result["issues"].append(
            "Access-Control-Allow-Credentials is true while origin is wildcard"
        )
    return result


def enumerate_methods(url: str) -> dict:
    """Return the list of HTTP methods the server reports as allowed."""
    result = {"allowed_methods": [], "issues": []}
    resp = fetch_url(url, "OPTIONS")
    if isinstance(resp, Exception):
        result["issues"].append(f"OPTIONS request error: {str(resp)}")
        return result

    allow = resp.headers.get("Allow")
    if allow:
        methods = [m.strip().upper() for m in allow.split(",")]
        result["allowed_methods"] = methods
        # Flag unsafe methods
        unsafe = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
        found_unsafe = unsafe.intersection(methods)
        if found_unsafe:
            result["issues"].append(
                f"Server permits unsafe methods: {', '.join(sorted(found_unsafe))}"
            )
    else:
        result["issues"].append("No Allow header in OPTIONS response")
    return result


def check_security_headers(url: str) -> dict:
    """Verify presence of common security‑related HTTP response headers."""
    result = {"missing_headers": [], "present_headers": {}, "issues": []}
    resp = fetch_url(url, "GET")
    if isinstance(resp, Exception):
        result["issues"].append(f"Request error: {str(resp)}")
        return result

    for header in EXPECTED_HEADERS:
        value = resp.headers.get(header)
        if value:
            result["present_headers"][header] = value
        else:
            result["missing_headers"].append(header)

    if result["missing_headers"]:
        result["issues"].append(
            f"Missing security headers: {', '.join(result['missing_headers'])}"
        )
    return result


def fingerprint_technologies(resp) -> list:
    """Simple technology fingerprint based on common server headers."""
    tech = []
    server = resp.headers.get("Server")
    if server:
        tech.append(server)
    x_powered = resp.headers.get("X-Powered-By")
    if x_powered:
        tech.append(x_powered)
    return tech


def run_scan(target: str) -> dict:
    """Execute all scanning modules against the target."""
    url = normalize_url(target)
    scan_output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": url,
        "status": "completed",
        "technologies": [],
        "findings": {},
        "results": {},
    }

    # Initial request for technology fingerprinting
    base_resp = fetch_url(url, "GET")
    if isinstance(base_resp, Exception):
        scan_output["status"] = "error"
        scan_output["results"]["error"] = str(base_resp)
        return scan_output

    scan_output["technologies"] = fingerprint_technologies(base_resp)

    # CORS
    cors_res = scan_cors(url)
    scan_output["findings"]["cors"] = cors_res

    # HTTP methods
    methods_res = enumerate_methods(url)
    scan_output["findings"]["http_methods"] = methods_res

    # Security headers
    headers_res = check_security_headers(url)
    scan_output["findings"]["security_headers"] = headers_res

    # Aggregate simple result summary
    issues = []
    for category, data in scan_output["findings"].items():
        issues.extend(data.get("issues", []))
    scan_output["results"]["total_issues"] = len(issues)
    scan_output["results"]["issues"] = issues

    return scan_output


def self_test():
    """Run a quick self‑test against httpbin.org."""
    test_target = "https://httpbin.org"
    print(json.dumps(run_scan(test_target), indent=2))


def parse_args():
    parser = argparse.ArgumentParser(
        description="CORS, HTTP methods and security‑header scanner."
    )
    parser.add_argument(
        "target", nargs="?", help="Target URL or hostname (e.g., example.com)"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Execute built‑in self‑test and exit",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps(
            {
                "tool": TOOL_NAME,
                "version": VERSION,
                "status": "error",
                "error": "No target supplied",
            },
            indent=2,
        ))
        sys.exit(1)

    result = run_scan(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()