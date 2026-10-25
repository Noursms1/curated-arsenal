#!/usr/bin/env python3
"""
CATEGORY: Web Security
TECHNIQUES: CSRF Token Detection, Token Validation, SameSite Attribute Analysis, JSON Endpoint CSRF Assessment
CHAIN_CONTRIBUTIONS: Integrates HTML parsing, HTTP header inspection, and request crafting to provide multi‑vector CSRF evaluation.
"""

import argparse
import json
import sys
import time
import threading
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Global configuration
REQUEST_TIMEOUT = 10  # seconds
RATE_LIMIT_DELAY = 0.5  # seconds between requests
USER_AGENT = "AutonomousForge-CSRFTester/1.0"

def rate_limited_get(session, url, **kwargs):
    """Perform a GET request respecting rate limiting and timeout."""
    try:
        time.sleep(RATE_LIMIT_DELAY)
        resp = session.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': USER_AGENT}, **kwargs)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return e

def rate_limited_post(session, url, data=None, json_data=None, **kwargs):
    """Perform a POST request respecting rate limiting and timeout."""
    try:
        time.sleep(RATE_LIMIT_DELAY)
        if json_data is not None:
            resp = session.post(url, json=json_data, timeout=REQUEST_TIMEOUT,
                                headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/json'},
                                **kwargs)
        else:
            resp = session.post(url, data=data, timeout=REQUEST_TIMEOUT,
                                headers={'User-Agent': USER_AGENT},
                                **kwargs)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return e

def detect_csrf_token(session, url):
    """Detect CSRF token presence in HTML forms or meta tags."""
    findings = []
    technologies = set()
    resp = rate_limited_get(session, url)
    if isinstance(resp, Exception):
        findings.append(f"Failed to fetch page: {resp}")
        return findings, list(technologies)

    soup = BeautifulSoup(resp.text, "html.parser")
    # Look for hidden inputs named like csrf
    token_fields = soup.find_all("input", {"type": "hidden"})
    for field in token_fields:
        name = field.get("name", "").lower()
        if "csrf" in name or "token" in name:
            token = field.get("value", "")
            if token:
                findings.append(f"Found CSRF token field '{name}' with value length {len(token)}")
                technologies.add("HTML Form")
    # Look for meta tags
    meta = soup.find("meta", {"name": "csrf-token"})
    if meta and meta.get("content"):
        findings.append("Found CSRF token in meta tag")
        technologies.add("Meta Tag")
    if not findings:
        findings.append("No CSRF token detected in HTML")
    return findings, list(technologies)

def validate_token(session, url):
    """Validate whether the endpoint enforces CSRF token."""
    findings = []
    # Attempt POST without token
    resp_no_token = rate_limited_post(session, url, data={"test": "value"})
    # Attempt POST with dummy token
    resp_dummy_token = rate_limited_post(session, url, data={"test": "value", "csrf_token": "dummy"})
    if isinstance(resp_no_token, Exception) or isinstance(resp_dummy_token, Exception):
        findings.append("POST requests failed; cannot assess token validation")
        return findings

    if resp_no_token.status_code == resp_dummy_token.status_code and resp_no_token.text == resp_dummy_token.text:
        findings.append("No observable difference between requests with/without token – possible CSRF protection missing")
    else:
        findings.append("Response differs when token is supplied – token likely validated")
    return findings

def check_samesite(session, url):
    """Inspect Set-Cookie headers for SameSite attribute."""
    findings = []
    resp = rate_limited_get(session, url)
    if isinstance(resp, Exception):
        findings.append(f"Failed to fetch for SameSite analysis: {resp}")
        return findings

    cookies = resp.headers.get_all('Set-Cookie') if hasattr(resp.headers, 'get_all') else resp.headers.get('Set-Cookie')
    if not cookies:
        findings.append("No Set-Cookie header present")
        return findings

    if isinstance(cookies, str):
        cookies = [cookies]

    for cookie in cookies:
        if "samesite=" in cookie.lower():
            ss_value = cookie.lower().split("samesite=")[1].split(";")[0].strip()
            findings.append(f"Cookie includes SameSite={ss_value}")
        else:
            findings.append("Cookie missing SameSite attribute – potential CSRF risk")
    return findings

def json_endpoint_check(session, url):
    """Test JSON POST endpoint for CSRF protection."""
    findings = []
    # Try POSTing JSON without token
    resp_no_token = rate_limited_post(session, url, json_data={"action":"test"})
    # Try POSTing JSON with dummy token field
    resp_with_token = rate_limited_post(session, url, json_data={"action":"test", "csrf_token":"dummy"})
    if isinstance(resp_no_token, Exception) or isinstance(resp_with_token, Exception):
        findings.append("JSON POST requests failed; cannot assess CSRF on JSON endpoint")
        return findings

    if resp_no_token.status_code == resp_with_token.status_code and resp_no_token.text == resp_with_token.text:
        findings.append("JSON endpoint does not differentiate token presence – possible CSRF vulnerability")
    else:
        findings.append("JSON endpoint appears to validate token")
    return findings

def run_assessment(target):
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    overall_findings = []
    technologies = set()

    # 1. Token detection
    token_findings, token_tech = detect_csrf_token(session, target)
    overall_findings.extend(token_findings)
    technologies.update(token_tech)

    # 2. Token validation
    validation_findings = validate_token(session, target)
    overall_findings.extend(validation_findings)

    # 3. SameSite analysis
    samesite_findings = check_samesite(session, target)
    overall_findings.extend(samesite_findings)

    # 4. JSON endpoint assessment
    json_findings = json_endpoint_check(session, target)
    overall_findings.extend(json_findings)

    status = "success" if overall_findings else "no findings"
    result = {
        "tool": "ForgeCSRFTester",
        "version": "1.0.0",
        "target": target,
        "status": status,
        "technologies": list(technologies),
        "findings": overall_findings,
        "results": {
            "token_detection": token_findings,
            "token_validation": validation_findings,
            "samesite_analysis": samesite_findings,
            "json_endpoint": json_findings
        }
    }
    return result

def self_test():
    """Simple self‑test using httpbin.org."""
    test_url = "https://httpbin.org/post"
    print("[*] Running self‑test against httpbin.org")
    result = run_assessment(test_url)
    print(json.dumps(result, indent=2))
    # Basic sanity checks
    assert isinstance(result, dict), "Result is not a dict"
    assert "tool" in result, "Missing tool key"
    assert result["target"] == test_url, "Target mismatch"
    print("[+] Self‑test completed successfully")

def main():
    parser = argparse.ArgumentParser(description="ForgeCSRFTester – Multi‑vector CSRF assessment tool")
    parser.add_argument("target", nargs="?", help="Target URL to assess")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test suite")
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
        except AssertionError as ae:
            print(f"[!] Self‑test assertion failed: {ae}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Self‑test encountered an error: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: target")
    # Validate URL
    parsed = urlparse(args.target)
    if not parsed.scheme:
        args.target = "http://" + args.target

    try:
        result = run_assessment(args.target)
        print(json.dumps(result, indent=2))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        error_output = {
            "tool": "ForgeCSRFTester",
            "version": "1.0.0",
            "target": args.target,
            "status": "error",
            "technologies": [],
            "findings": [f"Unexpected error: {exc}"],
            "results": {}
        }
        print(json.dumps(error_output, indent=2), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()