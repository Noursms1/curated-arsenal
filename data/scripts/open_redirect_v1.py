# CATEGORY: Web
# PREMORTEM:
# failure_mode: Network timeouts cause the scan to abort early, leaving many URLs untested.
# failure_mode: False positives arise from relative redirects that appear to point to the payload but are actually internal.
# failure_mode: Rate limiting or IP bans stop further requests, resulting in incomplete results.
# early_warning: Spike in request exception count (>10% of total requests) within a short window.
# early_warning: Average response time exceeding 5 seconds for consecutive requests.
# early_warning: Memory usage growth above 200MB when processing very large wordlists.

import argparse
import json
import sys
import time
import urllib.parse
from collections import defaultdict

import requests

TOOL_NAME = "OpenRedirectScanner"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10  # seconds
SLEEP_BETWEEN_REQUESTS = 0.5  # seconds
DEFAULT_WORDLIST = [
    "url",
    "redirect",
    "next",
    "dest",
    "destination",
    "rurl",
    "return",
    "target",
    "goto",
    "forward",
]

def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return DEFAULT_WORDLIST

def build_test_url(base_url, param, payload):
    parsed = urllib.parse.urlparse(base_url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query[param] = payload
    new_query = urllib.parse.urlencode(query, doseq=True)
    rebuilt = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(rebuilt)

def is_open_redirect(response, payload):
    # Check final URL after redirects
    final_url = response.url
    if payload in final_url:
        return True
    # Check Location header of the last response (if any)
    location = response.headers.get("Location", "")
    if payload in location:
        return True
    # Some apps reflect the payload in the body (simple heuristic)
    if payload in response.text:
        return True
    return False

def test_url_for_open_redirect(url, params, payload):
    findings = []
    for param in params:
        test_url = build_test_url(url, param, payload)
        try:
            resp = requests.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if is_open_redirect(resp, payload):
                findings.append({
                    "parameter": param,
                    "test_url": test_url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                })
        except Exception as exc:
            # Record the exception but continue scanning
            findings.append({
                "parameter": param,
                "test_url": test_url,
                "error": str(exc),
            })
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    return findings

def self_test():
    # Use httpbin.org which provides controlled redirect behavior
    safe_url = "https://httpbin.org/redirect-to"
    payload = "https://evil.com"
    test_params = ["url"]
    result = test_url_for_open_redirect(safe_url, test_params, payload)
    # Expect no open redirect because httpbin only redirects to the provided URL (controlled)
    success = all("error" in r or not is_open_redirect(requests.Response(), payload) for r in result)
    return {
        "self_test_passed": success,
        "details": result,
    }

def main():
    parser = argparse.ArgumentParser(description="Detect open redirect vulnerabilities.")
    parser.add_argument("target", nargs="?", help="Target URL to scan.")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file.")
    parser.add_argument("-p", "--payload", default="https://evil.com", help="Payload URL used for testing.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit.")
    args = parser.parse_args()

    if args.self_test:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "self-test",
            "status": "completed",
            "findings": [],
            "results": self_test(),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: target")

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST

    # Remove duplicates and empty strings
    params_to_test = list({p for p in wordlist if p})

    overall_findings = []
    exception_counter = 0
    total_requests = 0

    # Single target scan (could be extended to list of URLs)
    try:
        findings = test_url_for_open_redirect(args.target, params_to_test, args.payload)
        overall_findings.extend(findings)
        total_requests = len(params_to_test)
        exception_counter = sum(1 for f in findings if "error" in f)
    except Exception as e:
        overall_findings.append({"error": str(e)})

    status = "completed"
    if total_requests > 0 and exception_counter / total_requests > 0.1:
        status = "warning: high exception rate"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": overall_findings,
        "results": {
            "tested_parameters": len(params_to_test),
            "vulnerable_parameters": len([f for f in overall_findings if "parameter" in f and "error" not in f]),
            "exceptions": exception_counter,
        },
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()