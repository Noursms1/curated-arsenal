# CATEGORY: Web
# PREMORTEM:
# failure_mode: Unhandled exception causing the tool to crash (e.g., missing arguments, unexpected response format)
# early_warning: exception_counter > 0 logged to stderr
# failure_mode: Excessive request rate leading to target rate limiting or self-imposed throttling
# early_warning: consecutive_429_counter > 3 triggers warning and slows down further requests
# failure_mode: Memory exhaustion due to storing full response bodies for many payloads
# early_warning: total_stored_bytes > 10_000_000 (10 MB) triggers warning and truncates stored data

import argparse
import json
import sys
import time
import logging
from typing import List, Dict, Any
import requests

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)

TOOL_NAME = "SSRFScanner"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 5  # seconds
SLEEP_BETWEEN_REQUESTS = 0.5  # seconds
MAX_STORED_BYTES = 10_000_000  # 10 MB


def load_payloads(file_path: str) -> List[str]:
    """Load payloads from a text file, one per line."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads
    except Exception as e:
        logging.error(f"Failed to load payloads from {file_path}: {e}")
        return []


def build_url(target: str, payload: str) -> str:
    """
    Insert the payload into the target URL.
    The target should contain a placeholder `{payload}` where the payload will be substituted.
    If no placeholder is found, payload is appended as a query parameter `url`.
    """
    if "{payload}" in target:
        return target.replace("{payload}", payload)
    separator = "&" if "?" in target else "?"
    return f"{target}{separator}url={payload}"


def test_payload(target: str, payload: str) -> Dict[str, Any]:
    """
    Send a GET request to the target URL with the payload injected.
    Returns a dictionary with the result details.
    """
    url = build_url(target, payload)
    result = {
        "payload": payload,
        "url": url,
        "http_status": None,
        "response_length": None,
        "error": None,
        "potential_vuln": False,
    }

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        result["http_status"] = response.status_code
        result["response_length"] = len(response.content)

        # Simple heuristic: if we get a 200 and the response contains typical internal service strings
        internal_indicators = ["aws", "metadata", "internal", "root", "admin"]
        body_text = response.text.lower()
        if any(indicator in body_text for indicator in internal_indicators):
            result["potential_vuln"] = True

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


def self_test() -> Dict[str, Any]:
    """Run a minimal self‑test to verify basic functionality."""
    test_target = "https://httpbin.org/get?test={payload}"
    test_payloads = ["http://example.com"]
    findings = []
    results = []

    for payload in test_payloads:
        res = test_payload(test_target, payload)
        results.append(res)
        if res["error"] is None and res["http_status"] == 200:
            findings.append("self_test_success")
        else:
            findings.append("self_test_failure")
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_target,
        "status": "self_test_completed",
        "findings": findings,
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Simple SSRF detection tool.")
    parser.add_argument("--url", help="Target URL containing `{payload}` placeholder or base URL.", required=False)
    parser.add_argument("--payloads", help="Path to file with payloads (one per line).", required=False)
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit.")
    args = parser.parse_args()

    if args.self_test:
        output = self_test()
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    if not args.url:
        logging.error("Target URL is required unless --self-test is used.")
        sys.exit(1)

    payloads = []
    if args.payloads:
        payloads = load_payloads(args.payloads)
        if not payloads:
            logging.error("No payloads loaded; exiting.")
            sys.exit(1)
    else:
        # Default minimal payload list if none provided
        payloads = [
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://[::1]",
            "http://localhost",
        ]

    findings = []
    results = []
    exception_counter = 0
    consecutive_429_counter = 0
    total_stored_bytes = 0

    for payload in payloads:
        res = test_payload(args.url, payload)
        results.append(res)

        # Update early warning counters
        if res["error"]:
            exception_counter += 1
        if res["http_status"] == 429:
            consecutive_429_counter += 1
        else:
            consecutive_429_counter = 0

        if res["potential_vuln"]:
            findings.append({"payload": payload, "issue": "potential_ssrf"})

        # Track memory usage of stored results (approximate)
        total_stored_bytes += (
            len(res.get("payload", "")) +
            len(res.get("url", "")) +
            (res.get("response_length") or 0)
        )
        if total_stored_bytes > MAX_STORED_BYTES:
            logging.warning("Stored result size exceeds threshold; truncating further storage.")
            break

        # Early warnings
        if exception_counter > 0:
            logging.warning(f"Encountered {exception_counter} request exception(s).")
        if consecutive_429_counter > 3:
            logging.warning("Received >3 consecutive 429 responses; slowing down.")
            time.sleep(2)  # additional back‑off

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    status = "completed"
    if exception_counter > 0:
        status = "completed_with_errors"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.url,
        "status": status,
        "findings": findings,
        "results": results,
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()