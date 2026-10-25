# CATEGORY: Web
import argparse
import json
import sys
import time
import urllib.parse
import requests

TOOL_NAME = "SQLiScanner"
VERSION = "1.0"
SLEEP_INTERVAL = 0.5
HEADERS = {"User-Agent": "SQLiScanner/1.0"}

def build_url(base_url, payload):
    if "{inj}" in base_url:
        return base_url.replace("{inj}", urllib.parse.quote(payload))
    # Append payload as a query param named 'id' if not present
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.parse_qs(parsed.query)
    query["id"] = [payload]
    new_query = urllib.parse.urlencode(query, doseq=True)
    rebuilt = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(rebuilt)

def request(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        return resp
    except Exception as e:
        return e

def error_based_test(base_url):
    payload = "'"
    test_url = build_url(base_url, payload)
    resp = request(test_url)
    vulnerable = False
    details = ""
    if isinstance(resp, requests.Response):
        if any(err in resp.text.lower() for err in ["sql syntax", "sql error", "unterminated", "warning"]):
            vulnerable = True
            details = "Error message detected"
    else:
        details = str(resp)
    return {"type": "error-based", "vulnerable": vulnerable, "details": details, "url": test_url}

def boolean_based_test(base_url):
    true_payload = "1 AND 1=1"
    false_payload = "1 AND 1=2"
    true_url = build_url(base_url, true_payload)
    false_url = build_url(base_url, false_payload)

    true_resp = request(true_url)
    false_resp = request(false_url)

    vulnerable = False
    details = ""
    if isinstance(true_resp, requests.Response) and isinstance(false_resp, requests.Response):
        if true_resp.status_code == false_resp.status_code and true_resp.text != false_resp.text:
            vulnerable = True
            details = "Differing response bodies for true/false conditions"
    else:
        details = f"True request error: {true_resp}, False request error: {false_resp}"
    return {"type": "boolean-based", "vulnerable": vulnerable, "details": details,
            "true_url": true_url, "false_url": false_url}

def time_based_test(base_url):
    payload = "1; SELECT IF(1=1, SLEEP(5), 0)-- "
    test_url = build_url(base_url, payload)
    start = time.time()
    resp = request(test_url)
    elapsed = time.time() - start

    vulnerable = False
    details = ""
    if isinstance(resp, requests.Response):
        if elapsed > 4:  # threshold for sleep detection
            vulnerable = True
            details = f"Response delayed by {elapsed:.2f}s"
        else:
            details = f"Response time {elapsed:.2f}s"
    else:
        details = str(resp)
    return {"type": "time-based", "vulnerable": vulnerable, "details": details, "url": test_url, "elapsed": elapsed}

def run_all_tests(target):
    findings = []
    results = []

    for test_func in (error_based_test, boolean_based_test, time_based_test):
        result = test_func(target)
        results.append(result)
        if result.get("vulnerable"):
            findings.append({"type": result["type"], "details": result["details"], "url": result.get("url", result.get("true_url"))})

    status = "completed"
    return {"tool": TOOL_NAME, "version": VERSION, "target": target,
            "status": status, "findings": findings, "results": results}

def self_test():
    dummy_url = "http://example.com/?id={inj}"
    try:
        output = run_all_tests(dummy_url)
        output["status"] = "self-test passed"
        print(json.dumps(output, indent=2))
        return 0
    except Exception as e:
        err_output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": dummy_url,
            "status": f"self-test failed: {e}",
            "findings": [],
            "results": []
        }
        print(json.dumps(err_output, indent=2))
        return 1

def main():
    parser = argparse.ArgumentParser(description="Simple SQL Injection detection tool")
    parser.add_argument("target", nargs="?", help="Target URL (use {inj} as injection placeholder)")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error: no target provided",
            "findings": [],
            "results": []
        }, indent=2))
        sys.exit(1)

    output = run_all_tests(args.target)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()