# CATEGORY: Web - SSRF Detection Tool
import argparse
import json
import sys
import time
import urllib.parse
import requests

TOOL_NAME = "ssrf_scanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

DEFAULT_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://localhost",
    "file:///etc/passwd",
    "http://[::1]",
]

REDIRECT_PAYLOAD = "https://example.com/redirected"

def build_url(base, param, payload):
    parsed = urllib.parse.urlparse(base)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query[param] = payload
    new_query = urllib.parse.urlencode(query)
    rebuilt = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(rebuilt)

def request_url(url):
    try:
        resp = requests.get(url, timeout=10)
        return {"status_code": resp.status_code, "length": len(resp.content), "content": resp.text[:200]}
    except Exception as e:
        return {"error": str(e)}

def scan_target(target, param):
    findings = []
    results = []

    # Capability 1: Basic reachability
    basic = request_url(target)
    time.sleep(SLEEP_INTERVAL)
    if "error" in basic:
        status = "error"
        findings.append("Target unreachable")
    else:
        status = "ok"
        findings.append("Target reachable")
    results.append({"type": "reachability", "url": target, "response": basic})

    # Capability 2: SSRF payload testing
    for payload in DEFAULT_PAYLOADS:
        test_url = build_url(target, param, payload)
        resp = request_url(test_url)
        time.sleep(SLEEP_INTERVAL)
        result = {"type": "ssrf_test", "payload": payload, "url": test_url, "response": resp}
        results.append(result)
        if "error" not in resp and resp.get("status_code", 0) == 200:
            findings.append(f"Possible SSRF with payload {payload}")

    # Capability 3: Open redirect detection
    redirect_url = build_url(target, param, REDIRECT_PAYLOAD)
    resp = request_url(redirect_url)
    time.sleep(SLEEP_INTERVAL)
    results.append({"type": "open_redirect", "payload": REDIRECT_PAYLOAD, "url": redirect_url, "response": resp})
    if resp.get("status_code") in (301, 302) and REDIRECT_PAYLOAD in resp.get("content", ""):
        findings.append("Possible open redirect vulnerability")

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }

def self_test():
    test_target = "https://httpbin.org/get"
    param = "url"
    output = scan_target(test_target, param)
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="SSRF detection utility")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("-p", "--param", default="url", help="Parameter name to inject payloads")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target provided"],
            "results": []
        }, indent=2))
        sys.exit(1)

    output = scan_target(args.target, args.param)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()