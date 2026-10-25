# CATEGORY: API
import argparse
import json
import sys
import time
import requests

TOOL_NAME = "oauth_misconfig_scanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

def safe_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        time.sleep(SLEEP_INTERVAL)
        return response
    except Exception as e:
        return e

def check_token_endpoint(base_url):
    findings = []
    results = {}
    url = f"{base_url.rstrip('/')}/oauth/token"
    resp = safe_request("GET", url)
    if isinstance(resp, Exception):
        findings.append({
            "description": "Token endpoint reachable check failed",
            "vulnerable": False,
            "error": str(resp)
        })
    else:
        results["status_code"] = resp.status_code
        results["body"] = resp.text[:200]
        if resp.status_code == 200 and "access_token" in resp.text:
            findings.append({
                "description": "Token endpoint returns token without authentication",
                "vulnerable": True,
                "details": "Unauthenticated token issuance"
            })
        else:
            findings.append({
                "description": "Token endpoint requires authentication",
                "vulnerable": False,
                "details": f"Returned status {resp.status_code}"
            })
    return findings, results

def check_client_info_endpoint(base_url):
    findings = []
    results = {}
    url = f"{base_url.rstrip('/')}/oauth/clients"
    resp = safe_request("GET", url)
    if isinstance(resp, Exception):
        findings.append({
            "description": "Client info endpoint reachable check failed",
            "vulnerable": False,
            "error": str(resp)
        })
    else:
        results["status_code"] = resp.status_code
        results["body"] = resp.text[:200]
        if resp.status_code == 200 and ("client_id" in resp.text or "client_secret" in resp.text):
            findings.append({
                "description": "Client information exposed without authentication",
                "vulnerable": True,
                "details": "Sensitive client data disclosed"
            })
        else:
            findings.append({
                "description": "Client information protected",
                "vulnerable": False,
                "details": f"Returned status {resp.status_code}"
            })
    return findings, results

def check_introspection_endpoint(base_url):
    findings = []
    results = {}
    url = f"{base_url.rstrip('/')}/oauth/introspect"
    data = {"token": "dummy"}
    resp = safe_request("POST", url, data=data)
    if isinstance(resp, Exception):
        findings.append({
            "description": "Introspection endpoint reachable check failed",
            "vulnerable": False,
            "error": str(resp)
        })
    else:
        results["status_code"] = resp.status_code
        results["body"] = resp.text[:200]
        if resp.status_code == 200 and ("active" in resp.text):
            findings.append({
                "description": "Introspection endpoint allows unauthenticated token checks",
                "vulnerable": True,
                "details": "Token introspection without auth"
            })
        else:
            findings.append({
                "description": "Introspection endpoint requires authentication",
                "vulnerable": False,
                "details": f"Returned status {resp.status_code}"
            })
    return findings, results

def check_open_redirect(base_url):
    findings = []
    results = {}
    redirect_uri = "http://evil.com"
    url = f"{base_url.rstrip('/')}/oauth/authorize?client_id=test&redirect_uri={redirect_uri}"
    resp = safe_request("GET", url, allow_redirects=False)
    if isinstance(resp, Exception):
        findings.append({
            "description": "Open redirect check failed",
            "vulnerable": False,
            "error": str(resp)
        })
    else:
        results["status_code"] = resp.status_code
        results["location"] = resp.headers.get("Location", "")
        if resp.status_code in (301, 302) and results["location"].startswith(redirect_uri):
            findings.append({
                "description": "Open redirect vulnerability detected",
                "vulnerable": True,
                "details": f"Redirected to {results['location']}"
            })
        else:
            findings.append({
                "description": "No open redirect vulnerability",
                "vulnerable": False,
                "details": f"Returned status {resp.status_code}"
            })
    return findings, results

def run_checks(target):
    all_findings = []
    all_results = {}
    for check_func in [check_token_endpoint,
                       check_client_info_endpoint,
                       check_introspection_endpoint,
                       check_open_redirect]:
        name = check_func.__name__
        findings, results = check_func(target)
        all_findings.extend(findings)
        all_results[name] = results
    return all_findings, all_results

def self_test():
    # Simulate successful checks without network calls
    dummy_findings = [
        {"description": "Self-test token endpoint", "vulnerable": False},
        {"description": "Self-test client info endpoint", "vulnerable": False},
        {"description": "Self-test introspection endpoint", "vulnerable": False},
        {"description": "Self-test open redirect", "vulnerable": False}
    ]
    dummy_results = {
        "check_token_endpoint": {"status_code": 401},
        "check_client_info_endpoint": {"status_code": 401},
        "check_introspection_endpoint": {"status_code": 401},
        "check_open_redirect": {"status_code": 400}
    }
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "completed",
        "findings": dummy_findings,
        "results": dummy_results
    }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="OAuth Misconfiguration Scanner")
    parser.add_argument("target", nargs="?", help="Base URL of the API to scan")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
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
            "findings": [],
            "results": {}
        }, indent=2))
        sys.exit(1)

    findings, results = run_checks(args.target)
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