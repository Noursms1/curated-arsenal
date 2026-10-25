# CATEGORY: Web
import argparse
import json
import sys
import time
import traceback
import urllib.parse
from typing import List, Dict, Any

import requests


TOOL_NAME = "ReflectedXSSScanner"
VERSION = "1.0"
SLEEP_INTERVAL = 0.5
DEFAULT_TIMEOUT = 10
PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><script>alert(1)</script>",
    "javascript:alert(1)",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
]


def extract_params(url: str) -> List[Dict[str, Any]]:
    """Return a list of query parameters with their positions."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    params = []
    for name, value in query:
        params.append({"name": name, "value": value})
    return params


def build_url(base_url: str, param_name: str, payload: str) -> str:
    """Replace the value of param_name with payload and rebuild the URL."""
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_query = [(name, payload if name == param_name else value) for name, value in query]
    new_query_str = urllib.parse.urlencode(new_query, doseq=True)
    rebuilt = parsed._replace(query=new_query_str)
    return urllib.parse.urlunparse(rebuilt)


def fetch(url: str) -> str:
    """Perform a GET request and return response text (empty on error)."""
    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
        return resp.text
    except Exception:
        # Suppress detailed error; could be logged in a real tool
        return ""


def analyze_response(response: str, payload: str) -> bool:
    """Check if the payload (or its decoded form) appears in the response."""
    if not response:
        return False
    # Direct match
    if payload in response:
        return True
    # URL-decoded match
    try:
        decoded = urllib.parse.unquote(payload)
        if decoded in response:
            return True
    except Exception:
        pass
    return False


def scan_url(target: str) -> Dict[str, Any]:
    findings = []
    params = extract_params(target)
    if not params:
        # No query parameters; nothing to test
        return {
            "findings": [],
            "status": "no_params",
            "results": "Target URL has no query parameters to test."
        }

    for param in params:
        for payload in PAYLOADS:
            test_url = build_url(target, param["name"], payload)
            time.sleep(SLEEP_INTERVAL)
            response = fetch(test_url)
            vulnerable = analyze_response(response, payload)
            finding = {
                "parameter": param["name"],
                "payload": payload,
                "vulnerable": vulnerable,
                "evidence": response[:200] if vulnerable else ""
            }
            findings.append(finding)

    status = "completed"
    return {
        "findings": findings,
        "status": status,
        "results": f"Scanned {len(params)} parameter(s) with {len(PAYLOADS)} payload(s) each."
    }


def self_test() -> Dict[str, Any]:
    """Run a minimal self‑test against httpbin.org which reflects query values."""
    test_url = "https://httpbin.org/get?selftest=PLACEHOLDER"
    # Replace placeholder with a known payload
    payload = "<script>alert(1)</script>"
    test_url = test_url.replace("PLACEHOLDER", urllib.parse.quote(payload))
    time.sleep(SLEEP_INTERVAL)
    response = fetch(test_url)
    vulnerable = analyze_response(response, payload)
    finding = {
        "parameter": "selftest",
        "payload": payload,
        "vulnerable": vulnerable,
        "evidence": response[:200] if vulnerable else ""
    }
    return {
        "findings": [finding],
        "status": "self_test_completed",
        "results": "Self‑test executed against httpbin.org."
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Reflected XSS detection tool")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test")
    args = parser.parse_args()

    output: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target if args.target else "",
        "status": "",
        "findings": [],
        "results": ""
    }

    try:
        if args.self_test:
            result = self_test()
            output["target"] = "https://httpbin.org/get"
        elif args.target:
            result = scan_url(args.target)
        else:
            raise ValueError("Either a target URL or --self-test must be provided.")

        output.update({
            "status": result.get("status", ""),
            "findings": result.get("findings", []),
            "results": result.get("results", "")
        })
    except Exception as e:
        output["status"] = "error"
        output["results"] = f"Exception: {str(e)}"
        output["findings"] = []
        # In a production setting, log traceback somewhere secure
        traceback.print_exc(file=sys.stderr)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()