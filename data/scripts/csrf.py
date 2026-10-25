# CATEGORY: Web
import argparse
import json
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

TOOL_NAME = "csrf_scanner"
VERSION = "1.0.0"
COMMON_TOKEN_NAMES = {"csrf_token", "authenticity_token", "_csrf", "csrf", "token"}


def fetch_url(session, url):
    try:
        resp = session.get(url, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return e


def submit_form(session, form_details, base_url, omit_tokens=False):
    action = form_details["action"]
    method = form_details["method"].lower()
    url = urljoin(base_url, action) if not urlparse(action).netloc else action

    data = {}
    for name, value in form_details["inputs"].items():
        if omit_tokens and name.lower() in COMMON_TOKEN_NAMES:
            continue
        data[name] = value

    try:
        if method == "post":
            resp = session.post(url, data=data, timeout=10)
        else:  # GET or others treated as GET
            resp = session.get(url, params=data, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return e


def parse_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        details = {
            "action": form.get("action") or base_url,
            "method": form.get("method") or "get",
            "inputs": {},
        }
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value", "")
            details["inputs"][name] = value
        forms.append(details)
    return forms


def analyze_csrf(session, target_url):
    findings = []
    base_resp = fetch_url(session, target_url)
    if isinstance(base_resp, Exception):
        return {"status": "error", "message": str(base_resp), "findings": []}

    forms = parse_forms(base_resp.text, target_url)

    for idx, form in enumerate(forms, 1):
        token_fields = [n for n in form["inputs"] if n.lower() in COMMON_TOKEN_NAMES]
        token_present = bool(token_fields)

        # Attempt submission without token if token is present
        submission_status = None
        if token_present:
            resp = submit_form(session, form, target_url, omit_tokens=True)
            if isinstance(resp, Exception):
                submission_status = f"error: {resp}"
            else:
                # Simple heuristic: if server returns 4xx/5xx, assume token required
                if resp.status_code >= 400:
                    submission_status = f"rejected ({resp.status_code})"
                else:
                    submission_status = f"accepted ({resp.status_code})"
        else:
            submission_status = "no token to test"

        findings.append(
            {
                "form_index": idx,
                "action": form["action"],
                "method": form["method"].upper(),
                "token_present": token_present,
                "token_fields": token_fields,
                "submission_without_token": submission_status,
            }
        )

    # Cookie SameSite analysis
    cookie_findings = []
    for cookie in session.cookies:
        same_site = cookie._rest.get("samesite")
        cookie_findings.append(
            {
                "name": cookie.name,
                "value": cookie.value,
                "samesite": same_site if same_site else "None",
            }
        )

    return {
        "status": "completed",
        "findings": findings,
        "cookies": cookie_findings,
    }


def run_self_test():
    # Simple HTML with a CSRF hidden field
    test_html = """
    <html><body>
    <form action="/submit" method="post">
        <input type="hidden" name="csrf_token" value="abc123"/>
        <input type="text" name="username"/>
        <input type="submit" value="Send"/>
    </form>
    </body></html>
    """
    session = requests.Session()
    # Mock fetch by directly using the HTML
    forms = parse_forms(test_html, "http://example.com")
    if not forms:
        return False, "No forms parsed"
    form = forms[0]
    token_fields = [n for n in form["inputs"] if n.lower() in COMMON_TOKEN_NAMES]
    if "csrf_token" not in token_fields:
        return False, "CSRF token not detected"
    # Simulate submission without token (will fail because we cannot reach server, expect exception)
    resp = submit_form(session, form, "http://example.com", omit_tokens=True)
    if not isinstance(resp, Exception):
        return False, "Submission without token did not raise exception as expected"
    return True, "Self-test passed"


def main():
    parser = argparse.ArgumentParser(description="CSRF detection tool")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument(
        "--self-test", action="store_true", help="Run internal self‑test suite"
    )
    args = parser.parse_args()

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target if args.target else "",
        "status": "",
        "findings": [],
        "results": {},
    }

    if args.self_test:
        success, message = run_self_test()
        output["status"] = "self-test passed" if success else "self-test failed"
        output["results"] = {"message": message}
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: target")

    session = requests.Session()
    analysis = analyze_csrf(session, args.target)

    output["status"] = analysis.get("status", "error")
    output["findings"] = analysis.get("findings", [])
    output["results"] = {"cookies": analysis.get("cookies", [])}
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()