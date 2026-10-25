# CATEGORY: Web
import argparse
import json
import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

TOOL_NAME = "StoredXSSScanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5
XSS_PAYLOAD = "<script>alert('XSS')</script>"


def safe_get(url, session, **kwargs):
    try:
        resp = session.get(url, timeout=10, **kwargs)
        time.sleep(SLEEP_INTERVAL)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return None


def safe_post(url, data, session, **kwargs):
    try:
        resp = session.post(url, data=data, timeout=10, **kwargs)
        time.sleep(SLEEP_INTERVAL)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return None


def is_same_domain(base, target):
    return urlparse(base).netloc == urlparse(target).netloc


def crawl_site(base_url, session):
    visited = set()
    to_visit = [base_url]
    pages = []

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        resp = safe_get(url, session)
        if not resp:
            continue
        pages.append(url)

        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(url, href)
            if is_same_domain(base_url, full_url) and full_url not in visited:
                to_visit.append(full_url)
    return pages


def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append(name)
        form_details = {
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs,
        }
        forms.append(form_details)
    return forms


def submit_payload(form, session):
    data = {name: XSS_PAYLOAD for name in form["inputs"]}
    if form["method"] == "post":
        resp = safe_post(form["action"], data, session)
    else:
        resp = safe_get(form["action"], session, params=data)
    return resp


def verify_payload(page_url, session):
    resp = safe_get(page_url, session)
    if resp and XSS_PAYLOAD in resp.text:
        return True
    return False


def run_scan(target):
    session = requests.Session()
    findings = []
    results = []

    pages = crawl_site(target, session)

    for page in pages:
        resp = safe_get(page, session)
        if not resp:
            continue
        forms = extract_forms(resp.text, page)
        for form in forms:
            submit_resp = submit_payload(form, session)
            if not submit_resp:
                continue
            # After submission, attempt to locate payload on the original page or target page
            vulnerable = verify_payload(page, session) or verify_payload(form["action"], session)
            result_entry = {
                "page": page,
                "form_action": form["action"],
                "method": form["method"],
                "inputs": form["inputs"],
                "vulnerable": vulnerable,
            }
            results.append(result_entry)
            if vulnerable:
                findings.append({
                    "url": page,
                    "form_action": form["action"],
                    "method": form["method"],
                })
    status = "completed"
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }


def self_test():
    # Simple self‑test using a known safe URL; we expect no findings.
    test_target = "https://httpbin.org/html"
    report = run_scan(test_target)
    # Override status to indicate self‑test
    report["status"] = "self-test"
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Stored XSS detection tool")
    parser.add_argument("target", nargs="?", help="Base URL of the target site")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a self‑test against a known safe endpoint",
    )
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
            "results": [],
            "error": "Target URL not provided"
        }, indent=2))
        sys.exit(1)

    report = run_scan(args.target)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()