# CATEGORY: Web
import argparse
import json
import sys
import time
import urllib.parse
from collections import deque

import requests

TOOL_NAME = "OpenRedirectScanner"
VERSION = "1.0.0"
PAYLOAD = "https://evil.com/redirect"


def safe_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        return response
    except Exception as e:
        return e


def check_redirect(url):
    findings = []
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not query:
        return findings

    for param in query:
        modified_query = query.copy()
        modified_query[param] = [PAYLOAD]
        new_query = urllib.parse.urlencode(modified_query, doseq=True)
        test_url = urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )
        resp = safe_request("GET", test_url, allow_redirects=False)
        time.sleep(0.5)
        if isinstance(resp, Exception):
            continue
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("Location", "")
            if PAYLOAD in location:
                findings.append(
                    {
                        "url": test_url,
                        "parameter": param,
                        "redirect_to": location,
                        "status_code": resp.status_code,
                    }
                )
    return findings


def scan_target(target):
    results = []
    findings = []
    if target.startswith("http://") or target.startswith("https://"):
        res = check_redirect(target)
        results.append({"target": target, "findings": res})
        findings.extend(res)
    else:
        try:
            with open(target, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {"status": "error", "error": str(e), "results": []}
        for line in lines:
            res = check_redirect(line)
            results.append({"target": line, "findings": res})
            findings.extend(res)
    return {"status": "completed", "results": results, "findings": findings}


def crawl_site(start_url, max_depth=2):
    visited = set()
    queue = deque([(start_url, 0)])
    all_results = []
    all_findings = []

    while queue:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        resp = safe_request("GET", current_url)
        time.sleep(0.5)
        if isinstance(resp, Exception):
            continue
        if resp.status_code != 200:
            continue

        # Check current URL for open redirect
        redirect_findings = check_redirect(current_url)
        all_results.append({"target": current_url, "findings": redirect_findings})
        all_findings.extend(redirect_findings)

        # Extract links for further crawling
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                parsed_href = urllib.parse.urljoin(current_url, href)
                if parsed_href.startswith("http"):
                    queue.append((parsed_href, depth + 1))
        except Exception:
            # BeautifulSoup not available or parsing error; skip further crawling
            pass

    return {"status": "completed", "results": all_results, "findings": all_findings}


def self_test():
    test_url = "https://httpbin.org/redirect-to"
    # httpbin's redirect-to endpoint reflects the 'url' param, safe for test
    result = check_redirect(f"{test_url}?url={urllib.parse.quote('https://example.com')}")
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_url,
        "status": "self-test",
        "findings": result,
        "results": [{"target": test_url, "findings": result}],
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Detect open redirect vulnerabilities.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL to scan")
    group.add_argument("-f", "--file", help="File containing list of URLs")
    group.add_argument("-c", "--crawl", help="Base URL to crawl for potential redirects")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test routine")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if args.url:
        target = args.url
    elif args.file:
        target = args.file
    else:
        target = args.crawl

    if args.url or args.file:
        scan_data = scan_target(target)
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": target,
            "status": scan_data.get("status", "completed"),
            "findings": scan_data.get("findings", []),
            "results": scan_data.get("results", []),
        }
    else:
        crawl_data = crawl_site(args.crawl, max_depth=args.depth)
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.crawl,
            "status": crawl_data.get("status", "completed"),
            "findings": crawl_data.get("findings", []),
            "results": crawl_data.get("results", []),
        }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()