#!/usr/bin/env python3
"""
CATEGORY: Recon
TECHNIQUES: Wayback Machine harvesting, JavaScript asset discovery, URL parameter analysis for XSS vectors
CHAIN_CONTRIBUTIONS: Integrates historical URL data with active asset enumeration and automated payload surface identification
"""

import argparse
import json
import sys
import time
import urllib.parse
from typing import List, Dict, Set

import requests

TIMEOUT = 10
RATE_LIMIT = 0.5
USER_AGENT = "AutonomousForge/1.0 (+https://github.com/autonomousforge)"


def rate_limited_get(url: str, params: dict = None) -> requests.Response:
    """Perform a GET request respecting rate limiting and timeout."""
    time.sleep(RATE_LIMIT)
    try:
        resp = requests.get(
            url,
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp
    except Exception as e:
        raise RuntimeError(f"Request failed for {url}: {e}") from e


def get_wayback_urls(domain: str) -> List[str]:
    """
    Retrieve a list of unique URLs archived by the Wayback Machine for a given domain.
    """
    api = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
    }
    try:
        resp = rate_limited_get(api, params)
        data = resp.json()
        # First entry is header row; skip it
        urls = [entry[0] for entry in data[1:]]
        return urls
    except Exception as e:
        raise RuntimeError(f"Failed to fetch Wayback URLs for {domain}: {e}") from e


def filter_js_files(urls: List[str]) -> List[str]:
    """
    Identify URLs that point to JavaScript assets.
    """
    js_urls = [u for u in urls if u.lower().endswith(".js")]
    return js_urls


def extract_parameters(urls: List[str]) -> Dict[str, Set[str]]:
    """
    Extract query parameters from URLs and group them by base path.
    Returns a mapping: base_path -> set(parameter_names)
    """
    param_map: Dict[str, Set[str]] = {}
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if base not in param_map:
            param_map[base] = set()
        param_map[base].update(params.keys())
    return param_map


def identify_xss_candidates(param_map: Dict[str, Set[str]]) -> List[Dict]:
    """
    From the parameter map, generate potential XSS vectors.
    Heuristic: any parameter on pages with typical dynamic extensions.
    """
    dynamic_exts = {".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl"}
    candidates = []
    for base, params in param_map.items():
        _, ext = urllib.parse.os.path.splitext(urllib.parse.urlparse(base).path)
        if ext.lower() in dynamic_exts or not ext:
            for p in params:
                candidates.append({"url": base, "parameter": p})
    return candidates


def build_output(tool: str, version: str, target: str, findings: Dict) -> dict:
    """
    Assemble the standardized JSON output.
    """
    return {
        "tool": tool,
        "version": version,
        "target": target,
        "status": "completed",
        "technologies": list(findings.get("technologies", [])),
        "findings": findings,
        "results": findings.get("results", []),
    }


def run_analysis(domain: str) -> dict:
    """
    Execute the full analysis pipeline for a given domain.
    """
    try:
        wayback_urls = get_wayback_urls(domain)
        js_files = filter_js_files(wayback_urls)
        param_map = extract_parameters(wayback_urls)
        xss_candidates = identify_xss_candidates(param_map)

        findings = {
            "total_wayback_urls": len(wayback_urls),
            "js_files": js_files,
            "parameters_by_path": {k: list(v) for k, v in param_map.items()},
            "potential_xss_vectors": xss_candidates,
            "technologies": {"js_files": len(js_files), "xss_vectors": len(xss_candidates)},
            "results": {
                "js_files": js_files,
                "xss_vectors": xss_candidates,
            },
        }

        output = build_output(
            tool="WaybackJSXSS",
            version="1.0.0",
            target=domain,
            findings=findings,
        )
        return output
    except Exception as e:
        return {
            "tool": "WaybackJSXSS",
            "version": "1.0.0",
            "target": domain,
            "status": "error",
            "technologies": [],
            "findings": {"error": str(e)},
            "results": [],
        }


def self_test() -> bool:
    """
    Perform a lightweight self‑test against a known domain.
    Returns True if the test passes.
    """
    test_domain = "example.com"
    result = run_analysis(test_domain)
    required_keys = {"tool", "version", "target", "status", "technologies", "findings", "results"}
    if not isinstance(result, dict):
        print("Self‑test failed: result is not a dict")
        return False
    if not required_keys.issubset(result.keys()):
        print("Self‑test failed: missing required keys")
        return False
    if result.get("status") != "completed":
        print(f"Self‑test failed: status is {result.get('status')}")
        return False
    # Basic sanity checks
    if not isinstance(result["findings"].get("js_files", []), list):
        print("Self‑test failed: js_files not a list")
        return False
    if not isinstance(result["findings"].get("potential_xss_vectors", []), list):
        print("Self‑test failed: potential_xss_vectors not a list")
        return False
    print("Self‑test passed")
    return True


def main():
    parser = argparse.ArgumentParser(description="Wayback Machine URL extractor + JS finder + XSS parameter scanner")
    parser.add_argument("-t", "--target", help="Target domain (e.g., example.com)")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        success = self_test()
        sys.exit(0 if success else 1)

    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    output = run_analysis(args.target)
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()