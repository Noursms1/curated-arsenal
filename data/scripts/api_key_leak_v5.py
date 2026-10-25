# CATEGORY: API
# PREMORTEM:
# failure_mode: False negatives due to incomplete regex patterns missing new key formats
# failure_mode: Rate limiting or network outage causing incomplete external leak checks
# failure_mode: Accidental logging or printing of discovered API keys in plaintext
# early_warning: Spike in request exception count > 5 within a 5‑minute window
# early_warning: Total scan time exceeds expected threshold (e.g., > 2× average)
# early_warning: Output JSON contains empty "findings" despite non‑empty target

import argparse
import json
import os
import re
import sys
import time
import threading
from collections import Counter
from datetime import datetime, timedelta

import requests

TOOL_NAME = "api_key_leak_scanner"
VERSION = "1.0.0"

# Regex patterns for common API key formats (expandable)
KEY_PATTERNS = [
    # Generic alphanumeric strings of length >= 20
    re.compile(r"[A-Za-z0-9]{20,}"),
    # AWS Access Key ID
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Google API key
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    # Slack token
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    # Generic secret token prefix
    re.compile(r"(?i)secret[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-/+=]{30,})['\"]?"),
]

# Simple in‑memory counter for early warning signals
error_counter = Counter()
error_lock = threading.Lock()
ERROR_WINDOW = timedelta(minutes=5)

def record_error():
    with error_lock:
        now = datetime.utcnow()
        error_counter[now] += 1
        # Cleanup old entries
        for ts in list(error_counter):
            if now - ts > ERROR_WINDOW:
                del error_counter[ts]

def error_rate_exceeds(threshold=5):
    with error_lock:
        total = sum(error_counter.values())
        return total > threshold

def mask_key(key):
    """Return a masked version of the key, preserving first and last 4 chars."""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"

def scan_file_for_keys(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                for pattern in KEY_PATTERNS:
                    for match in pattern.finditer(line):
                        raw = match.group(0)
                        masked = mask_key(raw)
                        findings.append({
                            "type": "file",
                            "path": filepath,
                            "line": lineno,
                            "match": masked,
                        })
    except (UnicodeDecodeError, OSError) as e:
        record_error()
        # Non‑critical: skip unreadable files
    return findings

def walk_directory(root_path):
    findings = []
    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            if name.lower().endswith(('.py', '.js', '.json', '.env', '.txt', '.yml', '.yaml')):
                full_path = os.path.join(dirpath, name)
                findings.extend(scan_file_for_keys(full_path))
                time.sleep(0.5)  # throttle filesystem scans
    return findings

def scan_env_vars():
    findings = []
    for var, val in os.environ.items():
        for pattern in KEY_PATTERNS:
            if pattern.search(val):
                findings.append({
                    "type": "env",
                    "variable": var,
                    "match": mask_key(val),
                })
    return findings

def query_github_secret_scanning(api_url, token):
    """Query GitHub's secret scanning API for known leaks (public only)."""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    findings = []
    try:
        resp = requests.get(api_url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("results", []):
            findings.append({
                "type": "github",
                "repo": item.get("repository", {}).get("full_name"),
                "secret_type": item.get("secret_type"),
                "url": item.get("html_url"),
            })
    except requests.RequestException:
        record_error()
    finally:
        time.sleep(0.5)  # respect rate limits
    return findings

def perform_self_test():
    test_results = {"tests_passed": 0, "tests_failed": 0, "details": []}
    # Test 1: mask_key
    try:
        assert mask_key("ABCDEFGHIJKL1234567890") == "ABCD************7890"
        test_results["tests_passed"] += 1
        test_results["details"].append({"test": "mask_key", "status": "pass"})
    except AssertionError:
        test_results["tests_failed"] += 1
        test_results["details"].append({"test": "mask_key", "status": "fail"})
    # Test 2: regex detection
    sample = "My AWS key is AKIA1234567890ABCD"
    matches = [m.group(0) for p in KEY_PATTERNS for m in p.finditer(sample)]
    try:
        assert "AKIA1234567890ABCD" in matches
        test_results["tests_passed"] += 1
        test_results["details"].append({"test": "regex_detection", "status": "pass"})
    except AssertionError:
        test_results["tests_failed"] += 1
        test_results["details"].append({"test": "regex_detection", "status": "fail"})
    # Test 3: environment scan (mock)
    os.environ["TEST_API_KEY"] = "AIzaSyDUMMYKEY1234567890123456789012"
    env_findings = scan_env_vars()
    try:
        assert any(f["variable"] == "TEST_API_KEY" for f in env_findings)
        test_results["tests_passed"] += 1
        test_results["details"].append({"test": "env_scan", "status": "pass"})
    except AssertionError:
        test_results["tests_failed"] += 1
        test_results["details"].append({"test": "env_scan", "status": "fail"})
    # Cleanup mock env var
    del os.environ["TEST_API_KEY"]
    return test_results

def main():
    parser = argparse.ArgumentParser(description="Detect leaked API keys in codebases and environments.")
    parser.add_argument("target", nargs="?", help="Path to directory or repository to scan.")
    parser.add_argument("--github-token", help="GitHub token for secret scanning API (optional).")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests and exit.")
    args = parser.parse_args()

    if args.self_test:
        results = perform_self_test()
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "self-test",
            "findings": [],
            "results": results,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: target")

    overall_findings = []

    start_time = time.time()
    # 1. Scan filesystem
    if os.path.isdir(args.target):
        overall_findings.extend(walk_directory(args.target))
    elif os.path.isfile(args.target):
        overall_findings.extend(scan_file_for_keys(args.target))
    else:
        parser.error(f"Target '{args.target}' is not a valid file or directory.")

    # 2. Scan environment variables
    overall_findings.extend(scan_env_vars())

    # 3. Optional GitHub secret scanning
    if args.github_token:
        api_url = "https://api.github.com/search/code?q=api+key+in:file+language:python"
        overall_findings.extend(query_github_secret_scanning(api_url, args.github_token))

    duration = time.time() - start_time

    # Early warning checks
    warnings = []
    if error_rate_exceeds():
        warnings.append("High error rate detected during execution.")
    if duration > 2 * (len(overall_findings) + 1) * 0.5:  # rough heuristic
        warnings.append("Execution time unusually long; possible throttling or network issues.")

    status = "warning" if warnings else "ok"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": overall_findings,
        "results": {
            "duration_seconds": round(duration, 2),
            "warnings": warnings,
        },
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()