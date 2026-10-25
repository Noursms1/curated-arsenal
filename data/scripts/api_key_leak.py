# CATEGORY: API
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

TOOL_NAME = "api_key_leak_scanner"
VERSION = "1.0.0"

# Regex patterns for common API keys
API_KEY_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe Live Secret": r"sk_live_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Generic Secret": r"(?i)secret[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9\-_]{20,}[\"']?",
}

def find_keys_in_text(text):
    findings = []
    for name, pattern in API_KEY_PATTERNS.items():
        for match in re.finditer(pattern, text):
            findings.append({"type": name, "value": match.group(0)})
    return findings

def scan_url(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(0.5)
        if resp.status_code == 200:
            findings.extend(find_keys_in_text(resp.text))
        else:
            return {"error": f"HTTP {resp.status_code}"}, []
    except Exception as e:
        return {"error": str(e)}, []
    return None, findings

def scan_github_repo(repo):
    findings = []
    api_url = f"https://api.github.com/repos/{repo}/git/trees/main?recursive=1"
    try:
        resp = requests.get(api_url, timeout=10)
        time.sleep(0.5)
        if resp.status_code != 200:
            return {"error": f"GitHub API returned {resp.status_code}"}, []
        tree = resp.json().get("tree", [])
        for item in tree:
            if item.get("type") != "blob":
                continue
            raw_url = f"https://raw.githubusercontent.com/{repo}/main/{item['path']}"
            try:
                file_resp = requests.get(raw_url, timeout=10)
                time.sleep(0.5)
                if file_resp.status_code == 200:
                    file_findings = find_keys_in_text(file_resp.text)
                    for f in file_findings:
                        f["file"] = item["path"]
                    findings.extend(file_findings)
            except Exception:
                continue
    except Exception as e:
        return {"error": str(e)}, []
    return None, findings

def scan_directory(path):
    findings = []
    for root, _, files in os.walk(path):
        for fname in files:
            fpath = Path(root) / fname
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                file_findings = find_keys_in_text(content)
                for f in file_findings:
                    f["file"] = str(fpath)
                findings.extend(file_findings)
            except Exception:
                continue
    return findings

def self_test():
    test_string = """
    This is a test file containing an AWS key AKIA1234567890ABCD and a Google key AIzaSyA-ExampleKey1234567890abcdefg.
    """
    expected = {"AWS Access Key": "AKIA1234567890ABCD", "Google API Key": "AIzaSyA-ExampleKey1234567890abcdefg"}
    results = find_keys_in_text(test_string)
    passed = all(any(r["type"] == k and r["value"] == v for r in results) for k, v in expected.items())
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "success" if passed else "failure",
        "findings": results if not passed else [],
        "results": {"passed": passed, "detected": len(results)}
    }

def main():
    parser = argparse.ArgumentParser(description="Detect leaked API keys.")
    parser.add_argument("--target", help="Target to scan (URL, GitHub repo 'owner/repo', or directory path).")
    parser.add_argument("--type", choices=["url", "github", "dir"], help="Type of target.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test.")
    args = parser.parse_args()

    if args.self_test:
        output = self_test()
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if not args.target or not args.type:
        parser.error("Both --target and --type are required unless --self-test is used.")

    overall_findings = []
    error_info = None

    if args.type == "url":
        error_info, findings = scan_url(args.target)
        overall_findings.extend(findings)
    elif args.type == "github":
        error_info, findings = scan_github_repo(args.target)
        overall_findings.extend(findings)
    elif args.type == "dir":
        overall_findings = scan_directory(args.target)

    status = "success" if not error_info else "error"
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": overall_findings,
        "results": {
            "total_findings": len(overall_findings),
            "error": error_info.get("error") if error_info else None
        }
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()