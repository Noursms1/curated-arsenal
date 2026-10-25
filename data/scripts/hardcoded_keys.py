# CATEGORY: Crypto
import argparse
import os
import re
import json
import sys
import time
import requests
import tempfile
import shutil

TOOL_NAME = "hardcoded-key-scanner"
VERSION = "1.0.0"

HEX_KEY_REGEX = re.compile(r'\b0x[0-9a-fA-F]{32,}\b')
HEX_ONLY_REGEX = re.compile(r'\b[0-9a-fA-F]{32,}\b')
BASE64_REGEX = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')
COMMON_KEY_NAMES = re.compile(r'\b(API_KEY|SECRET|TOKEN|PRIVATE_KEY|PUBLIC_KEY|PASS|PASSWORD)\b', re.IGNORECASE)

def find_keys_in_text(text):
    findings = []
    for pattern, label in [
        (HEX_KEY_REGEX, "hex_key"),
        (HEX_ONLY_REGEX, "hex_key"),
        (BASE64_REGEX, "base64_key")
    ]:
        for match in pattern.finditer(text):
            findings.append({"type": label, "value": match.group()})
    return findings

def scan_file(path):
    findings = []
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
            findings.extend(find_keys_in_text(content))
    except Exception:
        pass
    return findings

def scan_directory(root_path):
    findings = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            findings.extend(scan_file(file_path))
    return findings

def scan_url(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(0.5)
        if resp.status_code == 200:
            findings.extend(find_keys_in_text(resp.text))
    except Exception:
        pass
    return findings

def scan_env():
    findings = []
    for key, value in os.environ.items():
        if COMMON_KEY_NAMES.search(key):
            if HEX_KEY_REGEX.search(value) or HEX_ONLY_REGEX.search(value) or BASE64_REGEX.search(value):
                findings.append({"type": "env_key", "env_var": key, "value": value})
    return findings

def run_self_test():
    test_results = {"status": "passed", "details": []}
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a file with a hardcoded key
        test_file_path = os.path.join(temp_dir, "test.py")
        with open(test_file_path, "w") as f:
            f.write('API_KEY = "0x1234567890abcdef1234567890abcdef"\n')
            f.write('secret = "c2VjcmV0X2tleV9iYXNlNjQ="  # base64\n')
        file_findings = scan_file(test_file_path)
        if len(file_findings) >= 2:
            test_results["details"].append("File scan detection passed")
        else:
            test_results["status"] = "failed"
            test_results["details"].append("File scan detection failed")

        # Mock a simple HTTP server using httpbin.org (public) for URL scan
        url_findings = scan_url("https://httpbin.org/anything?key=0xabcdef1234567890abcdef1234567890")
        if any(f["type"] == "hex_key" for f in url_findings):
            test_results["details"].append("URL scan detection passed")
        else:
            test_results["status"] = "failed"
            test_results["details"].append("URL scan detection failed")

        # Set an env var with a key
        os.environ["TEST_SECRET"] = "c2VjcmV0X2Vudg=="  # base64
        env_findings = scan_env()
        if any(f["type"] == "env_key" for f in env_findings):
            test_results["details"].append("Env scan detection passed")
        else:
            test_results["status"] = "failed"
            test_results["details"].append("Env scan detection failed")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return test_results

def main():
    parser = argparse.ArgumentParser(description="Detect hardcoded cryptographic keys.")
    parser.add_argument("target", nargs="?", help="File, directory, or URL to scan")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests")
    args = parser.parse_args()

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target if args.target else "",
        "status": "success",
        "findings": [],
        "results": {}
    }

    if args.self_test:
        test_res = run_self_test()
        output["status"] = test_res["status"]
        output["results"] = test_res
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if not args.target:
        output["status"] = "error"
        output["results"] = {"error": "No target provided"}
        print(json.dumps(output, indent=2))
        sys.exit(1)

    all_findings = []

    # Capability 1: Scan directory or file
    if os.path.isdir(args.target):
        all_findings.extend(scan_directory(args.target))
    elif os.path.isfile(args.target):
        all_findings.extend(scan_file(args.target))
    else:
        # Capability 2: Scan URL
        all_findings.extend(scan_url(args.target))

    # Capability 3: Scan environment variables
    all_findings.extend(scan_env())

    output["findings"] = all_findings
    output["results"] = {"total_findings": len(all_findings)}
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()