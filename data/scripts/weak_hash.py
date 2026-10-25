# CATEGORY: Crypto
import argparse
import json
import re
import sys
import time
import requests
import os
import tempfile

TOOL_NAME = "WeakHashScanner"
VERSION = "1.0"

MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_REGEX = re.compile(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40})\b')

def scan_text_for_hashes(text):
    findings = []
    for match in MD5_REGEX.finditer(text):
        findings.append({"type": "MD5", "hash": match.group(), "position": match.start()})
    for match in SHA1_REGEX.finditer(text):
        findings.append({"type": "SHA1", "hash": match.group(), "position": match.start()})
    return findings

def fetch_url(url):
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp.text, None
    except Exception as e:
        return None, str(e)

def check_pwned_sha1(hash_value):
    # Use the k-anonymity model of haveibeenpwned for SHA1 hashes
    prefix = hash_value[:5].upper()
    suffix = hash_value[5:].upper()
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None

def process_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        hashes = scan_text_for_hashes(content)
        pwned = []
        for h in hashes:
            if h["type"] == "SHA1":
                count = check_pwned_sha1(h["hash"])
                if count is not None:
                    pwned.append({"hash": h["hash"], "pwned_count": count})
        return {"hashes": hashes, "pwned": pwned}, None
    except Exception as e:
        return None, str(e)

def process_url(url):
    page, err = fetch_url(url)
    if err:
        return None, err
    hashes = scan_text_for_hashes(page)
    pwned = []
    for h in hashes:
        if h["type"] == "SHA1":
            count = check_pwned_sha1(h["hash"])
            if count is not None:
                pwned.append({"hash": h["hash"], "pwned_count": count})
    return {"hashes": hashes, "pwned": pwned}, None

def self_test():
    # Create temporary file with known hashes
    temp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
    temp.write("This is a test file with MD5 5d41402abc4b2a76b9719d911017c592 and SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12.")
    temp.close()
    file_result, file_err = process_file(temp.name)

    # Test URL processing with a known safe page (example.com)
    url_result, url_err = process_url("https://example.com")

    os.unlink(temp.name)

    findings = []
    results = {"file_test": {}, "url_test": {}}
    if file_err:
        findings.append(f"File test error: {file_err}")
        results["file_test"]["status"] = "error"
    else:
        results["file_test"]["status"] = "success"
        results["file_test"]["hashes_found"] = len(file_result["hashes"])
        findings.extend([f"Found {h['type']} hash {h['hash']} in file." for h in file_result["hashes"]])

    if url_err:
        findings.append(f"URL test error: {url_err}")
        results["url_test"]["status"] = "error"
    else:
        results["url_test"]["status"] = "success"
        results["url_test"]["hashes_found"] = len(url_result["hashes"])
        findings.extend([f"Found {h['type']} hash {h['hash']} in URL." for h in url_result["hashes"]])

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "success" if not (file_err or url_err) else "error",
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Detect weak hash usage in files or web pages.")
    parser.add_argument("target", nargs="?", help="Path to file or URL to scan.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target provided."],
            "results": {}
        }))
        sys.exit(1)

    findings = []
    results = {}
    status = "success"

    if re.match(r'^https?://', args.target, re.IGNORECASE):
        result, err = process_url(args.target)
        if err:
            status = "error"
            findings.append(f"Error fetching URL: {err}")
            results["url"] = {"status": "error"}
        else:
            results["url"] = {"status": "success", "hashes_found": len(result["hashes"])}
            for h in result["hashes"]:
                findings.append(f"Found {h['type']} hash {h['hash']} at position {h['position']}.")
            for p in result["pwned"]:
                findings.append(f"SHA1 hash {p['hash']} appears {p['pwned_count']} times in breach data.")
    else:
        result, err = process_file(args.target)
        if err:
            status = "error"
            findings.append(f"Error reading file: {err}")
            results["file"] = {"status": "error"}
        else:
            results["file"] = {"status": "success", "hashes_found": len(result["hashes"])}
            for h in result["hashes"]:
                findings.append(f"Found {h['type']} hash {h['hash']} at position {h['position']}.")
            for p in result["pwned"]:
                findings.append(f"SHA1 hash {p['hash']} appears {p['pwned_count']} times in breach data.")

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()