# CATEGORY: Malware - YARA Matching Tool
import argparse
import json
import os
import sys
import time
import urllib.request
import tempfile
import yara

TOOL_NAME = "YaraScanner"
VERSION = "1.0.0"

def load_local_rules(rules_dir):
    rule_files = {}
    if not os.path.isdir(rules_dir):
        return None, f"Rules directory '{rules_dir}' not found."
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.lower().endswith(('.yar', '.yara')):
                path = os.path.join(root, f)
                rule_files[f] = path
    if not rule_files:
        return None, f"No YARA rule files found in '{rules_dir}'."
    try:
        compiled = yara.compile(filepaths=rule_files)
        return compiled, None
    except yara.YaraError as e:
        return None, f"Failed to compile YARA rules: {e}"

def fetch_remote_rule(url):
    try:
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
            time.sleep(0.5)  # throttle
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".yar")
        with os.fdopen(tmp_fd, "wb") as tmp_file:
            tmp_file.write(data)
        return tmp_path, None
    except Exception as e:
        return None, f"Error fetching remote rule: {e}"

def scan_path(compiled_rules, target_path):
    findings = []
    results = {}
    if os.path.isfile(target_path):
        matches = compiled_rules.match(filepath=target_path)
        for m in matches:
            findings.append(m.rule)
            results[m.rule] = {"meta": m.meta, "strings": [(s[0], s[1].decode(errors='ignore') if isinstance(s[1], bytes) else s[1]) for s in m.strings]}
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in files:
                file_path = os.path.join(root, f)
                try:
                    matches = compiled_rules.match(filepath=file_path)
                    for m in matches:
                        findings.append(m.rule)
                        results.setdefault(m.rule, {"files": []})["files"].append(file_path)
                except Exception:
                    continue
    else:
        return None, None, f"Target '{target_path}' is not a file or directory."
    return findings, results, None

def self_test():
    test_rule = b'''
rule DummyTest {
    strings:
        $a = "dummy_test_string"
    condition:
        $a
}
'''
    try:
        compiled = yara.compile(source=test_rule.decode())
    except yara.YaraError as e:
        return False, f"Self-test compile failed: {e}"
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        tmp.write("this file contains dummy_test_string for testing")
        tmp_path = tmp.name
    try:
        matches = compiled.match(filepath=tmp_path)
        os.unlink(tmp_path)
        if any(m.rule == "DummyTest" for m in matches):
            return True, None
        else:
            return False, "Self-test rule did not match expected string."
    except Exception as e:
        return False, f"Self-test execution error: {e}"

def main():
    parser = argparse.ArgumentParser(description="YARA matching utility")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--file", help="Path to a single file to scan")
    group.add_argument("--dir", help="Path to a directory to scan recursively")
    parser.add_argument("--rules-dir", default="rules", help="Local directory containing YARA rules")
    parser.add_argument("--rules-url", help="Remote URL to download additional YARA rule")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test")
    args = parser.parse_args()

    if args.self_test:
        passed, error = self_test()
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "self-test",
            "status": "success" if passed else "error",
            "findings": [],
            "results": {"self_test_passed": passed, "error": error}
        }
        print(json.dumps(output, indent=2))
        sys.exit(0)

    target = args.file or args.dir
    if not target:
        parser.error("Either --file or --dir must be specified.")

    # Load local rules
    compiled_rules, err = load_local_rules(args.rules_dir)
    if err:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": target,
            "status": "error",
            "findings": [],
            "results": {"error": err}
        }
        print(json.dumps(output, indent=2))
        sys.exit(1)

    # Fetch remote rule if requested
    if args.rules_url:
        remote_path, fetch_err = fetch_remote_rule(args.rules_url)
        if fetch_err:
            output = {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": target,
                "status": "error",
                "findings": [],
                "results": {"error": fetch_err}
            }
            print(json.dumps(output, indent=2))
            sys.exit(1)
        try:
            remote_compiled = yara.compile(filepath=remote_path)
            compiled_rules = yara.compile(sources={**compiled_rules._sources, **remote_compiled._sources})
        except yara.YaraError as e:
            output = {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": target,
                "status": "error",
                "findings": [],
                "results": {"error": f"Failed to compile remote rule: {e}"}
            }
            print(json.dumps(output, indent=2))
            sys.exit(1)
        finally:
            os.unlink(remote_path)

    findings, results, scan_err = scan_path(compiled_rules, target)
    if scan_err:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": target,
            "status": "error",
            "findings": [],
            "results": {"error": scan_err}
        }
    else:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": target,
            "status": "success",
            "findings": findings,
            "results": results
        }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()