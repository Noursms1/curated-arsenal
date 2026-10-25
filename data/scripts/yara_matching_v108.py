# CATEGORY: Malware

import argparse
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
import time
from pathlib import Path

try:
    import yara
except ImportError:
    sys.stderr.write("Missing required module 'yara'. Install it with pip.\n")
    sys.exit(1)

TOOL_NAME = "YaraScanner"
VERSION = "1.0.0"


def load_rules(source):
    """
    Load YARA rules from a local file or a remote URL.
    Returns a compiled yara.Rules object.
    """
    if source.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(source) as resp:
                rule_data = resp.read().decode("utf-8")
            time.sleep(0.5)
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to download rules from {source}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error downloading rules: {e}")

        try:
            compiled = yara.compile(source=rule_data)
        except yara.YaraSyntaxError as e:
            raise RuntimeError(f"YARA syntax error in downloaded rules: {e}")
    else:
        rule_path = Path(source)
        if not rule_path.is_file():
            raise RuntimeError(f"Rule file not found: {source}")
        try:
            compiled = yara.compile(filepath=str(rule_path))
        except yara.YaraSyntaxError as e:
            raise RuntimeError(f"YARA syntax error in rule file: {e}")
    return compiled


def scan_file(file_path, compiled_rules):
    """
    Scan a single file with compiled YARA rules.
    Returns a list of matched rule identifiers.
    """
    try:
        matches = compiled_rules.match(filepath=str(file_path))
        return [m.rule for m in matches]
    except yara.Error as e:
        # Non-fatal: return empty list for this file
        return []


def scan_path(target_path, compiled_rules):
    """
    Recursively scan a file or directory.
    Returns a dict: {str(file_path): [matched_rules]}
    """
    results = {}
    target = Path(target_path)
    if target.is_file():
        matches = scan_file(target, compiled_rules)
        if matches:
            results[str(target)] = matches
    elif target.is_dir():
        for root, _, files in os.walk(target):
            for name in files:
                file_path = Path(root) / name
                matches = scan_file(file_path, compiled_rules)
                if matches:
                    results[str(file_path)] = matches
    else:
        raise RuntimeError(f"Target path does not exist: {target_path}")
    return results


def generate_report(tool, version, target, status, findings, results):
    report = {
        "tool": tool,
        "version": version,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(report, indent=2))


def run_self_test():
    """
    Perform a self-test:
    - Create a temporary file containing known string.
    - Compile a simple YARA rule that matches that string.
    - Scan the file and verify detection.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.bin"
        test_content = b"This is malicious content"
        test_file.write_bytes(test_content)

        rule_text = """
rule SelfTestRule {
    strings:
        $a = "malicious"
    condition:
        $a
}
"""
        try:
            compiled = yara.compile(source=rule_text)
        except yara.YaraSyntaxError as e:
            generate_report(
                TOOL_NAME,
                VERSION,
                "self-test",
                "self-test failed",
                [],
                {"error": f"Failed to compile test rule: {e}"},
            )
            return

        results = scan_path(str(test_file), compiled)
        findings = list({rule for matches in results.values() for rule in matches})

        status = "self-test passed" if findings else "self-test failed"
        generate_report(
            TOOL_NAME,
            VERSION,
            "self-test",
            status,
            findings,
            results,
        )


def main():
    parser = argparse.ArgumentParser(description="YARA scanning tool")
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument(
        "--rules",
        required=False,
        default=None,
        help="Path or URL to YARA rules file",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self-test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target path is required unless --self-test is used.\n")
        sys.exit(1)

    if not args.rules:
        sys.stderr.write("Error: --rules argument is required.\n")
        sys.exit(1)

    try:
        compiled_rules = load_rules(args.rules)
    except Exception as e:
        generate_report(
            TOOL_NAME,
            VERSION,
            args.target,
            "error",
            [],
            {"error": str(e)},
        )
        sys.exit(1)

    try:
        results = scan_path(args.target, compiled_rules)
        findings = list({rule for matches in results.values() for rule in matches})
        status = "success"
    except Exception as e:
        generate_report(
            TOOL_NAME,
            VERSION,
            args.target,
            "error",
            [],
            {"error": str(e)},
        )
        sys.exit(1)

    generate_report(
        TOOL_NAME,
        VERSION,
        args.target,
        status,
        findings,
        results,
    )


if __name__ == "__main__":
    main()