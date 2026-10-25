#!/usr/bin/env python3
"""
CATEGORY: Malware Analysis
TECHNIQUES: YARA rule validation, sample scanning, automated reporting
CHAIN_CONTRIBUTIONS: Integrates yara-python, requests, json, and pathlib for a secure, multi‑functional YARA testing suite.
"""

import argparse
import json
import sys
import time
import tempfile
import hashlib
from pathlib import Path
from typing import List, Dict, Any

import yara
import requests

# Constants
TOOL_NAME = "YaraForge"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10  # seconds
RATE_LIMIT = 0.5  # seconds between network requests


def rate_limited_request(method: str, url: str, **kwargs) -> requests.Response:
    """Perform a rate‑limited HTTP request."""
    time.sleep(RATE_LIMIT)
    try:
        response = requests.request(method, url, timeout=DEFAULT_TIMEOUT, **kwargs)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        raise RuntimeError(f"Network request failed for {url}: {e}") from e


def load_rules(rules_path: Path) -> yara.Rules:
    """Compile YARA rules from a file, raising on syntax errors."""
    try:
        compiled = yara.compile(filepath=str(rules_path))
        return compiled
    except yara.YaraError as e:
        raise RuntimeError(f"Failed to compile YARA rules at {rules_path}: {e}") from e


def fetch_sample(url: str, dest_dir: Path) -> Path:
    """Download a sample from a URL into dest_dir, returning the file path."""
    try:
        resp = rate_limited_request("GET", url, stream=True, verify=True)
        # Use SHA256 of URL as filename to avoid collisions
        sha = hashlib.sha256(url.encode()).hexdigest()
        out_path = dest_dir / f"{sha}.bin"
        with out_path.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return out_path
    except Exception as e:
        raise RuntimeError(f"Could not fetch sample from {url}: {e}") from e


def scan_sample(rules: yara.Rules, sample_path: Path) -> List[Dict[str, Any]]:
    """Run YARA rules against a single sample, returning match details."""
    try:
        matches = rules.match(filepath=str(sample_path))
        findings = []
        for match in matches:
            findings.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [{"offset": s[0], "identifier": s[1], "data": s[2].hex()} for s in match.strings]
            })
        return findings
    except yara.YaraError as e:
        raise RuntimeError(f"Scanning failed for {sample_path}: {e}") from e


def generate_report(
    target: List[str],
    status: str,
    findings: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Construct the standardized JSON report."""
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "technologies": ["YARA"],
        "findings": list(findings.keys()),
        "results": findings
    }


def process_inputs(
    rules_path: Path,
    sample_paths: List[Path],
    urls: List[str],
    output_path: Path
) -> None:
    """Main processing pipeline."""
    try:
        compiled_rules = load_rules(rules_path)
    except Exception as e:
        report = generate_report([], "failure", {})
        report["error"] = str(e)
        output_path.write_text(json.dumps(report, indent=2))
        sys.exit(1)

    temp_dir = None
    all_samples = list(sample_paths)  # copy
    fetched = []
    if urls:
        temp_dir = Path(tempfile.mkdtemp(prefix="yara_forge_"))
        for url in urls:
            try:
                fetched_path = fetch_sample(url, temp_dir)
                fetched.append(fetched_path)
                all_samples.append(fetched_path)
            except Exception as e:
                # Continue with other URLs, but note the error later
                report = generate_report([url], "failure", {})
                report["error"] = str(e)
                output_path.write_text(json.dumps(report, indent=2))
                sys.exit(1)

    results = {}
    for sample in all_samples:
        try:
            findings = scan_sample(compiled_rules, sample)
            results[str(sample)] = findings
        except Exception as e:
            results[str(sample)] = {"error": str(e)}

    report = generate_report(
        target=[str(p) for p in all_samples],
        status="success",
        findings=results
    )
    output_path.write_text(json.dumps(report, indent=2))

    # Cleanup temporary directory if used
    if temp_dir and temp_dir.is_dir():
        for child in temp_dir.iterdir():
            try:
                child.unlink()
            except Exception:
                pass
        try:
            temp_dir.rmdir()
        except Exception:
            pass


def self_test() -> None:
    """Run a minimal self‑test to verify core functionality."""
    with tempfile.TemporaryDirectory(prefix="yara_forge_selftest_") as td:
        td_path = Path(td)

        # Create a simple YARA rule
        rule_content = """
rule DummyRule {
    strings:
        $a = "test"
    condition:
        $a
}
"""
        rule_path = td_path / "dummy.yar"
        rule_path.write_text(rule_content)

        # Create a sample file that matches the rule
        sample_path = td_path / "sample.bin"
        sample_path.write_bytes(b"This is a test payload.")

        # Prepare output path
        out_path = td_path / "report.json"

        # Execute processing
        try:
            process_inputs(
                rules_path=rule_path,
                sample_paths=[sample_path],
                urls=[],
                output_path=out_path
            )
        except Exception as e:
            print(f"Self‑test failed during processing: {e}", file=sys.stderr)
            sys.exit(1)

        # Validate JSON structure
        try:
            report = json.loads(out_path.read_text())
            assert report["tool"] == TOOL_NAME
            assert report["status"] == "success"
            assert "DummyRule" in json.dumps(report["results"])
        except Exception as e:
            print(f"Self‑test validation error: {e}", file=sys.stderr)
            sys.exit(1)

        print("Self‑test passed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="YARA rule tester – validates rules, scans samples, and produces a standardized JSON report."
    )
    parser.add_argument("--rules", type=Path, required=False,
                        help="Path to a YARA rule file.")
    parser.add_argument("--samples", type=Path, nargs="*",
                        help="Local sample files or directories to scan.")
    parser.add_argument("--url", type=str, action="append",
                        help="Remote sample URL to download and scan. Can be repeated.")
    parser.add_argument("--output", type=Path, default=Path("yara_report.json"),
                        help="File to write the JSON report.")
    parser.add_argument("--self-test", action="store_true",
                        help="Run internal self‑test and exit.")
    return parser.parse_args()


def expand_paths(paths: List[Path]) -> List[Path]:
    """Expand directories into contained files, ignoring non‑regular files."""
    expanded = []
    for p in paths:
        if not p.exists():
            continue
        if p.is_file():
            expanded.append(p)
        elif p.is_dir():
            expanded.extend([f for f in p.rglob("*") if f.is_file()])
    return expanded


def main() -> None:
    args = parse_args()

    if args.self_test:
        self_test()
        return

    if not args.rules:
        print("Error: --rules is required unless --self-test is used.", file=sys.stderr)
        sys.exit(1)

    sample_paths = []
    if args.samples:
        sample_paths = expand_paths(args.samples)

    urls = args.url if args.url else []

    if not sample_paths and not urls:
        print("Error: No samples provided. Use --samples and/or --url.", file=sys.stderr)
        sys.exit(1)

    try:
        process_inputs(
            rules_path=args.rules,
            sample_paths=sample_paths,
            urls=urls,
            output_path=args.output
        )
        print(f"Report written to {args.output}")
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()