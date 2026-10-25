# CATEGORY: Blockchain - Reentrancy Detection Tool
import argparse
import json
import os
import re
import sys
import time
from typing import List, Dict, Any

import requests

TOOL_NAME = "ReentrancyScanner"
VERSION = "1.0.0"
ETHERSCAN_API_URL = "https://api.etherscan.io/api"
DEFAULT_TIMEOUT = 10  # seconds


def fetch_contract_source(address: str, api_key: str) -> str:
    """Fetch verified Solidity source code from Etherscan."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    try:
        response = requests.get(ETHERSCAN_API_URL, params=params, timeout=DEFAULT_TIMEOUT)
        time.sleep(0.5)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "1" or not data.get("result"):
            raise ValueError(f"Etherscan error: {data.get('message')}")
        source = data["result"][0].get("SourceCode", "")
        if source.startswith("{") and source.endswith("}"):
            # Handle standard JSON metadata wrapper
            try:
                meta = json.loads(source)
                source = meta.get("sources", {}).get("Main.sol", {}).get("content", "")
            except json.JSONDecodeError:
                pass
        return source
    except Exception as e:
        raise RuntimeError(f"Failed to fetch source for {address}: {e}") from e


def extract_functions(source: str) -> List[Dict[str, Any]]:
    """Very naive Solidity function extractor."""
    pattern = re.compile(
        r"function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(public|external|internal|private)?\s*(payable)?\s*(.*?){",
        re.DOTALL,
    )
    functions = []
    for match in pattern.finditer(source):
        name = match.group(1)
        start = match.start()
        # Find function body by matching braces
        brace_count = 1
        i = match.end()
        while i < len(source) and brace_count > 0:
            if source[i] == "{":
                brace_count += 1
            elif source[i] == "}":
                brace_count -= 1
            i += 1
        body = source[match.end() : i - 1]
        functions.append({"name": name, "body": body, "start_index": start})
    return functions


def detect_reentrancy_patterns(func: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect simple reentrancy patterns: external call before state change."""
    findings = []
    lines = func["body"].splitlines()
    state_change_regex = re.compile(r"\b\w+\s*=\s*[^;]+;")
    external_call_regex = re.compile(
        r"\b(?:call|callcode|delegatecall|staticcall|transfer|send)\b"
    )
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if external_call_regex.search(stripped):
            # Look ahead for state change within the same function after this line
            for later_line in lines[idx + 1 :]:
                if state_change_regex.search(later_line):
                    findings.append(
                        {
                            "type": "reentrancy",
                            "function": func["name"],
                            "line": idx + 1,
                            "code": stripped,
                            "description": "External call before state change",
                        }
                    )
                    break
    return findings


def analyze_source(source: str) -> List[Dict[str, Any]]:
    """Run static analysis on Solidity source."""
    findings = []
    functions = extract_functions(source)
    for func in functions:
        func_findings = detect_reentrancy_patterns(func)
        findings.extend(func_findings)
    return findings


def format_output(
    target: str,
    status: str,
    findings: List[Dict[str, Any]],
    results: Dict[str, Any],
) -> str:
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    return json.dumps(output, indent=2)


def run_scan(address: str, api_key: str) -> str:
    try:
        source = fetch_contract_source(address, api_key)
        if not source:
            raise RuntimeError("No source code available")
        findings = analyze_source(source)
        status = "completed"
        results = {"source_length": len(source), "function_count": len(extract_functions(source))}
        return format_output(address, status, findings, results)
    except Exception as e:
        error_output = format_output(
            address,
            "error",
            [{"error": str(e)}],
            {},
        )
        return error_output


def self_test() -> None:
    """Run a built‑in test on a hard‑coded vulnerable contract."""
    vulnerable_source = """
    pragma solidity ^0.8.0;
    contract Vulnerable {
        mapping(address => uint) public balances;
        function withdraw(uint _amount) public {
            require(balances[msg.sender] >= _amount);
            (bool success,) = msg.sender.call{value:_amount}("");
            require(success);
            balances[msg.sender] -= _amount;
        }
    }
    """
    findings = analyze_source(vulnerable_source)
    status = "completed"
    results = {"source_length": len(vulnerable_source), "function_count": len(extract_functions(vulnerable_source))}
    print(format_output("self-test", status, findings, results))


def main() -> None:
    parser = argparse.ArgumentParser(description="Reentrancy detection tool for Ethereum contracts.")
    parser.add_argument("address", nargs="?", help="Target contract address (hex).")
    parser.add_argument(
        "--api-key",
        default=os.getenv("ETHERSCAN_API_KEY"),
        help="Etherscan API key (or set ETHERSCAN_API_KEY env var).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built‑in self‑test and exit.",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.address:
        print("Error: contract address required unless --self-test is used.", file=sys.stderr)
        sys.exit(1)

    if not args.api_key:
        print("Error: Etherscan API key required via --api-key or ETHERSCAN_API_KEY env var.", file=sys.stderr)
        sys.exit(1)

    output = run_scan(args.address, args.api_key)
    print(output)


if __name__ == "__main__":
    main()