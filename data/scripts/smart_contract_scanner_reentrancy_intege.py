#!/usr/bin/env python3
"""
CATEGORY: Smart Contract Security
TECHNIQUES: Static Analysis, Pattern Matching, Heuristic Detection
CHAIN_CONTRIBUTIONS: Supports Ethereum, Binance Smart Chain, Polygon, Avalanche, Fantom
"""

import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds

def rate_limited_request(url):
    """Perform a GET request with timeout and rate limiting."""
    try:
        time.sleep(RATE_LIMIT)
        req = Request(url, headers={'User-Agent': 'AutonomousForgeScanner/1.0'})
        with urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode('utf-8')
    except (URLError, HTTPError) as e:
        return None

def fetch_source_from_etherscan(address, api_key):
    """Retrieve verified Solidity source code from Etherscan-compatible APIs."""
    base = "https://api.etherscan.io/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key
    }
    url = f"{base}?{urlencode(params)}"
    data = rate_limited_request(url)
    if not data:
        return None
    try:
        obj = json.loads(data)
        if obj.get("status") != "1" or not obj.get("result"):
            return None
        source = obj["result"][0].get("SourceCode", "")
        # Etherscan may wrap source in JSON if multiple files
        if source.startswith("{") and source.endswith("}"):
            try:
                multi = json.loads(source)
                # Concatenate all files
                source = "\n".join(multi.get("sources", {}).values())
            except json.JSONDecodeError:
                pass
        return source
    except json.JSONDecodeError:
        return None

def detect_reentrancy(source):
    """Heuristic detection of reentrancy patterns."""
    findings = []
    pattern = re.compile(r"(call\.value\(|call\(|send\(|transfer\()")
    for i, line in enumerate(source.splitlines(), 1):
        if pattern.search(line):
            # Look for state changes after the call on subsequent lines
            post_lines = source.splitlines()[i:i+5]
            if any(re.search(r"\b(balance|mapping|uint|int)\b.*=", pl) for pl in post_lines):
                findings.append({
                    "type": "reentrancy",
                    "line": i,
                    "description": "Potential reentrancy: external call before state update"
                })
    return findings

def detect_integer_overflow(source):
    """Detect usage of unchecked arithmetic (pre-0.8 Solidity) or unsafe math."""
    findings = []
    unchecked_pattern = re.compile(r"\bunchecked\s*\{")
    for i, line in enumerate(source.splitlines(), 1):
        if unchecked_pattern.search(line):
            findings.append({
                "type": "integer_overflow",
                "line": i,
                "description": "Unchecked block may allow integer overflow/underflow"
            })
    # Detect usage of SafeMath absence in older versions
    if "pragma solidity ^0.7" in source or "pragma solidity ^0.6" in source:
        if not re.search(r"using\s+SafeMath\s+for", source):
            findings.append({
                "type": "integer_overflow",
                "line": 0,
                "description": "SafeMath not used in Solidity <0.8"
            })
    return findings

def detect_access_control(source):
    """Identify functions lacking access modifiers."""
    findings = []
    func_pattern = re.compile(r"function\s+(\w+)\s*\([^)]*\)\s*(public|external)?\s*(?!.*(onlyOwner|onlyAdmin|onlyRole))")
    for i, line in enumerate(source.splitlines(), 1):
        m = func_pattern.search(line)
        if m:
            func_name = m.group(1)
            findings.append({
                "type": "access_control",
                "line": i,
                "description": f"Function '{func_name}' may be missing access restriction"
            })
    return findings

def detect_unchecked_calls(source):
    """Detect low-level calls whose return values are ignored."""
    findings = []
    pattern = re.compile(r"\b(address|address\(\))\s*\.\s*(call|delegatecall|staticcall)\s*\(")
    for i, line in enumerate(source.splitlines(), 1):
        if pattern.search(line) and not re.search(r"=\s*.*\.", line):
            findings.append({
                "type": "unchecked_call",
                "line": i,
                "description": "Low-level call result not checked"
            })
    return findings

def analyze_source(source):
    """Run all detection modules and aggregate findings."""
    findings = []
    findings.extend(detect_reentrancy(source))
    findings.extend(detect_integer_overflow(source))
    findings.extend(detect_access_control(source))
    findings.extend(detect_unchecked_calls(source))
    return findings

def build_output(tool, version, target, status, technologies, findings):
    """Construct standardized JSON output."""
    result = {
        "tool": tool,
        "version": version,
        "target": target,
        "status": status,
        "technologies": technologies,
        "findings": findings,
        "results": "completed"
    }
    return json.dumps(result, indent=2)

def run_scan(address=None, source_path=None):
    target = address if address else source_path
    technologies = ["Solidity"]
    if address:
        api_key = os.getenv("ETHERSCAN_API_KEY")
        if not api_key:
            return build_output("SmartContractScanner", "1.0", target, "error", technologies,
                                [{"type": "config", "line": 0, "description": "Missing ETHERSCAN_API_KEY"}])
        source = fetch_source_from_etherscan(address, api_key)
        if not source:
            return build_output("SmartContractScanner", "1.0", target, "error", technologies,
                                [{"type": "fetch", "line": 0, "description": "Unable to retrieve source"}])
    else:
        try:
            with open(source_path, "r", encoding="utf-8") as f:
                source = f.read()
        except Exception as e:
            return build_output("SmartContractScanner", "1.0", target, "error", technologies,
                                [{"type": "io", "line": 0, "description": str(e)}])
    findings = analyze_source(source)
    status = "vulnerable" if findings else "clean"
    return build_output("SmartContractScanner", "1.0", target, status, technologies, findings)

def self_test():
    """Run a minimal self‑test using an embedded vulnerable contract."""
    vulnerable_contract = """
pragma solidity ^0.6.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        msg.sender.call.value(_amount)(); // unchecked call
        balances[msg.sender] -= _amount; // reentrancy risk
    }
    function add(uint a, uint b) public pure returns (uint) {
        unchecked {
            return a + b; // unchecked overflow
        }
    }
    function open() public {
        // no access control
    }
}
"""
    findings = analyze_source(vulnerable_contract)
    expected = {"reentrancy", "integer_overflow", "unchecked_call", "access_control"}
    detected = {f["type"] for f in findings}
    success = expected.issubset(detected)
    output = {
        "tool": "SmartContractScanner",
        "version": "1.0",
        "target": "self-test",
        "status": "pass" if success else "fail",
        "technologies": ["Solidity"],
        "findings": findings,
        "results": "self-test completed"
    }
    print(json.dumps(output, indent=2))
    sys.exit(0 if success else 1)

def main():
    parser = argparse.ArgumentParser(description="Advanced Smart Contract Security Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--address", help="Contract address to scan (requires ETHERSCAN_API_KEY)")
    group.add_argument("--source", help="Path to local Solidity source file")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()

    result_json = run_scan(address=args.address, source_path=args.source)
    print(result_json)

if __name__ == "__main__":
    main()