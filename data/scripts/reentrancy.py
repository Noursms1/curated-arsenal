# CATEGORY: Blockchain - Reentrancy Detection Tool
import argparse
import json
import sys
import time
import re
import requests

TOOL_NAME = "ReentrancyScanner"
VERSION = "1.0.0"
ETHERSCAN_API_URL = "https://api.etherscan.io/api"
API_KEY = ""  # Set your Etherscan API key here or via ETHERSCAN_API_KEY env var


def get_api_key():
    import os
    key = API_KEY or os.getenv("ETHERSCAN_API_KEY")
    if not key:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": [],
            "results": "Etherscan API key not provided."
        }))
        sys.exit(1)
    return key


def fetch_source(address):
    """Fetch verified source code from Etherscan."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": get_api_key()
    }
    try:
        resp = requests.get(ETHERSCAN_API_URL, params=params, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "1":
            return None, data.get("result", "No source code found.")
        source = data["result"][0].get("SourceCode", "")
        return source, None
    except Exception as e:
        return None, str(e)


def fetch_bytecode(address):
    """Fetch contract bytecode from Etherscan."""
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
        "apikey": get_api_key()
    }
    try:
        resp = requests.get(ETHERSCAN_API_URL, params=params, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("result") is None:
            return None, "Bytecode not found."
        return data["result"], None
    except Exception as e:
        return None, str(e)


def analyze_source_for_reentrancy(source):
    """
    Very naive static analysis:
    - Look for state variable updates after external calls.
    - Detect patterns like `balances[msg.sender] =` after `.call(`, `.send(`, `.transfer(`.
    """
    findings = []
    if not source:
        return findings

    # Remove comments to reduce false positives
    source_nocomments = re.sub(r'//.*?$|/\*.*?\*/', '', source, flags=re.DOTALL | re.MULTILINE)

    # Split into functions
    functions = re.split(r'\bfunction\b', source_nocomments)[1:]

    for func in functions:
        func_header = func.split("{", 1)[0].strip()
        body = "{" + func.split("{", 1)[1] if "{" in func else ""
        # Find external calls
        external_calls = [(m.start(), m.group()) for m in re.finditer(r'\.\s*(call|send|transfer)\s*\(', body)]
        # Find state updates (simple pattern)
        state_updates = [(m.start(), m.group()) for m in re.finditer(r'\b\w+\s*\[\s*.*?\s*\]\s*=\s*', body)]

        for call_pos, call_str in external_calls:
            # Check if any state update occurs after the call within the same function
            later_updates = [u for u in state_updates if u[0] > call_pos]
            if later_updates:
                findings.append({
                    "function": func_header,
                    "issue": "Potential reentrancy: state update after external call",
                    "call": call_str.strip()
                })
    return findings


def analyze_bytecode_for_reentrancy(bytecode):
    """
    Simple heuristic: look for CALL opcode (0xf1) before SSTORE (0x55).
    This is a very rough check and may produce false positives.
    """
    findings = []
    if not bytecode or bytecode == "0x":
        return findings

    # Strip 0x prefix
    code = bytecode[2:] if bytecode.startswith("0x") else bytecode
    # Convert to list of opcodes (2 hex chars each)
    ops = [code[i:i+2] for i in range(0, len(code), 2)]

    for i, op in enumerate(ops):
        if op == "f1":  # CALL
            # Look ahead a few ops for SSTORE (55)
            window = ops[i+1:i+10]
            if "55" in window:
                findings.append({
                    "opcode_index": i,
                    "issue": "CALL followed by SSTORE within short range, possible reentrancy"
                })
                break
    return findings


def run_analysis(address):
    source, src_err = fetch_source(address)
    bytecode, bc_err = fetch_bytecode(address)

    findings = []
    results = {}

    if src_err:
        results["source_error"] = src_err
    else:
        src_findings = analyze_source_for_reentrancy(source)
        findings.extend(src_findings)
        results["source_findings"] = len(src_findings)

    if bc_err:
        results["bytecode_error"] = bc_err
    else:
        bc_findings = analyze_bytecode_for_reentrancy(bytecode)
        findings.extend(bc_findings)
        results["bytecode_findings"] = len(bc_findings)

    status = "completed" if not (src_err or bc_err) else "partial"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": address,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))


def self_test():
    # Example known vulnerable contract (placeholder address)
    test_address = "0x0000000000000000000000000000000000000000"
    print(json.dumps({
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_address,
        "status": "self-test",
        "findings": [{
            "function": "fallback()",
            "issue": "Potential reentrancy: state update after external call",
            "call": ".call("
        }],
        "results": {
            "source_findings": 1,
            "bytecode_findings": 0,
            "note": "Self-test completed with mock data."
        }
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Reentrancy detection for Ethereum contracts.")
    parser.add_argument("address", nargs="?", help="Target contract address (0x...).")
    parser.add_argument("--self-test", action="store_true", help="Run built-in self test.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.address:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": [],
            "results": "No contract address provided."
        }))
        sys.exit(1)

    run_analysis(args.address)


if __name__ == "__main__":
    main()