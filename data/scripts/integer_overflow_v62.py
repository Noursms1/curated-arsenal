# CATEGORY: Blockchain - Integer Overflow Detection Tool
import argparse
import json
import re
import sys
import time
from typing import List, Dict, Any

import requests

TOOL_NAME = "IntOverflowScanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5
ETHERSCAN_API = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "YourApiKeyToken"  # Replace with a valid API key or set via env


def fetch_contract_source(address: str) -> str:
    """Fetch verified Solidity source code from Etherscan."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    }
    try:
        response = requests.get(ETHERSCAN_API, params=params, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "1" and data.get("result"):
            return data["result"][0].get("SourceCode", "")
    except Exception as e:
        return ""
    return ""


def fetch_contract_bytecode(address: str) -> str:
    """Fetch contract bytecode via Etherscan."""
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
        "apikey": ETHERSCAN_API_KEY,
    }
    try:
        response = requests.get(ETHERSCAN_API, params=params, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        response.raise_for_status()
        data = response.json()
        if data.get("result"):
            return data["result"]
    except Exception:
        return ""
    return ""


def analyze_source_code(source: str) -> List[Dict[str, Any]]:
    """Detect unsafe integer operations in Solidity source."""
    findings = []
    # Simple regex patterns for unsafe arithmetic
    patterns = {
        "addition": r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\w+);",
        "subtraction": r"\b(\w+)\s*=\s*(\w+)\s*-\s*(\w+);",
        "multiplication": r"\b(\w+)\s*=\s*(\w+)\s*\*\s*(\w+);",
        "division": r"\b(\w+)\s*=\s*(\w+)\s*\/\s*(\w+);",
    }
    for op, pattern in patterns.items():
        for match in re.finditer(pattern, source):
            line_no = source[: match.start()].count("\n") + 1
            findings.append(
                {
                    "type": "unsafe_{}".format(op),
                    "description": f"Potential integer overflow/underflow in {op} operation.",
                    "line": line_no,
                    "code": match.group(0).strip(),
                }
            )
    return findings


def analyze_bytecode(bytecode: str) -> List[Dict[str, Any]]:
    """Very basic heuristic: look for arithmetic opcodes without overflow checks."""
    findings = []
    # Opcodes for ADD, SUB, MUL, DIV (0x01, 0x03, 0x02, 0x04)
    # This is a placeholder; real analysis would be more complex.
    unsafe_ops = {"01": "ADD", "02": "MUL", "03": "SUB", "04": "DIV"}
    for opcode, name in unsafe_ops.items():
        if opcode in bytecode:
            findings.append(
                {
                    "type": "bytecode_unsafe_{}".format(name.lower()),
                    "description": f"Bytecode contains {name} opcode which may be unsafe without checks.",
                }
            )
    return findings


def simulate_overflow(address: str) -> List[Dict[str, Any]]:
    """Attempt to trigger overflow via a JSON-RPC call to a local node."""
    findings = []
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": address,
                "data": "0x",  # Placeholder: actual function selector + max uint256 args needed
            },
            "latest",
        ],
        "id": 1,
    }
    try:
        response = requests.post("http://127.0.0.1:8545", json=payload, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        response.raise_for_status()
        result = response.json()
        if "error" in result:
            findings.append(
                {
                    "type": "simulation_error",
                    "description": f"Simulation error: {result['error'].get('message')}",
                }
            )
        else:
            # If call succeeded, we can't be sure; just note that simulation ran.
            findings.append(
                {
                    "type": "simulation_success",
                    "description": "Simulation executed without RPC error (overflow not detected).",
                }
            )
    except Exception as e:
        findings.append(
            {
                "type": "simulation_exception",
                "description": f"Exception during simulation: {str(e)}",
            }
        )
    return findings


def run_analysis(target: str, is_address: bool) -> Dict[str, Any]:
    findings = []
    results = {}

    if is_address:
        source = fetch_contract_source(target)
        if source:
            src_findings = analyze_source_code(source)
            findings.extend(src_findings)
            results["source_analysis"] = {"found": len(src_findings)}
        else:
            results["source_analysis"] = {"found": 0, "note": "Source not verified or unavailable"}

        bytecode = fetch_contract_bytecode(target)
        if bytecode:
            byte_findings = analyze_bytecode(bytecode)
            findings.extend(byte_findings)
            results["bytecode_analysis"] = {"found": len(byte_findings)}
        else:
            results["bytecode_analysis"] = {"found": 0, "note": "Bytecode fetch failed"}

        sim_findings = simulate_overflow(target)
        findings.extend(sim_findings)
        results["simulation"] = {"found": len(sim_findings)}
    else:
        try:
            with open(target, "r", encoding="utf-8") as f:
                source = f.read()
            src_findings = analyze_source_code(source)
            findings.extend(src_findings)
            results["source_file_analysis"] = {"found": len(src_findings)}
        except Exception as e:
            results["source_file_analysis"] = {"found": 0, "error": str(e)}

    status = "completed"
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }


def self_test() -> bool:
    """Run minimal internal tests to verify functionality."""
    test_source = """
    pragma solidity ^0.8.0;
    contract Test {
        function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
            uint256 c = a + b;
            return c;
        }
    }
    """
    findings = analyze_source_code(test_source)
    return any(f["type"] == "unsafe_addition" for f in findings)


def main():
    parser = argparse.ArgumentParser(description="Integer overflow detection tool for blockchain contracts.")
    parser.add_argument("target", help="Contract address (0x...) or path to Solidity source file.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests and exit.")
    args = parser.parse_args()

    if args.self_test:
        passed = self_test()
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "self-test",
            "status": "self-test",
            "findings": [],
            "results": {"self_test_passed": passed},
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if passed else 1)

    is_address = bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", args.target.strip()))
    report = run_analysis(args.target, is_address)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()