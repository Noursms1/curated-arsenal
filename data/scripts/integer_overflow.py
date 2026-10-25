# CATEGORY: Blockchain - Integer Overflow Detection Tool
import argparse
import json
import os
import re
import sys
import time
from typing import Dict, List, Optional

import requests

TOOL_NAME = "IntOverflowScanner"
VERSION = "1.0.0"
ETHERSCAN_API_URL = "https://api.etherscan.io/api"
DEFAULT_RPC_URL = "https://cloudflare-eth.com"  # Public RPC endpoint


def fetch_contract_source(address: str, api_key: str) -> Optional[str]:
    """Capability 1: Retrieve verified Solidity source code from Etherscan."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    try:
        time.sleep(0.5)
        response = requests.get(ETHERSCAN_API_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "1" and data.get("result"):
            source = data["result"][0].get("SourceCode", "")
            return source if source else None
    except Exception as e:
        print(f"Error fetching source for {address}: {e}", file=sys.stderr)
    return None


def fetch_contract_bytecode(address: str, rpc_url: str = DEFAULT_RPC_URL) -> Optional[str]:
    """Capability 2: Retrieve contract bytecode via JSON-RPC."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1,
    }
    headers = {"Content-Type": "application/json"}
    try:
        time.sleep(0.5)
        response = requests.post(rpc_url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()
        return result.get("result")
    except Exception as e:
        print(f"Error fetching bytecode for {address}: {e}", file=sys.stderr)
    return None


def static_analysis(source: str) -> List[str]:
    """Capability 3: Simple static analysis for unsafe integer operations."""
    findings = []
    # Detect Solidity version <0.8.0 (no built‑in overflow checks)
    version_match = re.search(r"pragma solidity\s+(\d+\.\d+\.\d+)", source)
    if version_match:
        version = version_match.group(1)
        major, minor, patch = map(int, version.split("."))
        if major < 0 or (major == 0 and minor < 8):
            findings.append(
                f"Contract uses Solidity version {version} without built‑in overflow protection."
            )
    else:
        findings.append("Unable to determine Solidity version; assume unsafe.")

    # Look for usage of unsafe arithmetic without SafeMath
    if "using SafeMath for" not in source:
        unsafe_ops = re.findall(r"\b(uint|int)[256]*\b[^;]*[+\-*/]{1}[^;]*;", source)
        if unsafe_ops:
            findings.append(
                f"Found {len(unsafe_ops)} arithmetic operations without SafeMath."
            )

    # Detect explicit require/assert checks for overflow (simple heuristic)
    overflow_checks = re.findall(r"require\([^,]*\s*>=\s*[^,]*\)", source)
    if not overflow_checks:
        findings.append("No explicit overflow checks (require/assert) detected.")

    return findings


def generate_report(
    target: str,
    source_findings: List[str],
    bytecode: Optional[str],
) -> Dict:
    status = "completed"
    findings = source_findings.copy()
    results = {}

    if bytecode:
        # Simple heuristic: check for presence of ADD (0x01) and MUL (0x02) opcodes without overflow guards
        # This is just illustrative; real analysis would be deeper.
        if "0x01" in bytecode or "0x02" in bytecode:
            findings.append("Bytecode contains arithmetic opcodes; potential overflow risk.")
        results["bytecode_length"] = len(bytecode)
    else:
        findings.append("Bytecode could not be retrieved.")

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }


def self_test() -> None:
    """Run a self‑test against a known contract (placeholder address)."""
    test_address = "0x0000000000000000000000000000000000000000"
    api_key = os.getenv("ETHERSCAN_API_KEY", "")
    source = fetch_contract_source(test_address, api_key) or ""
    bytecode = fetch_contract_bytecode(test_address) or ""
    findings = static_analysis(source) if source else ["No source code available."]
    report = generate_report(test_address, findings, bytecode)
    print(json.dumps(report, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect integer overflow issues in Ethereum contracts.")
    parser.add_argument("address", nargs="?", help="Ethereum contract address to scan.")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.address:
        print("Error: contract address required.", file=sys.stderr)
        sys.exit(1)

    address = args.address
    api_key = os.getenv("ETHERSCAN_API_KEY", "")
    if not api_key:
        print("Warning: ETHERSCAN_API_KEY not set; source code retrieval may fail.", file=sys.stderr)

    source = fetch_contract_source(address, api_key)
    source_findings = static_analysis(source) if source else ["Source code not available."]
    bytecode = fetch_contract_bytecode(address)

    report = generate_report(address, source_findings, bytecode)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()