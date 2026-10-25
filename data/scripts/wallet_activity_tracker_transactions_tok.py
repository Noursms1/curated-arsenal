#!/usr/bin/env python3
"""
CATEGORY: Blockchain - Recon
TECHNIQUES: API Integration, Transaction Analysis, DeFi Interaction Mapping, Risk Scoring
CHAIN_CONTRIBUTIONS: Supports Ethereum and Binance Smart Chain via public APIs
"""

import argparse
import json
import sys
import time
import logging
from typing import Dict, Any, List, Optional

import requests

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

# Constants
REQUEST_TIMEOUT = 10  # seconds
RATE_LIMIT_DELAY = 0.5  # seconds between API calls
ETHERSCAN_API_KEY = "YourEtherscanAPIKey"  # Replace with a valid key or set via env
BSCSCAN_API_KEY = "YourBscScanAPIKey"      # Replace with a valid key or set via env

# Simple in-memory list of known malicious addresses (example)
MALICIOUS_ADDRESSES = {
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "0xbadc0ffee0ddf00ddeadbeefdeadbeefdeadbeef",
}


def rate_limited_get(url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Perform a GET request with timeout and rate limiting."""
    try:
        time.sleep(RATE_LIMIT_DELAY)
        response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"GET request failed for {url}: {e}")
        return None


def fetch_transactions(address: str, chain: str) -> List[Dict[str, Any]]:
    """Fetch recent normal transactions for the address."""
    if chain == "eth":
        base = "https://api.etherscan.io/api"
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": ETHERSCAN_API_KEY,
        }
    elif chain == "bsc":
        base = "https://api.bscscan.com/api"
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": BSCSCAN_API_KEY,
        }
    else:
        logging.error(f"Unsupported chain for transactions: {chain}")
        return []

    data = rate_limited_get(base, params)
    if data and data.get("status") == "1":
        return data.get("result", [])
    return []


def fetch_token_holdings(address: str, chain: str) -> List[Dict[str, Any]]:
    """Fetch ERC20/BEP20 token balances."""
    if chain == "eth":
        base = "https://api.etherscan.io/api"
        params = {
            "module": "account",
            "action": "tokenbalance",
            "address": address,
            "tag": "latest",
            "apikey": ETHERSCAN_API_KEY,
        }
    elif chain == "bsc":
        base = "https://api.bscscan.com/api"
        params = {
            "module": "account",
            "action": "tokenbalance",
            "address": address,
            "tag": "latest",
            "apikey": BSCSCAN_API_KEY,
        }
    else:
        logging.error(f"Unsupported chain for token holdings: {chain}")
        return []

    # Etherscan/BscScan tokenbalance returns a single token balance; for full portfolio we use tokenlist endpoint
    # Use tokenlist endpoint (account tokenlist) if available
    if chain == "eth":
        base = "https://api.etherscan.io/api"
        params = {
            "module": "account",
            "action": "tokenlist",
            "address": address,
            "apikey": ETHERSCAN_API_KEY,
        }
    else:
        base = "https://api.bscscan.com/api"
        params = {
            "module": "account",
            "action": "tokenlist",
            "address": address,
            "apikey": BSCSCAN_API_KEY,
        }

    data = rate_limited_get(base, params)
    if data and data.get("status") == "1":
        return data.get("result", [])
    return []


def fetch_defi_interactions(address: str, chain: str) -> List[Dict[str, Any]]:
    """Detect interactions with known DeFi contracts (simple heuristic)."""
    # For demonstration, we use a static list of popular DeFi contract addresses per chain
    known_defi_contracts = {
        "eth": {
            "UniswapV2Router": "0x7a250d5630b4cf539739df2c5dacab0c5e5a6a6c",
            "AaveLendingPool": "0x7d2768dE32b0b80b7a3454c06BdAc2c5f3F2fD1",
            "CompoundComptroller": "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b",
        },
        "bsc": {
            "PancakeSwapRouter": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
            "VenusComptroller": "0xfD36E2c2a6789Db23113685031d7F16329158384",
        },
    }

    contracts = known_defi_contracts.get(chain, {})
    interactions = []

    txs = fetch_transactions(address, chain)
    for tx in txs:
        to_addr = tx.get("to", "").lower()
        for name, defi_addr in contracts.items():
            if to_addr == defi_addr.lower():
                interactions.append({
                    "protocol": name,
                    "tx_hash": tx.get("hash"),
                    "timestamp": tx.get("timeStamp"),
                })
    return interactions


def compute_risk_score(transactions: List[Dict[str, Any]],
                      token_holdings: List[Dict[str, Any]],
                      defi_interactions: List[Dict[str, Any]]) -> float:
    """Simple heuristic risk scoring."""
    tx_count = len(transactions)
    defi_count = len(defi_interactions)
    malicious_tx = sum(1 for tx in transactions if tx.get("to", "").lower() in MALICIOUS_ADDRESSES)

    # Token risk: count of tokens with known high-risk flags (placeholder)
    risky_tokens = sum(1 for token in token_holdings if token.get("symbol", "").upper() in {"SCAM", "FAKE"})

    # Weighted score (0-10)
    score = (
        min(tx_count / 1000, 1) * 2 +          # up to 2 points for activity volume
        min(defi_count / 50, 1) * 3 +         # up to 3 points for DeFi usage
        min(malicious_tx / 5, 1) * 4 +        # up to 4 points for malicious interactions
        min(risky_tokens / 5, 1) * 1          # up to 1 point for risky tokens
    )
    return round(min(score, 10), 2)


def build_output(tool: str, version: str, target: str, status: str,
                 technologies: List[str], findings: Dict[str, Any],
                 results: Dict[str, Any]) -> str:
    """Serialize standardized JSON."""
    output = {
        "tool": tool,
        "version": version,
        "target": target,
        "status": status,
        "technologies": technologies,
        "findings": findings,
        "results": results,
    }
    return json.dumps(output, indent=2)


def run_tracker(address: str, chain: str) -> str:
    """Main workflow for wallet activity tracking."""
    try:
        transactions = fetch_transactions(address, chain)
        token_holdings = fetch_token_holdings(address, chain)
        defi_interactions = fetch_defi_interactions(address, chain)
        risk_score = compute_risk_score(transactions, token_holdings, defi_interactions)

        findings = {
            "transaction_count": len(transactions),
            "token_holdings_count": len(token_holdings),
            "defi_interactions": defi_interactions,
            "risk_score": risk_score,
        }

        results = {
            "transactions": transactions,
            "tokens": token_holdings,
        }

        return build_output(
            tool="WalletActivityTracker",
            version="1.0.0",
            target=address,
            status="completed",
            technologies=[chain.upper()],
            findings=findings,
            results=results,
        )
    except Exception as e:
        logging.error(f"Unexpected error in run_tracker: {e}")
        return build_output(
            tool="WalletActivityTracker",
            version="1.0.0",
            target=address,
            status="error",
            technologies=[chain.upper()],
            findings={"error": str(e)},
            results={},
        )


def self_test() -> bool:
    """Perform a lightweight self‑test using a known address."""
    test_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"  # Known large holder
    output = run_tracker(test_address, "eth")
    try:
        data = json.loads(output)
        return (
            data.get("status") == "completed"
            and data["findings"].get("transaction_count", 0) > 0
        )
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wallet Activity Tracker")
    parser.add_argument("--address", help="Target wallet address (hex)", required=False)
    parser.add_argument("--chain", choices=["eth", "bsc"], default="eth", help="Blockchain network")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.self_test:
        success = self_test()
        sys.exit(0 if success else 1)

    if not args.address:
        logging.error("Address is required unless running --self-test")
        sys.exit(1)

    output = run_tracker(args.address, args.chain)
    print(output)


if __name__ == "__main__":
    main()