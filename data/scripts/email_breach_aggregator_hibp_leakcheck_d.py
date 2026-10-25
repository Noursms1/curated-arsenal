#!/usr/bin/env python3
"""
CATEGORY: OSINT
TECHNIQUES: Email breach aggregation, API integration, local database search
CHAIN_CONTRIBUTIONS: Combines public breach APIs (HIBP, LeakCheck, DeHashed) with offline search for comprehensive coverage.
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

import requests

__version__ = "1.0.0"
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def rate_limited():
    """Enforce a simple rate limit between external calls."""
    time.sleep(RATE_LIMIT)


def safe_request(method: str, url: str, **kwargs) -> requests.Response:
    """Wrap requests with timeout, error handling, and rate limiting."""
    try:
        rate_limited()
        response = requests.request(method, url, timeout=TIMEOUT, **kwargs)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        raise RuntimeError(f"Request failed for {url}: {e}") from e


def query_hibp(email: str) -> Dict[str, Any]:
    """Query Have I Been Pwned API for breach data."""
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {"error": "HIBP_API_KEY not set"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "User-Agent": "EmailBreachAggregator/1.0"}
    try:
        resp = safe_request("GET", url, headers=headers)
        data = resp.json()
        return {"source": "HIBP", "breaches": data}
    except Exception as e:
        return {"source": "HIBP", "error": str(e)}


def query_leakcheck(email: str) -> Dict[str, Any]:
    """Query LeakCheck.io for breach data."""
    api_key = os.getenv("LEAKCHECK_API_KEY")
    if not api_key:
        return {"error": "LEAKCHECK_API_KEY not set"}
    url = f"https://leakcheck.io/api/v1/search"
    params = {"email": email, "key": api_key}
    try:
        resp = safe_request("GET", url, params=params)
        data = resp.json()
        return {"source": "LeakCheck", "breaches": data.get("results", [])}
    except Exception as e:
        return {"source": "LeakCheck", "error": str(e)}


def query_dehashed(email: str) -> Dict[str, Any]:
    """Query DeHashed API for breach data."""
    api_user = os.getenv("DEHASHED_USER")
    api_key = os.getenv("DEHASHED_KEY")
    if not api_user or not api_key:
        return {"error": "DEHASHED_USER or DEHASHED_KEY not set"}
    url = "https://api.dehashed.com/search"
    params = {"query": email, "size": 100}
    auth = (api_user, api_key)
    try:
        resp = safe_request("GET", url, params=params, auth=auth)
        data = resp.json()
        return {"source": "DeHashed", "breaches": data.get("entries", [])}
    except Exception as e:
        return {"source": "DeHashed", "error": str(e)}


def local_search(email: str, db_path: str = "local_breaches.json") -> Dict[str, Any]:
    """Search a local JSON file for known breaches."""
    if not os.path.isfile(db_path):
        return {"source": "Local", "error": f"{db_path} not found"}
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
        matches = [entry for entry in db if entry.get("email") == email]
        return {"source": "Local", "breaches": matches}
    except Exception as e:
        return {"source": "Local", "error": str(e)}


def aggregate_results(email: str) -> Dict[str, Any]:
    """Run all queries and build a unified JSON report."""
    results = {
        "tool": "EmailBreachAggregator",
        "version": __version__,
        "target": email,
        "status": "completed",
        "technologies": ["HIBP", "LeakCheck", "DeHashed", "LocalDB"],
        "findings": [],
        "results": {}
    }

    for func in (query_hibp, query_leakcheck, query_dehashed, local_search):
        try:
            data = func(email)
            source = data.get("source", "unknown")
            results["results"][source] = data
            if "breaches" in data and isinstance(data["breaches"], list):
                for breach in data["breaches"]:
                    name = breach.get("Name") or breach.get("title") or breach.get("source")
                    if name and name not in results["findings"]:
                        results["findings"].append(name)
        except Exception as e:
            results["results"][func.__name__] = {"error": str(e)}

    return results


def print_json(data: Dict[str, Any]) -> None:
    """Pretty‑print JSON to stdout."""
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def run_self_test() -> int:
    """Simple self‑test using mocked responses."""
    import unittest
    from unittest.mock import patch

    class SelfTest(unittest.TestCase):
        def setUp(self):
            self.email = "test@example.com"

        @patch("builtins.open", create=True)
        @patch("os.path.isfile", return_value=True)
        @patch("json.load", return_value=[{"email": "test@example.com", "info": "local breach"}])
        @patch("requests.request")
        def test_aggregate(self, mock_req, mock_json_load, mock_isfile, mock_open):
            # Mock HIBP response
            mock_req.side_effect = [
                # HIBP
                unittest.mock.Mock(status_code=200, json=lambda: [{"Name": "HIBP Breach"}]),
                # LeakCheck
                unittest.mock.Mock(status_code=200, json=lambda: {"results": [{"title": "LeakCheck Breach"}]}),
                # DeHashed
                unittest.mock.Mock(status_code=200, json=lambda: {"entries": [{"source": "DeHashed Breach"}]})
            ]
            result = aggregate_results(self.email)
            self.assertIn("HIBP", result["results"])
            self.assertIn("LeakCheck", result["results"])
            self.assertIn("DeHashed", result["results"])
            self.assertIn("Local", result["results"])
            self.assertIn("HIBP Breach", result["findings"])
            self.assertIn("LeakCheck Breach", result["findings"])
            self.assertIn("DeHashed Breach", result["findings"])
            self.assertIn("local breach", result["findings"])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest)
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate email breach data from multiple sources.")
    parser.add_argument("email", nargs="?", help="Target email address")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test suite")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    if not args.email:
        parser.error("the following arguments are required: email")
    report = aggregate_results(args.email)
    print_json(report)


if __name__ == "__main__":
    main()