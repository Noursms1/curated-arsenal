# CATEGORY: Recon - Certificate Transparency
# PREMORTEM:
# failure_mode: API rate limiting causes HTTP 429 responses leading to incomplete data collection
# failure_mode: Unhandled JSON schema changes from the CT source break parsing logic
# failure_mode: Memory exhaustion when processing extremely large result sets for popular domains
# early_warning: Consecutive HTTP 429 or 5xx responses > 3 in a row
# early_warning: Response payload size > 5 MB or processing time > 30 seconds per request

import argparse
import json
import sys
import time
import datetime
import logging
from typing import List, Dict, Any

import requests

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
TOOL_NAME = "ct_recon"
VERSION = "1.0.0"
REQUEST_TIMEOUT = 10  # seconds
SLEEP_BETWEEN_REQUESTS = 0.5  # seconds
MAX_RETRIES = 3
MAX_ENTRIES_FOR_MEMORY_SAFETY = 50000  # safeguard against huge domains

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def safe_request(url: str, params: Dict[str, Any] = None) -> Any:
    """Perform a GET request with retries, timeout and error handling."""
    attempts = 0
    while attempts < MAX_RETRIES:
        try:
            resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 429:
                logging.warning("Rate limited (429) on %s, retrying after backoff", url)
                time.sleep(2 ** attempts)
                attempts += 1
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logging.error("Request error for %s: %s", url, e)
            attempts += 1
            time.sleep(2 ** attempts)
    raise RuntimeError(f"Failed to fetch data from {url} after {MAX_RETRIES} attempts")

def iso_to_datetime(iso_str: str) -> datetime.datetime:
    """Convert ISO8601 string to datetime, tolerant of missing timezone."""
    try:
        return datetime.datetime.fromisoformat(iso_str.rstrip("Z"))
    except ValueError:
        # Fallback for non‑standard formats
        return datetime.datetime.strptime(iso_str, "%Y-%m-%d %H:%M:%S")

def filter_recent(entries: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
    """Return entries whose not_before date is within the last `days` days."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    recent = []
    for entry in entries:
        nb = entry.get("not_before")
        if not nb:
            continue
        try:
            nb_dt = iso_to_datetime(nb)
            if nb_dt >= cutoff:
                recent.append(entry)
        except Exception:
            continue
    return recent

def domain_mismatch(entry: Dict[str, Any], target: str) -> bool:
    """Detect if the certificate does not contain the target domain in CN or SAN."""
    cn = entry.get("common_name", "").lower()
    san = entry.get("name_value", "").lower()
    target = target.lower()
    return target not in cn and target not in san

def truncate_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """If entry count exceeds safety threshold, keep only the first N and log a warning."""
    if len(entries) > MAX_ENTRIES_FOR_MEMORY_SAFETY:
        logging.warning(
            "Entry count %d exceeds safety limit %d; truncating",
            len(entries),
            MAX_ENTRIES_FOR_MEMORY_SAFETY,
        )
        return entries[:MAX_ENTRIES_FOR_MEMORY_SAFETY]
    return entries

# ----------------------------------------------------------------------
# Core Capabilities
# ----------------------------------------------------------------------
def fetch_ct_data(domain: str) -> List[Dict[str, Any]]:
    """Capability 1: Retrieve all CT log entries for a domain via crt.sh."""
    url = "https://crt.sh/"
    params = {"q": domain, "output": "json"}
    data = safe_request(url, params=params)
    if not isinstance(data, list):
        raise ValueError("Unexpected response format from crt.sh")
    return truncate_entries(data)

def recent_certificates(domain: str, days: int = 30) -> List[Dict[str, Any]]:
    """Capability 2: Identify certificates issued in the last `days` days."""
    entries = fetch_ct_data(domain)
    time.sleep(SLEEP_BETWEEN_REQUESTS)
    recent = filter_recent(entries, days)
    return recent

def mismatched_certificates(domain: str) -> List[Dict[str, Any]]:
    """Capability 3: Find certificates that do NOT contain the target domain."""
    entries = fetch_ct_data(domain)
    time.sleep(SLEEP_BETWEEN_REQUESTS)
    mismatched = [e for e in entries if domain_mismatch(e, domain)]
    return mismatched

# ----------------------------------------------------------------------
# Output Formatting
# ----------------------------------------------------------------------
def build_output(
    target: str,
    status: str,
    findings: Dict[str, Any],
    results: Dict[str, Any],
) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

# ----------------------------------------------------------------------
# Self‑Test
# ----------------------------------------------------------------------
def run_self_test() -> bool:
    """Simple sanity checks against a known domain."""
    test_domain = "example.com"
    try:
        recent = recent_certificates(test_domain, days=3650)  # 10 years should return at least one
        mismatched = mismatched_certificates(test_domain)
        assert isinstance(recent, list)
        assert isinstance(mismatched, list)
        # Basic sanity: recent list should be non‑empty for a long window
        if not recent:
            logging.error("Self‑test failed: no recent certificates found")
            return False
        # Mismatched list may be empty; just ensure no exception
        return True
    except Exception as e:
        logging.error("Self‑test exception: %s", e)
        return False

# ----------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Certificate Transparency Reconnaissance Tool")
    parser.add_argument("target", nargs="?", help="Domain to investigate")
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Look back period for recent certificates (default: 30)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        success = run_self_test()
        sys.exit(0 if success else 1)

    if not args.target:
        parser.error("the following arguments are required: target")

    target = args.target
    findings = {}
    results = {}
    status = "success"

    try:
        # Capability 1: Full CT dump (limited for safety)
        full_entries = fetch_ct_data(target)
        results["total_entries"] = len(full_entries)

        # Capability 2: Recent certificates
        recent = recent_certificates(target, days=args.days)
        findings["recent_count"] = len(recent)
        results["recent"] = [
            {
                "id": e.get("id"),
                "not_before": e.get("not_before"),
                "not_after": e.get("not_after"),
                "common_name": e.get("common_name"),
                "san": e.get("name_value"),
            }
            for e in recent
        ]

        # Capability 3: Mismatched certificates
        mismatched = mismatched_certificates(target)
        findings["mismatched_count"] = len(mismatched)
        results["mismatched"] = [
            {
                "id": e.get("id"),
                "common_name": e.get("common_name"),
                "san": e.get("name_value"),
            }
            for e in mismatched
        ]

    except Exception as exc:
        logging.exception("Fatal error during processing")
        status = "error"
        findings["error"] = str(exc)

    output = build_output(target, status, findings, results)
    print(output)


if __name__ == "__main__":
    main()