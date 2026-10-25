# CATEGORY: Recon - Wayback URLs
import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime

import requests

TOOL_NAME = "WaybackURLScanner"
VERSION = "1.0"
WAYBACK_CDX_API = "http://web.archive.org/cdx/search/cdx"


def fetch_cdx(domain):
    """
    Fetch CDX records for the given domain.
    Returns a list of dicts with keys: timestamp, original, statuscode, mimetype
    """
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
    }
    try:
        resp = requests.get(WAYBACK_CDX_API, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        # First row is header
        records = []
        for row in data[1:]:
            records.append(
                {
                    "timestamp": row[0],
                    "original": row[1],
                    "statuscode": row[2],
                    "mimetype": row[3],
                }
            )
        return records
    except Exception as e:
        return {"error": str(e)}


def get_latest_snapshot(records):
    if not records:
        return None
    latest = max(records, key=lambda r: r["timestamp"])
    return latest


def count_snapshots_per_year(records):
    counts = defaultdict(int)
    for rec in records:
        try:
            year = datetime.strptime(rec["timestamp"], "%Y%m%d%H%M%S").year
            counts[year] += 1
        except Exception:
            continue
    return dict(sorted(counts.items()))


def build_output(tool, version, target, status, findings, results):
    output = {
        "tool": tool,
        "version": version,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(output, indent=2))


def run_scan(target):
    records = fetch_cdx(target)
    time.sleep(0.5)

    if isinstance(records, dict) and "error" in records:
        build_output(
            TOOL_NAME,
            VERSION,
            target,
            "error",
            {"error": records["error"]},
            {},
        )
        return

    latest = get_latest_snapshot(records)
    yearly_counts = count_snapshots_per_year(records)

    findings = {
        "total_snapshots": len(records),
        "latest_snapshot_timestamp": latest["timestamp"] if latest else None,
        "latest_snapshot_url": latest["original"] if latest else None,
        "snapshots_per_year": yearly_counts,
    }

    # Limit detailed results to first 20 entries for brevity
    results = {
        "snapshots": records[:20],
    }

    build_output(
        TOOL_NAME,
        VERSION,
        target,
        "success",
        findings,
        results,
    )


def self_test():
    test_target = "example.com"
    records = fetch_cdx(test_target)
    time.sleep(0.5)

    if isinstance(records, dict) and "error" in records:
        status = "self-test-failed"
        findings = {"error": records["error"]}
        results = {}
    else:
        status = "self-test-passed"
        findings = {"total_snapshots": len(records)}
        results = {"sample_snapshot": records[0] if records else None}

    build_output(
        TOOL_NAME,
        VERSION,
        test_target,
        status,
        findings,
        results,
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Wayback URL reconnaissance tool")
    parser.add_argument("target", nargs="?", help="Target domain to scan")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.self_test:
        self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target domain is required unless --self-test is used.\n")
        sys.exit(1)

    run_scan(args.target)


if __name__ == "__main__":
    main()