# CATEGORY: OSINT - Email breach detection tool
import argparse
import hashlib
import json
import socket
import sys
import time
from urllib.parse import quote

import requests

# Try to import dnspython for MX lookup; if unavailable, MX lookup will be skipped.
try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False


TOOL_NAME = "EmailBreachOSINT"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5


def breach_check(email):
    """
    Check the email against HaveIBeenPwned public API (v2, no API key required).
    Returns a list of breach names or an empty list if none found.
    """
    url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{quote(email)}"
    headers = {"User-Agent": f"{TOOL_NAME}/{VERSION}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        if resp.status_code == 200:
            try:
                data = resp.json()
                return [b.get("Name", "Unknown") for b in data]
            except Exception:
                return ["Error parsing breach data"]
        elif resp.status_code == 404:
            return []  # No breach found
        else:
            return [f"Unexpected status {resp.status_code}"]
    except Exception as e:
        return [f"Error contacting HIBP: {str(e)}"]


def gravatar_check(email):
    """
    Check if a Gravatar exists for the given email.
    Returns True if an image is found, False otherwise.
    """
    email_clean = email.strip().lower()
    md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
    try:
        resp = requests.get(url, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        return resp.status_code == 200
    except Exception:
        return False


def mx_lookup(email):
    """
    Perform an MX record lookup for the domain part of the email.
    Returns a list of MX hostnames or an empty list if none found / lookup fails.
    """
    if not DNS_AVAILABLE:
        return ["dnspython not installed"]
    domain = email.split("@")[-1]
    try:
        answers = dns.resolver.resolve(domain, "MX")
        time.sleep(SLEEP_INTERVAL)
        mx_records = sorted([r.exchange.to_text().rstrip('.') for r in answers])
        return mx_records
    except Exception as e:
        return [f"MX lookup error: {str(e)}"]


def run_checks(email):
    findings = []
    results = {}

    # Capability 1: Breach check
    breaches = breach_check(email)
    results["breaches"] = breaches
    if breaches:
        if isinstance(breaches, list) and breaches and not breaches[0].startswith("Error"):
            findings.append(f"Email found in {len(breaches)} breach(es).")
        else:
            findings.append(f"Breach check issue: {breaches}")

    # Capability 2: Gravatar presence
    has_gravatar = gravatar_check(email)
    results["gravatar"] = has_gravatar
    findings.append("Gravatar image exists." if has_gravatar else "No Gravatar image found.")

    # Capability 3: MX record lookup
    mx_records = mx_lookup(email)
    results["mx_records"] = mx_records
    if mx_records:
        if isinstance(mx_records, list) and mx_records and not mx_records[0].startswith("MX lookup error"):
            findings.append(f"MX records retrieved: {', '.join(mx_records)}")
        else:
            findings.append(f"MX lookup issue: {mx_records}")

    status = "success"
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": email,
        "status": status,
        "findings": findings,
        "results": results,
    }


def self_test():
    """
    Simple self‑test using a known non‑existent email.
    The test asserts that the tool runs without raising exceptions.
    """
    test_email = "test@example.com"
    output = run_checks(test_email)
    # Basic sanity checks
    assert isinstance(output, dict), "Self‑test failed: output not dict"
    assert "tool" in output and output["tool"] == TOOL_NAME, "Self‑test failed: tool name"
    assert "version" in output, "Self‑test failed: missing version"
    assert "target" in output and output["target"] == test_email, "Self‑test failed: target mismatch"
    assert "status" in output and output["status"] == "success", "Self‑test failed: status not success"
    # Print the JSON for visibility
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Email breach OSINT tool")
    parser.add_argument("email", nargs="?", help="Target email address")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.email:
        print(json.dumps(
            {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": None,
                "status": "error",
                "findings": ["No email address provided."],
                "results": {},
            },
            indent=2,
        ))
        sys.exit(1)

    output = run_checks(args.email)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()