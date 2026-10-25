# CATEGORY: OSINT - Email breach investigation tool
import sys
import argparse
import json
import hashlib
import time
import requests

TOOL_NAME = "EmailBreachOSINT"
VERSION = "1.0.0"
USER_AGENT = f"{TOOL_NAME}/{VERSION}"

def safe_request(url, headers=None, params=None):
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        return None

def check_hibp(email):
    """Check HaveIBeenPwned for breaches related to the email."""
    url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{email}"
    headers = {"User-Agent": USER_AGENT}
    resp = safe_request(url, headers=headers)
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except ValueError:
            return []
    return []

def check_gravatar(email):
    """Check if a Gravatar image exists for the email."""
    email_clean = email.strip().lower()
    md5_hash = hashlib.md5(email_clean.encode('utf-8')).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
    resp = safe_request(url)
    return resp is not None and resp.status_code == 200

def check_emailrep(email):
    """Query emailrep.io for reputation data."""
    url = f"https://emailrep.io/{email}"
    headers = {"User-Agent": USER_AGENT}
    resp = safe_request(url, headers=headers)
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except ValueError:
            return {}
    return {}

def build_output(target, status, findings, results):
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

def perform_checks(email):
    findings = []
    results = {}

    hibp_data = check_hibp(email)
    if hibp_data:
        findings.append("breach")
        results["breaches"] = hibp_data
    else:
        results["breaches"] = []

    gravatar_exists = check_gravatar(email)
    if gravatar_exists:
        findings.append("gravatar")
        results["gravatar"] = True
    else:
        results["gravatar"] = False

    emailrep_data = check_emailrep(email)
    if emailrep_data:
        findings.append("emailrep")
        results["emailrep"] = emailrep_data
    else:
        results["emailrep"] = {}

    status = "success" if findings else "no_findings"
    return status, findings, results

def self_test():
    test_email = "test@example.com"
    status, findings, results = perform_checks(test_email)
    build_output(test_email, status, findings, results)

def main():
    parser = argparse.ArgumentParser(description="Email breach OSINT tool")
    parser.add_argument("email", nargs="?", help="Target email address")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.email:
        sys.stderr.write("Error: email address required\n")
        sys.exit(1)

    status, findings, results = perform_checks(args.email)
    build_output(args.email, status, findings, results)

if __name__ == "__main__":
    main()