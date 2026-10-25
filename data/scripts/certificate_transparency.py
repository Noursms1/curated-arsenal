# CATEGORY: Recon - Certificate Transparency
import argparse
import json
import sys
import time
import datetime
import requests

TOOL_NAME = "ct_recon"
VERSION = "1.0"

def fetch_crtsh(domain):
    """Fetch certificates from crt.sh for the given domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        time.sleep(0.5)
        return data
    except Exception as e:
        return {"error": str(e)}

def fetch_certspotter(domain):
    """Fetch certificates from CertSpotter for the given domain."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {"Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        time.sleep(0.5)
        return data
    except Exception as e:
        return {"error": str(e)}

def filter_recent(certificates, days=30):
    """Return certificates issued within the last `days` days."""
    recent = []
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    for cert in certificates:
        try:
            issued_str = cert.get("not_before") or cert.get("issued_at")
            if not issued_str:
                continue
            # Parse ISO8601 or other common formats
            try:
                issued = datetime.datetime.strptime(issued_str, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                issued = datetime.datetime.strptime(issued_str, "%Y-%m-%d %H:%M:%S")
            if issued >= cutoff:
                recent.append(cert)
        except Exception:
            continue
    return recent

def extract_subdomains(certificates):
    """Extract unique subdomains from certificate entries."""
    subs = set()
    for cert in certificates:
        dns_names = cert.get("dns_names") or cert.get("name_value")
        if isinstance(dns_names, list):
            for name in dns_names:
                subs.add(name.lower())
        elif isinstance(dns_names, str):
            for name in dns_names.splitlines():
                subs.add(name.lower())
    return sorted(subs)

def run_recon(target):
    findings = {}
    results = {}

    # Capability 1: crt.sh enumeration
    crtsh_data = fetch_crtsh(target)
    if isinstance(crtsh_data, dict) and "error" in crtsh_data:
        findings["crtsh_error"] = crtsh_data["error"]
        results["crtsh"] = []
    else:
        findings["crtsh_total"] = len(crtsh_data)
        recent = filter_recent(crtsh_data)
        findings["crtsh_recent_30d"] = len(recent)
        results["crtsh"] = recent

    # Capability 2: CertSpotter enumeration
    certspotter_data = fetch_certspotter(target)
    if isinstance(certspotter_data, dict) and "error" in certspotter_data:
        findings["certspotter_error"] = certspotter_data["error"]
        results["certspotter"] = []
    else:
        findings["certspotter_total"] = len(certspotter_data)
        recent = filter_recent(certspotter_data)
        findings["certspotter_recent_30d"] = len(recent)
        results["certspotter"] = recent

    # Capability 3: Subdomain extraction from both sources
    combined = []
    if isinstance(crtsh_data, list):
        combined.extend(crtsh_data)
    if isinstance(certspotter_data, list):
        combined.extend(certspotter_data)
    subdomains = extract_subdomains(combined)
    findings["unique_subdomains"] = len(subdomains)
    results["subdomains"] = subdomains

    status = "completed" if not (findings.get("crtsh_error") or findings.get("certspotter_error")) else "partial"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

def self_test():
    """Run a quick self‑test against a known domain."""
    test_target = "example.com"
    print(f"Running self‑test against {test_target} ...")
    run_recon(test_target)

def main():
    parser = argparse.ArgumentParser(description="Certificate Transparency reconnaissance tool")
    parser.add_argument("-t", "--target", help="Target domain (e.g., example.com)")
    parser.add_argument("--self-test", action="store_true", help="Execute built‑in self test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target domain is required unless --self-test is used.\n")
        sys.exit(1)

    run_recon(args.target)

if __name__ == "__main__":
    main()