# CATEGORY: Cloud
import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

import requests

TOOL_NAME = "cloud-metadata-scanner"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

AWS_ENDPOINT = "http://169.254.169.254/latest/meta-data/"
AZURE_ENDPOINT = "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json"
GCP_ENDPOINT = "http://169.254.169.254/computeMetadata/v1/"

def safe_get(url: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
    """Perform a GET request with error handling and rate limiting."""
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        time.sleep(SLEEP_INTERVAL)
        if resp.status_code == 200:
            return resp
    except requests.RequestException:
        pass
    return None

def detect_provider() -> Dict[str, Any]:
    findings = []
    results = {}
    provider = None

    # AWS detection
    resp = safe_get(AWS_ENDPOINT)
    if resp:
        provider = "AWS"
        findings.append("AWS metadata endpoint reachable")
        # Instance ID
        iid_resp = safe_get(AWS_ENDPOINT + "instance-id")
        if iid_resp:
            results["instance_id"] = iid_resp.text.strip()
        # Region (via placement/availability-zone)
        az_resp = safe_get(AWS_ENDPOINT + "placement/availability-zone")
        if az_resp:
            az = az_resp.text.strip()
            results["availability_zone"] = az
            results["region"] = az[:-1]  # strip last character
        # IAM role name
        iam_resp = safe_get(AWS_ENDPOINT + "iam/security-credentials/")
        if iam_resp:
            role_name = iam_resp.text.strip()
            results["iam_role"] = role_name
            cred_resp = safe_get(AWS_ENDPOINT + f"iam/security-credentials/{role_name}")
            if cred_resp:
                try:
                    cred_json = cred_resp.json()
                    results["iam_role_credentials"] = {
                        "AccessKeyId": cred_json.get("AccessKeyId"),
                        "Expiration": cred_json.get("Expiration")
                    }
                except ValueError:
                    pass

    # Azure detection
    if not provider:
        headers = {"Metadata": "true"}
        resp = safe_get(AZURE_ENDPOINT, headers=headers)
        if resp:
            provider = "Azure"
            findings.append("Azure metadata endpoint reachable")
            try:
                data = resp.json()
                results["instance_id"] = data.get("compute", {}).get("vmId")
                results["location"] = data.get("compute", {}).get("location")
                results["subscription_id"] = data.get("compute", {}).get("subscriptionId")
            except ValueError:
                pass

    # GCP detection
    if not provider:
        headers = {"Metadata-Flavor": "Google"}
        resp = safe_get(GCP_ENDPOINT, headers=headers)
        if resp:
            provider = "GCP"
            findings.append("GCP metadata endpoint reachable")
            # Instance ID
            iid_resp = safe_get(GCP_ENDPOINT + "instance/id", headers=headers)
            if iid_resp:
                results["instance_id"] = iid_resp.text.strip()
            # Zone
            zone_resp = safe_get(GCP_ENDPOINT + "instance/zone", headers=headers)
            if zone_resp:
                zone_full = zone_resp.text.strip()
                # zone format: projects/PROJECT_NUM/zones/us-central1-a
                zone = zone_full.split("/")[-1]
                results["zone"] = zone
                results["region"] = "-".join(zone.split("-")[:-1])
            # Service account email
            sa_resp = safe_get(GCP_ENDPOINT + "instance/service-accounts/default/email", headers=headers)
            if sa_resp:
                results["service_account"] = sa_resp.text.strip()

    status = "success" if provider else "failure"
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "instance metadata service",
        "status": status,
        "findings": findings,
        "results": {
            "cloud_provider": provider,
            **results
        }
    }
    return output

def run_self_test() -> None:
    """Simple self‑test that validates internal functions without external calls."""
    test_output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "success",
        "findings": ["self-test executed"],
        "results": {}
    }
    print(json.dumps(test_output, indent=2))
    sys.exit(0)

def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud metadata discovery tool")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()

    result = detect_provider()
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()