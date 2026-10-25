# CATEGORY: Cloud
import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

import requests

TOOL_NAME = "cloud-metadata-scanner"
VERSION = "1.0.0"

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def safe_get(url: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
    """
    Perform a GET request with error handling and a short delay.
    """
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp
    except requests.RequestException:
        time.sleep(0.5)
        return None


def fetch_aws_metadata() -> Dict[str, Any]:
    base = "http://169.254.169.254/latest/meta-data/"
    keys = ["instance-id", "instance-type", "placement/availability-zone", "ami-id"]
    data = {}
    for key in keys:
        resp = safe_get(base + key)
        if resp and resp.text:
            data[key.replace("/", "-")] = resp.text.strip()
    # IAM role detection
    iam_role_resp = safe_get(base + "iam/security-credentials/")
    if iam_role_resp and iam_role_resp.text:
        role_name = iam_role_resp.text.strip()
        cred_resp = safe_get(base + f"iam/security-credentials/{role_name}")
        if cred_resp and cred_resp.text:
            data["iam-role"] = role_name
            data["iam-credentials"] = cred_resp.json()
    return data


def fetch_azure_metadata() -> Dict[str, Any]:
    url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json"
    headers = {"Metadata": "true"}
    resp = safe_get(url, headers=headers)
    if not resp:
        return {}
    try:
        meta = resp.json()
    except ValueError:
        return {}
    # Extract a few useful fields
    data = {
        "vmId": meta.get("compute", {}).get("vmId"),
        "location": meta.get("compute", {}).get("location"),
        "vmSize": meta.get("compute", {}).get("vmSize"),
        "subscriptionId": meta.get("compute", {}).get("subscriptionId"),
    }
    # Managed identity token endpoint test
    token_url = "http://169.254.169.254/metadata/identity/oauth2/token"
    token_params = {"api-version": "2018-02-01", "resource": "https://management.azure.com/"}
    token_resp = safe_get(token_url, headers=headers)
    if token_resp and token_resp.text:
        data["managed-identity-token"] = token_resp.text.strip()
    return data


def fetch_gcp_metadata() -> Dict[str, Any]:
    base = "http://metadata.google.internal/computeMetadata/v1/"
    headers = {"Metadata-Flavor": "Google"}
    keys = ["instance/id", "instance/machine-type", "instance/zone", "project/project-id"]
    data = {}
    for key in keys:
        resp = safe_get(base + key, headers=headers)
        if resp and resp.text:
            clean_key = key.replace("/", "-")
            data[clean_key] = resp.text.strip()
    # Service account token
    token_resp = safe_get(base + "instance/service-accounts/default/token", headers=headers)
    if token_resp and token_resp.text:
        try:
            data["service-account-token"] = token_resp.json()
        except ValueError:
            data["service-account-token"] = token_resp.text.strip()
    return data


def detect_provider() -> str:
    """
    Simple heuristic to decide which provider is reachable.
    """
    # Try AWS first
    if safe_get("http://169.254.169.254/latest/meta-data/"):
        return "aws"
    # Azure
    if safe_get("http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json", headers={"Metadata": "true"}):
        return "azure"
    # GCP
    if safe_get("http://metadata.google.internal/computeMetadata/v1/", headers={"Metadata-Flavor": "Google"}):
        return "gcp"
    return "unknown"


def run_scan() -> Dict[str, Any]:
    provider = detect_provider()
    findings: List[str] = []
    results: Dict[str, Any] = {}

    if provider == "aws":
        results = fetch_aws_metadata()
        findings.append("AWS metadata retrieved")
    elif provider == "azure":
        results = fetch_azure_metadata()
        findings.append("Azure metadata retrieved")
    elif provider == "gcp":
        results = fetch_gcp_metadata()
        findings.append("GCP metadata retrieved")
    else:
        findings.append("No known cloud metadata endpoint reachable")
        results = {}

    status = "success" if results else "failed"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "local-instance",
        "status": status,
        "findings": findings,
        "results": results,
    }
    return output


def self_test() -> bool:
    """
    Minimal self‑test: ensure that helper functions behave as expected
    when endpoints are unreachable (they should return empty structures)
    and that JSON output contains required keys.
    """
    # Mock unreachable by pointing to an invalid address (handled internally)
    original_get = requests.get

    def mock_get(*args, **kwargs):
        raise requests.ConnectionError

    requests.get = mock_get
    try:
        out = run_scan()
    finally:
        requests.get = original_get

    required_keys = {"tool", "version", "target", "status", "findings", "results"}
    return isinstance(out, dict) and required_keys.issubset(out.keys())


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud metadata discovery tool")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        success = self_test()
        result = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "self-test",
            "status": "success" if success else "failed",
            "findings": ["self-test passed"] if success else ["self-test failed"],
            "results": {},
        }
        print(json.dumps(result, indent=2))
        sys.exit(0 if success else 1)

    output = run_scan()
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()