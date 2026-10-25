# CATEGORY: Cloud
# PREMORTEM:
# failure_mode: Metadata service becomes unreachable due to network partition, causing the tool to hang or crash.
# failure_mode: Unexpected response format leads to JSON serialization errors, causing the tool to exit with traceback.
# failure_mode: Rate limiting or request storms trigger HTTP 429, leading to incomplete findings.
# early_warning: Increase in request latency >2 seconds or repeated HTTP error status codes.

import argparse
import json
import sys
import time
import requests

TOOL_NAME = "cloud-metadata-inspector"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 5  # seconds
SLEEP_BETWEEN_REQUESTS = 0.5  # seconds

AWS_ENDPOINT = "http://169.254.169.254/latest/meta-data/"
GCP_ENDPOINT = "http://metadata.google.internal/computeMetadata/v1/"
AZURE_ENDPOINT = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

HEADERS = {
    "Metadata-Flavor": "Google",  # GCP requires this header
    "User-Agent": f"{TOOL_NAME}/{VERSION}"
}


def safe_get(url, headers=None, params=None):
    """Perform a GET request with timeout, error handling and rate‑limit back‑off."""
    try:
        resp = requests.get(
            url,
            headers=headers or {},
            params=params or {},
            timeout=DEFAULT_TIMEOUT,
        )
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        resp.raise_for_status()
        return resp
    except requests.exceptions.RequestException as e:
        return e


def fetch_aws_metadata():
    findings = {}
    base = AWS_ENDPOINT
    # Retrieve a short list of common metadata keys
    keys = ["instance-id", "instance-type", "local-ipv4", "public-ipv4", "iam/security-credentials/"]
    for key in keys:
        url = f"{base}{key}"
        resp = safe_get(url)
        if isinstance(resp, Exception):
            findings[key] = {"error": str(resp)}
            continue
        # IAM credentials endpoint returns a directory; handle specially
        if key.endswith("/"):
            # List available IAM roles
            role_name = resp.text.strip()
            cred_url = f"{base}{key}{role_name}"
            cred_resp = safe_get(cred_url)
            if isinstance(cred_resp, Exception):
                findings[key] = {"error": str(cred_resp)}
            else:
                try:
                    findings[key] = json.loads(cred_resp.text)
                except json.JSONDecodeError:
                    findings[key] = {"raw": cred_resp.text}
        else:
            findings[key] = resp.text.strip()
    return findings


def fetch_gcp_metadata():
    findings = {}
    base = GCP_ENDPOINT
    keys = [
        "instance/id",
        "instance/machine-type",
        "instance/network-interfaces/0/ip",
        "instance/service-accounts/",
    ]
    for key in keys:
        url = f"{base}{key}"
        resp = safe_get(url, headers={"Metadata-Flavor": "Google"})
        if isinstance(resp, Exception):
            findings[key] = {"error": str(resp)}
            continue
        if key.endswith("/"):
            # Service accounts list
            accounts = resp.text.strip().splitlines()
            acct_info = {}
            for acct in accounts:
                acct_url = f"{base}{key}{acct}/email"
                acct_resp = safe_get(acct_url, headers={"Metadata-Flavor": "Google"})
                if isinstance(acct_resp, Exception):
                    acct_info[acct] = {"error": str(acct_resp)}
                else:
                    acct_info[acct] = {"email": acct_resp.text.strip()}
            findings[key] = acct_info
        else:
            findings[key] = resp.text.strip()
    return findings


def fetch_azure_metadata():
    findings = {}
    url = AZURE_ENDPOINT
    params = {"api-version": "2021-02-01"}
    headers = {"Metadata": "true"}
    resp = safe_get(url, headers=headers, params=params)
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from Azure metadata service"}
    # Extract a few useful fields
    for field in ["compute", "network"]:
        if field in data:
            findings[field] = data[field]
    return findings


def detect_provider():
    """Attempt to detect the cloud provider by probing known endpoints."""
    # Order matters: Azure and AWS share the same IP, but Azure requires a header.
    # Probe Azure first.
    azure_test = safe_get(AZURE_ENDPOINT, headers={"Metadata": "true"}, params={"api-version": "2021-02-01"})
    if not isinstance(azure_test, Exception) and azure_test.status_code == 200:
        return "azure"
    aws_test = safe_get(AWS_ENDPOINT)
    if not isinstance(aws_test, Exception) and aws_test.status_code == 200:
        return "aws"
    gcp_test = safe_get(GCP_ENDPOINT, headers={"Metadata-Flavor": "Google"})
    if not isinstance(gcp_test, Exception) and gcp_test.status_code == 200:
        return "gcp"
    return "unknown"


def run_self_test():
    """Basic self‑test to ensure each fetch function handles errors gracefully."""
    results = {}
    for provider, func in [("aws", fetch_aws_metadata),
                           ("gcp", fetch_gcp_metadata),
                           ("azure", fetch_azure_metadata)]:
        try:
            findings = func()
            results[provider] = {"status": "ok", "findings": findings}
        except Exception as e:
            results[provider] = {"status": "failed", "error": str(e)}
    return results


def main():
    parser = argparse.ArgumentParser(description="Cloud metadata inspection tool")
    parser.add_argument(
        "--target",
        choices=["aws", "gcp", "azure", "auto"],
        default="auto",
        help="Cloud provider to query (default: auto-detect)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑tests and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        test_results = run_self_test()
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "self-test",
            "status": "completed",
            "findings": "self-test results",
            "results": test_results,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    if args.target == "auto":
        provider = detect_provider()
    else:
        provider = args.target

    if provider == "unknown":
        status = "failed"
        findings = {"error": "Unable to detect cloud provider"}
        results = {}
    else:
        try:
            if provider == "aws":
                findings = fetch_aws_metadata()
            elif provider == "gcp":
                findings = fetch_gcp_metadata()
            elif provider == "azure":
                findings = fetch_azure_metadata()
            else:
                findings = {"error": f"Unsupported provider: {provider}"}
            status = "completed"
            results = {"provider": provider}
        except Exception as e:
            status = "failed"
            findings = {"error": str(e)}
            results = {}

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": provider,
        "status": status,
        "findings": "metadata collection",
        "results": {
            "findings": findings,
            **results,
        },
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()