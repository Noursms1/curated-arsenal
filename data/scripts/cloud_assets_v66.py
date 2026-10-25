# CATEGORY: Recon
import argparse
import json
import sys
import time
from urllib.parse import quote_plus

import requests


class CloudRecon:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CloudRecon/1.0"})

    def _request(self, method, url, **kwargs):
        try:
            resp = self.session.request(method, url, timeout=10, **kwargs)
            time.sleep(0.5)
            return resp
        except requests.RequestException as e:
            self.findings.append(f"Network error for {url}: {e}")
            return None

    def _check_s3_bucket(self, bucket):
        url = f"https://{bucket}.s3.amazonaws.com"
        resp = self._request("GET", url)
        if resp and resp.status_code == 200:
            self.findings.append(f"S3 bucket public: {bucket}")
            return {"public": True, "status_code": resp.status_code}
        elif resp and resp.status_code == 403:
            return {"public": False, "status_code": resp.status_code}
        return {"public": None, "status_code": resp.status_code if resp else None}

    def _check_azure_blob(self, account):
        url = f"https://{account}.blob.core.windows.net/?restype=container&comp=list"
        resp = self._request("GET", url)
        if resp and resp.status_code == 200:
            self.findings.append(f"Azure storage account public: {account}")
            return {"public": True, "status_code": resp.status_code}
        elif resp and resp.status_code == 404:
            return {"public": False, "status_code": resp.status_code}
        return {"public": None, "status_code": resp.status_code if resp else None}

    def _check_gcp_bucket(self, bucket):
        url = f"https://storage.googleapis.com/{bucket}"
        resp = self._request("GET", url)
        if resp and resp.status_code == 200:
            self.findings.append(f"GCP bucket public: {bucket}")
            return {"public": True, "status_code": resp.status_code}
        elif resp and resp.status_code == 403:
            return {"public": False, "status_code": resp.status_code}
        return {"public": None, "status_code": resp.status_code if resp else None}

    def run(self):
        # Capability 1: Enumerate possible S3 buckets based on target
        s3_buckets = [
            f"{self.target}",
            f"{self.target}-logs",
            f"{self.target}-backup",
        ]
        s3_results = {}
        for bucket in s3_buckets:
            s3_results[bucket] = self._check_s3_bucket(bucket)
        self.results["aws_s3"] = s3_results

        # Capability 2: Enumerate possible Azure storage accounts
        azure_accounts = [
            f"{self.target}",
            f"{self.target}storage",
            f"{self.target}account",
        ]
        azure_results = {}
        for account in azure_accounts:
            azure_results[account] = self._check_azure_blob(account)
        self.results["azure_blob"] = azure_results

        # Capability 3: Enumerate possible GCP buckets
        gcp_buckets = [
            f"{self.target}",
            f"{self.target}-data",
            f"{self.target}-static",
        ]
        gcp_results = {}
        for bucket in gcp_buckets:
            gcp_results[bucket] = self._check_gcp_bucket(bucket)
        self.results["gcp_storage"] = gcp_results

        return {
            "tool": "CloudRecon",
            "version": "1.0",
            "target": self.target,
            "status": "completed",
            "findings": self.findings,
            "results": self.results,
        }


def self_test():
    test_target = "example.com"
    recon = CloudRecon(test_target)
    output = recon.run()
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Cloud assets reconnaissance tool")
    parser.add_argument("target", nargs="?", help="Target domain or identifier")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built‑in self‑test against a known public target",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps(
            {
                "tool": "CloudRecon",
                "version": "1.0",
                "target": None,
                "status": "error",
                "findings": ["No target provided"],
                "results": {},
            },
            indent=2,
        ))
        sys.exit(1)

    recon = CloudRecon(args.target)
    output = recon.run()
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()