# CATEGORY: Recon - Cloud assets enumeration tool
import argparse
import json
import sys
import time
import requests
import re

TOOL_NAME = "CloudRecon"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

def safe_get(url, params=None, headers=None):
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        return resp
    except Exception as e:
        return e

def check_s3_bucket(bucket_name):
    url = f"https://{bucket_name}.s3.amazonaws.com"
    params = {"list-type": "2"}
    resp = safe_get(url, params=params)
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    if resp.status_code == 200:
        return {"public": True, "status_code": resp.status_code}
    elif resp.status_code == 403:
        return {"public": False, "status_code": resp.status_code}
    else:
        return {"public": None, "status_code": resp.status_code}

def enumerate_crtsh(domain):
    url = "https://crt.sh/"
    params = {"q": f"%25.{domain}", "output": "json"}
    resp = safe_get(url, params=params)
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    try:
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return {"subdomains": sorted(subdomains)}
    except Exception as e:
        return {"error": str(e)}

def check_azure_storage(account_name):
    url = f"https://{account_name}.blob.core.windows.net"
    params = {"restype": "container", "comp": "list"}
    resp = safe_get(url, params=params)
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    if resp.status_code == 200:
        return {"public": True, "status_code": resp.status_code}
    elif resp.status_code == 404:
        return {"public": False, "status_code": resp.status_code}
    else:
        return {"public": None, "status_code": resp.status_code}

def run_recon(target):
    findings = []
    results = {}

    # Capability 1: S3 bucket check
    bucket_name = target.replace(".", "-")
    s3_result = check_s3_bucket(bucket_name)
    results["s3_bucket_check"] = s3_result
    if isinstance(s3_result, dict) and s3_result.get("public") is True:
        findings.append(f"S3 bucket '{bucket_name}' is publicly accessible.")
    elif isinstance(s3_result, dict) and s3_result.get("public") is False:
        findings.append(f"S3 bucket '{bucket_name}' exists but is not public.")
    else:
        findings.append(f"S3 bucket check error: {s3_result.get('error', 'unknown')}")

    # Capability 2: crt.sh subdomain enumeration
    crtsh_result = enumerate_crtsh(target)
    results["crtsh_subdomains"] = crtsh_result
    if isinstance(crtsh_result, dict) and "subdomains" in crtsh_result:
        count = len(crtsh_result["subdomains"])
        findings.append(f"Found {count} subdomains via crt.sh.")
    else:
        findings.append(f"crt.sh enumeration error: {crtsh_result.get('error', 'unknown')}")

    # Capability 3: Azure storage account check
    azure_name = re.sub(r'[^a-z0-9]', '', target.split('.')[0].lower())
    azure_result = check_azure_storage(azure_name)
    results["azure_storage_check"] = azure_result
    if isinstance(azure_result, dict) and azure_result.get("public") is True:
        findings.append(f"Azure storage account '{azure_name}' is publicly accessible.")
    elif isinstance(azure_result, dict) and azure_result.get("public") is False:
        findings.append(f"Azure storage account '{azure_name}' is not public or does not exist.")
    else:
        findings.append(f"Azure storage check error: {azure_result.get('error', 'unknown')}")

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": "completed",
        "findings": findings,
        "results": results
    }

def self_test():
    test_target = "example.com"
    output = run_recon(test_target)
    output["status"] = "self-test passed" if "error" not in json.dumps(output) else "self-test failed"
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Cloud assets reconnaissance tool")
    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target provided."],
            "results": {}
        }, indent=2))
        sys.exit(1)

    output = run_recon(args.target)
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()