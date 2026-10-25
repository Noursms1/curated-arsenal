# CATEGORY: Cloud
import argparse
import json
import sys
import time
import boto3
from botocore.exceptions import BotoCoreError, ClientError

TOOL_NAME = "s3_audit_tool"
VERSION = "1.0"

def safe_call(func, *args, **kwargs):
    """Wrap boto3 calls with try/except and sleep."""
    try:
        response = func(*args, **kwargs)
        time.sleep(0.5)
        return response, None
    except (BotoCoreError, ClientError) as e:
        time.sleep(0.5)
        return None, str(e)

def get_account_id(sts_client):
    resp, err = safe_call(sts_client.get_caller_identity)
    if err:
        return "unknown", f"Failed to get account ID: {err}"
    return resp.get("Account", "unknown"), None

def list_buckets(s3_client):
    resp, err = safe_call(s3_client.list_buckets)
    if err:
        return [], f"Failed to list buckets: {err}"
    buckets = [b["Name"] for b in resp.get("Buckets", [])]
    return buckets, None

def get_public_access_block(s3_client, bucket):
    resp, err = safe_call(s3_client.get_public_access_block, Bucket=bucket)
    if err:
        return None, err
    return resp.get("PublicAccessBlockConfiguration", {}), None

def get_encryption(s3_client, bucket):
    resp, err = safe_call(s3_client.get_bucket_encryption, Bucket=bucket)
    if err:
        # If the error is that encryption is not configured, treat as None
        if isinstance(err, str) and "ServerSideEncryptionConfigurationNotFoundError" in err:
            return None, None
        return None, err
    return resp.get("ServerSideEncryptionConfiguration", {}), None

def count_objects(s3_client, bucket):
    paginator = s3_client.get_paginator('list_objects_v2')
    try:
        total = 0
        for page in paginator.paginate(Bucket=bucket):
            time.sleep(0.5)
            total += page.get('KeyCount', 0)
        return total, None
    except (BotoCoreError, ClientError) as e:
        return None, str(e)

def run_audit(region):
    findings = []
    results = {"buckets": []}
    session_kwargs = {}
    if region:
        session_kwargs["region_name"] = region
    session = boto3.Session(**session_kwargs)

    sts = session.client('sts')
    s3 = session.client('s3')

    account_id, err = get_account_id(sts)
    if err:
        findings.append(err)

    bucket_names, err = list_buckets(s3)
    if err:
        findings.append(err)
        return {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": account_id,
            "status": "error",
            "findings": findings,
            "results": results
        }

    for bucket in bucket_names:
        bucket_info = {"name": bucket}
        # Public Access Block
        pab, err = get_public_access_block(s3, bucket)
        if err:
            findings.append(f"{bucket}: {err}")
            bucket_info["public_access_block"] = "error"
        else:
            bucket_info["public_access_block"] = pab

        # Encryption
        enc, err = get_encryption(s3, bucket)
        if err:
            findings.append(f"{bucket}: {err}")
            bucket_info["encryption"] = "error"
        else:
            bucket_info["encryption"] = enc if enc else "not_enabled"

        # Object count
        count, err = count_objects(s3, bucket)
        if err:
            findings.append(f"{bucket}: {err}")
            bucket_info["object_count"] = "error"
        else:
            bucket_info["object_count"] = count

        results["buckets"].append(bucket_info)

    status = "completed" if not findings else "completed_with_issues"
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": account_id,
        "status": status,
        "findings": findings,
        "results": results
    }

def self_test():
    findings = []
    try:
        boto3.client('sts')
        findings.append("boto3 import and client creation succeeded")
        status = "success"
    except Exception as e:
        findings.append(f"self-test failed: {e}")
        status = "failure"
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": status,
        "findings": findings,
        "results": {}
    }
    print(json.dumps(output, indent=2))
    sys.exit(0 if status == "success" else 1)

def main():
    parser = argparse.ArgumentParser(description="S3 bucket audit tool")
    parser.add_argument("--region", help="AWS region to use")
    parser.add_argument("--self-test", action="store_true", help="Run self-test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()

    audit_result = run_audit(args.region)
    print(json.dumps(audit_result, indent=2))

if __name__ == "__main__":
    main()