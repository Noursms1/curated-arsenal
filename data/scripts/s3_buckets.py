# CATEGORY: Cloud - S3 Bucket Security Tool
import argparse
import json
import sys
import time
import boto3
from botocore.exceptions import BotoCoreError, ClientError

TOOL_NAME = "s3sec"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

def safe_call(func, *args, **kwargs):
    """Wrap boto3 calls with try/except and sleep."""
    try:
        result = func(*args, **kwargs)
        time.sleep(SLEEP_INTERVAL)
        return result, None
    except (BotoCoreError, ClientError) as e:
        time.sleep(SLEEP_INTERVAL)
        return None, str(e)

def list_buckets():
    client = boto3.client('s3')
    resp, err = safe_call(client.list_buckets)
    if err:
        return [], [f"Error listing buckets: {err}"]
    buckets = [b['Name'] for b in resp.get('Buckets', [])]
    return buckets, []

def list_objects(bucket):
    client = boto3.client('s3')
    paginator = client.get_paginator('list_objects_v2')
    objects = []
    findings = []
    try:
        for page in paginator.paginate(Bucket=bucket):
            time.sleep(SLEEP_INTERVAL)
            for obj in page.get('Contents', []):
                objects.append(obj['Key'])
    except (BotoCoreError, ClientError) as e:
        findings.append(f"Error listing objects in {bucket}: {e}")
    return objects, findings

def check_public_access(bucket):
    client = boto3.client('s3')
    findings = []
    public = False

    # Check ACL
    acl_resp, err = safe_call(client.get_bucket_acl, Bucket=bucket)
    if err:
        findings.append(f"ACL check failed: {err}")
    else:
        for grant in acl_resp.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public = True
                findings.append("Bucket ACL grants public read/write")
                break

    # Check bucket policy for public statements
    policy_resp, err = safe_call(client.get_bucket_policy, Bucket=bucket)
    if err and "NoSuchBucketPolicy" not in err:
        findings.append(f"Policy check failed: {err}")
    elif policy_resp:
        try:
            policy = json.loads(policy_resp['Policy'])
            for stmt in policy.get('Statement', []):
                principal = stmt.get('Principal')
                effect = stmt.get('Effect')
                if effect == 'Allow' and principal == '*':
                    public = True
                    findings.append("Bucket policy allows public access")
                    break
        except json.JSONDecodeError as e:
            findings.append(f"Failed to parse bucket policy: {e}")

    # Check Block Public Access settings
    bpa_resp, err = safe_call(client.get_public_access_block, Bucket=bucket)
    if err:
        findings.append(f"PublicAccessBlock check failed: {err}")
    else:
        config = bpa_resp.get('PublicAccessBlockConfiguration', {})
        if not all(config.get(k, False) for k in [
            'BlockPublicAcls',
            'IgnorePublicAcls',
            'BlockPublicPolicy',
            'RestrictPublicBuckets']):
            findings.append("Public Access Block not fully enabled")
            public = True

    return {"public": public}, findings

def get_encryption(bucket):
    client = boto3.client('s3')
    resp, err = safe_call(client.get_bucket_encryption, Bucket=bucket)
    if err:
        if "ServerSideEncryptionConfigurationNotFoundError" in err:
            return {"encrypted": False}, []
        return {"encrypted": None}, [f"Encryption check error: {err}"]
    rules = resp.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
    encrypted = len(rules) > 0
    return {"encrypted": encrypted, "rules": rules}, []

def perform_self_test():
    result = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "success",
        "findings": [],
        "results": {}
    }
    # Test boto3 client creation
    try:
        boto3.client('s3')
    except Exception as e:
        result["status"] = "error"
        result["findings"].append(f"Boto3 client creation failed: {e}")
        return result

    # Test list_buckets (may fail without credentials, treat as pass if permission error)
    buckets, findings = list_buckets()
    result["results"]["buckets_accessible"] = bool(buckets) or any("AccessDenied" in f for f in findings)
    result["findings"].extend(findings)
    return result

def main():
    parser = argparse.ArgumentParser(description="S3 bucket security assessment tool")
    parser.add_argument("--bucket", help="Target S3 bucket name")
    parser.add_argument("--list-objects", action="store_true", help="List objects in the bucket")
    parser.add_argument("--check-public", action="store_true", help="Check if bucket is publicly accessible")
    parser.add_argument("--encryption", action="store_true", help="Check bucket encryption status")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        output = perform_self_test()
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if not args.bucket:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No bucket specified"],
            "results": {}
        }, indent=2))
        sys.exit(1)

    overall_findings = []
    overall_results = {}
    status = "success"

    if args.list_objects:
        objs, findings = list_objects(args.bucket)
        overall_results["objects"] = objs
        overall_findings.extend(findings)

    if args.check_public:
        pub_info, findings = check_public_access(args.bucket)
        overall_results["public_access"] = pub_info
        overall_findings.extend(findings)

    if args.encryption:
        enc_info, findings = get_encryption(args.bucket)
        overall_results["encryption"] = enc_info
        overall_findings.extend(findings)

    if not (args.list_objects or args.check_public or args.encryption):
        overall_findings.append("No operation specified")
        status = "error"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.bucket,
        "status": status,
        "findings": overall_findings,
        "results": overall_results
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()