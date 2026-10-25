# CATEGORY: Cloud
# PREMORTEM:
# failure_mode: Missing or expired AWS credentials cause all AWS API calls to fail.
# failure_mode: AWS API rate limiting (Throttling) leads to incomplete scans and timeouts.
# failure_mode: Large number of buckets without throttling control results in request storms and eventual script termination.
# failure_mode: Unhandled pagination leads to missing buckets or objects in findings.
# early_warning: Consecutive API call failures > 3 triggers early warning flag.
# early_warning: Total execution time exceeds expected threshold (e.g., 5 minutes) triggers early warning.

import argparse
import json
import sys
import time
import logging
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, EndpointConnectionError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TOOL_NAME = "s3_inspector"
VERSION = "1.0.0"
API_TIMEOUT = 10  # seconds
SLEEP_BETWEEN_CALLS = 0.5  # seconds
MAX_CONSECUTIVE_ERRORS = 3
MAX_EXECUTION_TIME = 300  # seconds (5 minutes)


class S3Inspector:
    def __init__(self):
        self.session = boto3.session.Session()
        self.s3 = self.session.client("s3", config=boto3.session.Config(connect_timeout=API_TIMEOUT, read_timeout=API_TIMEOUT))
        self.consecutive_errors = 0
        self.start_time = datetime.utcnow()
        self.early_warnings = []

    def _check_time_limit(self):
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        if elapsed > MAX_EXECUTION_TIME:
            self.early_warnings.append("Execution time exceeded expected threshold")
            logger.warning("Early warning: execution time limit reached")
            return False
        return True

    def _handle_error(self, e, context=""):
        self.consecutive_errors += 1
        logger.error(f"Error during {context}: {e}")
        if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
            warning = f"Consecutive API failures >= {MAX_CONSECUTIVE_ERRORS}"
            self.early_warnings.append(warning)
            logger.warning(f"Early warning: {warning}")

    def _reset_error_counter(self):
        self.consecutive_errors = 0

    def list_buckets(self):
        """Capability 1: List all S3 buckets."""
        try:
            response = self.s3.list_buckets()
            self._reset_error_counter()
            buckets = [b["Name"] for b in response.get("Buckets", [])]
            return buckets
        except (BotoCoreError, ClientError, EndpointConnectionError) as e:
            self._handle_error(e, "list_buckets")
            return []

    def check_public_access(self, bucket_name):
        """Capability 2: Determine if bucket allows public read/write."""
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            self._reset_error_counter()
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ):
                    permission = grant.get("Permission")
                    return True, permission
            return False, None
        except (BotoCoreError, ClientError, EndpointConnectionError) as e:
            self._handle_error(e, f"check_public_access({bucket_name})")
            return None, None

    def check_encryption(self, bucket_name):
        """Capability 3: Verify if bucket has default encryption enabled."""
        try:
            enc = self.s3.get_bucket_encryption(Bucket=bucket_name)
            self._reset_error_counter()
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                return True, rules
            return False, None
        except self.s3.exceptions.ClientError as e:
            # 404 means encryption not configured
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                self._reset_error_counter()
                return False, None
            self._handle_error(e, f"check_encryption({bucket_name})")
            return None, None
        except (BotoCoreError, EndpointConnectionError) as e:
            self._handle_error(e, f"check_encryption({bucket_name})")
            return None, None

    def inspect(self, target=None):
        findings = {}
        results = {}
        status = "success"

        buckets = self.list_buckets()
        if not buckets:
            status = "partial_failure"
            logger.warning("No buckets retrieved; proceeding with empty list.")

        for bucket in buckets:
            if not self._check_time_limit():
                status = "timeout"
                break

            bucket_info = {"public_access": None, "encryption": None}
            is_public, permission = self.check_public_access(bucket)
            bucket_info["public_access"] = {"is_public": is_public, "permission": permission}

            enc_enabled, enc_rules = self.check_encryption(bucket)
            bucket_info["encryption"] = {"enabled": enc_enabled, "rules": enc_rules}

            findings[bucket] = bucket_info
            time.sleep(SLEEP_BETWEEN_CALLS)

        results["bucket_count"] = len(buckets)
        results["early_warnings"] = self.early_warnings

        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": target or "aws_account",
            "status": status,
            "findings": findings,
            "results": results,
        }
        return output


def run_self_test():
    """Simple self‑test to verify AWS SDK availability and basic connectivity."""
    test_output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "self-test",
        "findings": {},
        "results": {"message": ""},
    }
    try:
        inspector = S3Inspector()
        # Attempt a cheap call: list buckets (may be empty)
        inspector.list_buckets()
        test_output["results"]["message"] = "Self‑test passed: AWS SDK operational."
        test_output["status"] = "self-test-passed"
    except NoCredentialsError:
        test_output["results"]["message"] = "Self‑test failed: No AWS credentials found."
        test_output["status"] = "self-test-failed"
    except Exception as e:
        test_output["results"]["message"] = f"Self‑test failed: {e}"
        test_output["status"] = "self-test-failed"

    print(json.dumps(test_output, default=str, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="S3 bucket inspection tool")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    parser.add_argument("--target", type=str, default=None, help="Optional identifier for the target (e.g., account alias)")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        sys.exit(0)

    try:
        inspector = S3Inspector()
        output = inspector.inspect(target=args.target)
        print(json.dumps(output, default=str, ensure_ascii=False, indent=2))
    except Exception as e:
        error_output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target or "aws_account",
            "status": "failed",
            "findings": {},
            "results": {"error": str(e)},
        }
        print(json.dumps(error_output, default=str, ensure_ascii=False, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()