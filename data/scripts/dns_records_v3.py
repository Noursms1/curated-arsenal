# CATEGORY: Recon
# PREMORTEM:
# failure_mode: Unhandled dns.exception.Timeout leading to crash during bulk queries
# failure_mode: Missing or malformed DNS response causing KeyError when accessing answer sections
# failure_mode: Rate limiting or network throttling causing long delays and eventual script timeout
# early_warning: Consecutive DNS timeout count exceeds threshold (>=3)
# early_warning: Unexpected empty result set for a record type that usually exists (e.g., A for well‑known domains)

import argparse
import json
import sys
import time
import logging
from collections import defaultdict

import dns.resolver
import dns.exception

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
TOOL_NAME = "dns_recon"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 5.0  # seconds for each DNS query
SLEEP_BETWEEN_QUERIES = 0.5  # seconds
MAX_CONSECUTIVE_TIMEOUTS = 3   # early warning threshold

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def _resolve(domain: str, rtype: str, resolver: dns.resolver.Resolver):
    """
    Resolve a single DNS record type for a domain.
    Returns a list of string representations of the answers.
    Handles all dns exceptions and returns an empty list on failure.
    """
    try:
        answer = resolver.resolve(domain, rtype, lifetime=DEFAULT_TIMEOUT)
        records = [r.to_text() for r in answer]
        return records, None
    except dns.exception.Timeout as e:
        logging.warning(f"Timeout while resolving {rtype} for {domain}: {e}")
        return [], "timeout"
    except dns.resolver.NoAnswer:
        logging.info(f"No answer for {rtype} record on {domain}")
        return [], "no_answer"
    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain does not exist: {domain}")
        return [], "nxdomain"
    except dns.resolver.NoNameservers as e:
        logging.error(f"No nameservers could be reached for {domain}: {e}")
        return [], "no_nameservers"
    except Exception as e:
        logging.exception(f"Unexpected error resolving {rtype} for {domain}: {e}")
        return [], "unexpected"

def _perform_queries(domain: str, record_types):
    """
    Perform DNS queries for the given record types.
    Returns a dict mapping record type -> list of records,
    and a dict of any errors encountered.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DEFAULT_TIMEOUT
    results = defaultdict(list)
    errors = {}
    consecutive_timeouts = 0

    for rtype in record_types:
        records, err = _resolve(domain, rtype, resolver)
        if err == "timeout":
            consecutive_timeouts += 1
            if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                logging.warning(
                    f"Early warning: {consecutive_timeouts} consecutive DNS timeouts."
                )
        else:
            consecutive_timeouts = 0  # reset on any non-timeout result

        if records:
            results[rtype] = records
        if err:
            errors[rtype] = err

        time.sleep(SLEEP_BETWEEN_QUERIES)

    return dict(results), errors

def _self_test():
    """
    Simple self‑test that resolves known records for example.com.
    Returns True if all checks pass, False otherwise.
    """
    test_domain = "example.com"
    required = {
        "A": lambda recs: len(recs) > 0,
        "MX": lambda recs: len(recs) > 0,
    }
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DEFAULT_TIMEOUT

    for rtype, validator in required.items():
        records, err = _resolve(test_domain, rtype, resolver)
        if err or not validator(records):
            logging.error(f"Self‑test failed for {rtype}: err={err}, records={records}")
            return False
        time.sleep(SLEEP_BETWEEN_QUERIES)

    logging.info("Self‑test passed.")
    return True

def _load_config(path: str):
    """
    Load optional JSON configuration file.
    Returns a dict; empty dict if file missing or malformed.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Configuration file not found: {path}")
    except json.JSONDecodeError as e:
        logging.error(f"Malformed JSON in config file {path}: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error loading config {path}: {e}")
    return {}

# ----------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="DNS Reconnaissance Tool")
    parser.add_argument("target", nargs="?", help="Domain name to query")
    parser.add_argument(
        "-t",
        "--types",
        nargs="+",
        default=["A", "AAAA", "MX", "NS", "TXT"],
        help="DNS record types to query (default: A AAAA MX NS TXT)",
    )
    parser.add_argument(
        "--config",
        help="Path to optional JSON config file (currently unused but reserved)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        success = _self_test()
        sys.exit(0 if success else 1)

    if not args.target:
        parser.error("the following arguments are required: target")

    # Load config (future extension)
    config = {}
    if args.config:
        config = _load_config(args.config)

    # Perform DNS queries
    findings = args.types
    results, errors = _perform_queries(args.target, findings)

    # Determine overall status
    if errors:
        status = "partial"
    else:
        status = "success"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": findings,
        "results": results,
        "errors": errors,
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()