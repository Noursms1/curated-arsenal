"""
CATEGORY: Security Tool - GraphQL Assessment

This tool performs three main capabilities against a target host:
1. GraphQL endpoint discovery (common paths probing).
2. GraphQL introspection query execution to retrieve the schema.
3. Basic IDOR testing on discovered mutations that accept an `id` argument.

The script prints a JSON report with the following keys:
{
    "tool": "<tool name>",
    "version": "<semantic version>",
    "target": "<target base URL>",
    "status": "<overall status>",
    "technologies": ["GraphQL"],
    "findings": [...],
    "results": {...}
}

Usage:
    python gql_assessor.py <target_url> [--self-test]

The `--self-test` flag runs a quick sanity check against a known public GraphQL endpoint.
"""

import argparse
import json
import sys
import time
from urllib.parse import urljoin

import requests

TOOL_NAME = "gql_assessor"
VERSION = "1.0.0"
COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/",
    "/api/v1/graphql",
    "/v1/graphql",
    "/v2/graphql",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields {
        name
        args {
          name
          type { kind name ofType { name kind } }
        }
        type { kind name ofType { name kind } }
      }
    }
  }
}
"""

IDOR_TEST_IDS = [1, 2, 9999]  # simple set of IDs to test


def _request(url, payload):
    """Send a POST request to a GraphQL endpoint with basic error handling."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        time.sleep(0.5)  # polite delay
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def discover_endpoints(base_url):
    """Probe common GraphQL paths and return a list of responsive endpoints."""
    found = []
    for path in COMMON_PATHS:
        full_url = urljoin(base_url, path)
        payload = {"query": "{ __typename }"}
        result = _request(full_url, payload)
        if "data" in result and result["data"].get("__typename"):
            found.append(full_url)
    return found


def run_introspection(endpoint):
    """Execute the standard introspection query."""
    payload = {"query": INTROSPECTION_QUERY}
    result = _request(endpoint, payload)
    if "data" in result:
        return result["data"]
    return None


def extract_mutations(schema):
    """Return a list of mutation field definitions that have an `id` argument."""
    mutations = []
    mutation_type = schema.get("__schema", {}).get("mutationType")
    if not mutation_type:
        return mutations

    # Find the mutation type definition in the types list
    for t in schema["__schema"]["types"]:
        if t["name"] == mutation_type["name"]:
            for field in t.get("fields", []):
                for arg in field.get("args", []):
                    if arg["name"].lower() == "id":
                        mutations.append(field)
                        break
            break
    return mutations


def test_idor(endpoint, mutations):
    """Attempt to invoke each mutation with different IDs and compare responses."""
    findings = []
    for mut in mutations:
        mut_name = mut["name"]
        # Build a minimal mutation string with variable id
        mutation_str = f"mutation Test($id: ID!) {{ {mut_name}(id: $id) {{ __typename }} }}"
        previous_response = None
        vulnerable = False

        for test_id in IDOR_TEST_IDS:
            variables = {"id": str(test_id)}
            payload = {"query": mutation_str, "variables": variables}
            result = _request(endpoint, payload)

            if "errors" in result:
                # If the server returns an authorization error for some IDs but not others,
                # it may indicate IDOR. We'll just note the difference.
                pass

            response_snapshot = json.dumps(result, sort_keys=True)
            if previous_response and response_snapshot != previous_response:
                vulnerable = True
                findings.append(
                    {
                        "mutation": mut_name,
                        "ids_tested": IDOR_TEST_IDS,
                        "difference": "Responses differ between IDs",
                    }
                )
                break
            previous_response = response_snapshot

        if not vulnerable:
            findings.append(
                {
                    "mutation": mut_name,
                    "ids_tested": IDOR_TEST_IDS,
                    "difference": "No variation detected",
                }
            )
    return findings


def generate_report(target, endpoints, introspection, idor_findings):
    status = "success"
    findings = []

    if not endpoints:
        status = "failed"
        findings.append("No GraphQL endpoints discovered.")
    else:
        findings.append(f"Discovered endpoints: {endpoints}")

    if introspection:
        findings.append("Introspection succeeded.")
    else:
        status = "partial"
        findings.append("Introspection failed or returned no schema.")

    if idor_findings:
        findings.append("IDOR testing completed.")
    else:
        findings.append("No mutations with `id` argument found; IDOR test skipped.")

    report = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "technologies": ["GraphQL"],
        "findings": findings,
        "results": {
            "endpoints": endpoints,
            "introspection_schema": introspection,
            "idor_findings": idor_findings,
        },
    }
    return report


def self_test():
    """Run a minimal self‑test against a public GraphQL endpoint."""
    test_target = "https://countries.trevorblades.com"
    endpoints = discover_endpoints(test_target)
    if not endpoints:
        print(json.dumps({"self_test": "failed", "reason": "No endpoint found"}))
        sys.exit(1)

    introspection = run_introspection(endpoints[0])
    mutations = extract_mutations(introspection) if introspection else []
    idor_findings = test_idor(endpoints[0], mutations) if mutations else []

    report = generate_report(test_target, endpoints, introspection, idor_findings)
    report["self_test"] = "passed"
    print(json.dumps(report, indent=2))
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="GraphQL endpoint finder and security tester")
    parser.add_argument("target", nargs="?", help="Base URL of the target (e.g., https://example.com)")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a built‑in self‑test against a known public GraphQL service",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()

    if not args.target:
        parser.error("the following arguments are required: target")

    target = args.target.rstrip("/")
    endpoints = discover_endpoints(target)

    introspection = None
    idor_findings = []
    if endpoints:
        introspection = run_introspection(endpoints[0])
        if introspection:
            mutations = extract_mutations(introspection)
            if mutations:
                idor_findings = test_idor(endpoints[0], mutations)

    report = generate_report(target, endpoints, introspection, idor_findings)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()