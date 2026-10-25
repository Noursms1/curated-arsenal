#!/usr/bin/env python3
"""
CATEGORY: Recon/Web
TECHNIQUES: GraphQL introspection, field enumeration, batch query DoS detection, IDOR detection in mutations
CHAIN_CONTRIBUTIONS: Utilizes standard GraphQL introspection spec, leverages JSON schema parsing, integrates timing analysis for DoS heuristics, applies simple IDOR heuristics on mutation inputs.
"""

import argparse
import json
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

DEFAULT_TIMEOUT = 10
RATE_DELAY = 0.5
DOS_THRESHOLD = 5  # seconds


def rate_limit():
    time.sleep(RATE_DELAY)


def send_graphql(url: str, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Sends a GraphQL POST request with proper error handling and rate limiting.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        rate_limit()
        resp = requests.post(url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def introspect_schema(url: str) -> Dict[str, Any]:
    """
    Retrieves the full GraphQL schema via introspection.
    """
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type { kind name ofType { kind name } }
              defaultValue
            }
            type { kind name ofType { kind name } }
            isDeprecated
            deprecationReason
          }
          inputFields {
            name
            description
            type { kind name ofType { kind name } }
            defaultValue
          }
          interfaces { name }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes { name }
        }
        directives {
          name
          description
          locations
          args {
            name
            description
            type { kind name ofType { kind name } }
            defaultValue
          }
        }
      }
    }
    """
    result = send_graphql(url, introspection_query)
    return result.get("data", {})


def extract_fields(schema: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Parses the introspection result to produce a list of field suggestions.
    Each entry contains type and field name.
    """
    fields = []
    types = schema.get("__schema", {}).get("types", [])
    for t in types:
        if t.get("fields"):
            for f in t["fields"]:
                fields.append({"type": t["name"], "field": f["name"]})
    return fields


def batch_query_dos_test(url: str) -> bool:
    """
    Sends a deliberately large batch query to gauge server response time.
    Returns True if response time exceeds DOS_THRESHOLD.
    """
    # Build a query that repeats a simple field many times
    repeated_fields = "\n".join([f"field{idx}: __typename" for idx in range(200)])
    query = f"{{\n{repeated_fields}\n}}"
    start = time.time()
    result = send_graphql(url, query)
    elapsed = time.time() - start
    # If the server returned an error quickly, treat as not vulnerable
    if "error" in result:
        return False
    return elapsed > DOS_THRESHOLD


def detect_idor_in_mutations(url: str, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Attempts simple IDOR detection by invoking mutations with sequential IDs.
    Returns a list of findings where responses differ in a way that suggests IDOR.
    """
    findings = []
    mutation_type = schema.get("__schema", {}).get("mutationType")
    if not mutation_type:
        return findings

    # Locate mutation fields
    mutation_name = mutation_type.get("name")
    mutation_fields = None
    for t in schema.get("__schema", {}).get("types", []):
        if t.get("name") == mutation_name:
            mutation_fields = t.get("fields", [])
            break
    if not mutation_fields:
        return findings

    # For each mutation that takes an 'id' argument, test a few values
    test_ids = [1, 2, 3]
    for field in mutation_fields:
        args = field.get("args", [])
        id_arg = next((a for a in args if a.get("name") == "id"), None)
        if not id_arg:
            continue

        # Build a simple mutation query template
        mutation_name = field["name"]
        var_name = "idVar"
        mutation_query = f"mutation {mutation_name}(${var_name}: ID!) {{ {mutation_name}({var_name}: ${var_name}) {{ __typename }} }}"

        responses = {}
        for test_id in test_ids:
            variables = {var_name: str(test_id)}
            resp = send_graphql(url, mutation_query, variables)
            if "error" in resp:
                continue
            key = json.dumps(resp, sort_keys=True)
            responses.setdefault(key, []).append(test_id)

        # If we have more than one distinct response, flag potential IDOR
        if len(responses) > 1:
            findings.append({
                "mutation": mutation_name,
                "ids_tested": test_ids,
                "responses": list(responses.values())
            })
    return findings


def run_scan(target: str) -> Dict[str, Any]:
    """
    Executes the full GraphQL security scan and returns a structured result.
    """
    result = {
        "tool": "GraphQLForge",
        "version": "1.0.0",
        "target": target,
        "status": "completed",
        "technologies": ["GraphQL"],
        "findings": [],
        "results": {}
    }

    schema = introspect_schema(target)
    if not schema:
        result["status"] = "failed"
        result["findings"].append({"error": "Unable to retrieve schema via introspection."})
        return result

    # 1. Field suggestion
    fields = extract_fields(schema)
    result["results"]["field_suggestions"] = fields[:20]  # limit for brevity

    # 2. Batch query DoS detection
    dos_vulnerable = batch_query_dos_test(target)
    if dos_vulnerable:
        result["findings"].append({
            "type": "BatchQueryDoS",
            "description": "Server response time exceeds threshold, indicating potential DoS vulnerability."
        })

    # 3. IDOR in mutations
    idor_findings = detect_idor_in_mutations(target, schema)
    if idor_findings:
        for f in idor_findings:
            result["findings"].append({
                "type": "MutationIDOR",
                "mutation": f["mutation"],
                "details": f"Different responses observed for IDs {f['ids_tested']}."
            })

    return result


def self_test() -> int:
    """
    Performs a lightweight self‑test against a public GraphQL endpoint.
    Returns exit code 0 on success, 1 otherwise.
    """
    test_url = "https://countries.trevorblades.com/"
    try:
        scan_result = run_scan(test_url)
        if scan_result["status"] != "completed":
            print("Self‑test failed: scan did not complete.", file=sys.stderr)
            return 1
        # Basic sanity checks
        if "field_suggestions" not in scan_result["results"]:
            print("Self‑test failed: missing field suggestions.", file=sys.stderr)
            return 1
        print(json.dumps(scan_result, indent=2))
        return 0
    except Exception as e:
        print(f"Self‑test exception: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description="GraphQL security scanner with introspection, field enumeration, batch query DoS and mutation IDOR detection.")
    parser.add_argument("target", nargs="?", help="GraphQL endpoint URL (e.g., https://example.com/graphql)")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test and exit.")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if not args.target:
        parser.error("the following arguments are required: target")

    scan_output = run_scan(args.target)
    print(json.dumps(scan_output, ensure_ascii=False))


if __name__ == "__main__":
    main()