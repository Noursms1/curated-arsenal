# CATEGORY: API
import argparse
import json
import sys
import time
from urllib.parse import urljoin

import requests

TOOL_NAME = "GraphQLIntrospector"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
SLEEP_INTERVAL = 0.5

INTROSPECTION_QUERY = """
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
          type { name kind ofType { name kind } }
        }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type { name kind ofType { name kind } }
        description
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
        type { name kind ofType { name kind } }
        defaultValue
        description
      }
    }
  }
}
"""

DEEP_QUERY_TEMPLATE = """
query DeepQuery {{
  {"a: __typename " * {depth}}
}}
"""

SENSITIVE_KEYWORDS = ["password", "secret", "token", "apiKey", "credential"]


def send_graphql_request(url, query, variables=None):
    headers = {"Content-Type": "application/json"}
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def introspect_schema(endpoint):
    time.sleep(SLEEP_INTERVAL)
    result = send_graphql_request(endpoint, INTROSPECTION_QUERY)
    if "error" in result:
        return None, result["error"]
    return result.get("data", {}), None


def list_types_and_fields(schema_data):
    types_info = []
    for t in schema_data.get("__schema", {}).get("types", []):
        fields = [f["name"] for f in t.get("fields", [])] if t.get("fields") else []
        types_info.append({"type": t["name"], "fields": fields})
    return types_info


def detect_sensitive_fields(types_info):
    findings = []
    for t in types_info:
        for field in t["fields"]:
            lower = field.lower()
            if any(keyword in lower for keyword in SENSITIVE_KEYWORDS):
                findings.append(
                    {"type": t["type"], "field": field, "reason": "Potentially sensitive field name"}
                )
    return findings


def test_query_depth(endpoint, max_depth=5):
    # Build a query that exceeds typical depth limits
    depth = max_depth + 2
    query = DEEP_QUERY_TEMPLATE.format(depth=depth)
    time.sleep(SLEEP_INTERVAL)
    result = send_graphql_request(endpoint, query)
    if "error" in result:
        return {"depth_test": "error", "message": result["error"]}
    if "errors" in result:
        # Assume depth limit triggered if error mentions depth
        messages = [e.get("message", "") for e in result["errors"]]
        if any("depth" in msg.lower() for msg in messages):
            return {"depth_test": "blocked", "message": "Depth limit enforced"}
        return {"depth_test": "allowed", "message": "No depth limit detected"}
    return {"depth_test": "allowed", "message": "No depth limit detected"}


def run_self_test():
    test_endpoint = "https://countries.trevorblades.com/"
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_endpoint,
        "status": "success",
        "findings": [],
        "results": {}
    }

    schema, err = introspect_schema(test_endpoint)
    if err:
        output["status"] = "error"
        output["findings"].append({"type": "self-test", "issue": f"Introspection failed: {err}"})
        print(json.dumps(output, indent=2))
        return

    types_info = list_types_and_fields(schema)
    sensitive = detect_sensitive_fields(types_info)
    depth_result = test_query_depth(test_endpoint)

    output["results"]["types"] = types_info
    output["results"]["sensitive_fields"] = sensitive
    output["results"]["depth_test"] = depth_result
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="GraphQL Introspection Tool")
    parser.add_argument("target", nargs="?", help="GraphQL endpoint URL")
    parser.add_argument("--self-test", action="store_true", help="Run self-test against a known endpoint")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target endpoint URL is required unless --self-test is used.\n")
        sys.exit(1)

    endpoint = args.target.rstrip("/")
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": endpoint,
        "status": "success",
        "findings": [],
        "results": {}
    }

    schema, err = introspect_schema(endpoint)
    if err:
        output["status"] = "error"
        output["findings"].append({"type": "introspection", "issue": err})
        print(json.dumps(output, indent=2))
        return

    types_info = list_types_and_fields(schema)
    sensitive = detect_sensitive_fields(types_info)
    depth_result = test_query_depth(endpoint)

    output["results"]["types"] = types_info
    output["results"]["sensitive_fields"] = sensitive
    output["results"]["depth_test"] = depth_result

    if sensitive:
        output["findings"].extend(sensitive)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()