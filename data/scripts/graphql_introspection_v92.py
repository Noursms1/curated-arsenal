# CATEGORY: API
import argparse
import json
import sys
import time
from typing import Any, Dict, List

import requests

TOOL_NAME = "GraphQLIntrospector"
VERSION = "1.0.0"
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
          defaultValue
        }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { name kind ofType { name kind } }
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
        type { name kind ofType { name kind } }
        defaultValue
      }
    }
  }
}
"""

def perform_introspection(url: str) -> Dict[str, Any]:
    """Send an introspection query to the GraphQL endpoint."""
    headers = {"Content-Type": "application/json"}
    payload = {"query": INTROSPECTION_QUERY}
    try:
        time.sleep(SLEEP_INTERVAL)
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {"success": True, "data": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deprecated fields/types and basic schema info."""
    deprecated_fields: List[Dict[str, str]] = []
    deprecated_types: List[Dict[str, str]] = []
    types = schema.get("__schema", {}).get("types", [])
    for t in types:
        # Check deprecated enum values
        for enum in t.get("enumValues", []):
            if enum.get("isDeprecated"):
                deprecated_fields.append({
                    "type": t["name"],
                    "field": enum["name"],
                    "reason": enum.get("deprecationReason", "")
                })
        # Check deprecated fields in object types
        for field in t.get("fields", []):
            if field.get("isDeprecated"):
                deprecated_fields.append({
                    "type": t["name"],
                    "field": field["name"],
                    "reason": field.get("deprecationReason", "")
                })
        # Mark whole type as deprecated if it has a @deprecated directive (rare)
        if t.get("isDeprecated"):
            deprecated_types.append({
                "type": t["name"],
                "reason": t.get("deprecationReason", "")
            })
    return {
        "deprecated_fields": deprecated_fields,
        "deprecated_types": deprecated_types,
        "type_count": len(types)
    }

def self_test() -> int:
    """Run a basic self‑test against a public GraphQL endpoint."""
    test_url = "https://countries.trevorblades.com/"
    result = perform_introspection(test_url)
    if not result["success"]:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": test_url,
            "status": "error",
            "findings": {"self_test": "failed"},
            "results": {"error": result["error"]}
        }, indent=2))
        return 1
    analysis = analyze_schema(result["data"])
    print(json.dumps({
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_url,
        "status": "ok",
        "findings": {"self_test": "passed"},
        "results": analysis
    }, indent=2))
    return 0

def main() -> None:
    parser = argparse.ArgumentParser(description="GraphQL introspection utility")
    parser.add_argument("target", nargs="?", help="GraphQL endpoint URL")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": {"error": "No target URL provided"},
            "results": {}
        }, indent=2))
        sys.exit(1)

    introspection = perform_introspection(args.target)
    if not introspection["success"]:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "findings": {"introspection_enabled": False},
            "results": {"error": introspection["error"]}
        }
        print(json.dumps(output, indent=2))
        sys.exit(1)

    schema_data = introspection["data"]
    # Detect if introspection was blocked (GraphQL returns errors without __schema)
    if "data" not in schema_data or not schema_data["data"] or "__schema" not in schema_data["data"]:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "findings": {"introspection_enabled": False},
            "results": {"error": "Introspection appears disabled or blocked"}
        }
        print(json.dumps(output, indent=2))
        sys.exit(1)

    analysis = analyze_schema(schema_data["data"])
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": "ok",
        "findings": {"introspection_enabled": True},
        "results": analysis
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()