# CATEGORY: API
"""
IDOR Test Tool
Version: 1.0.0
"""

import argparse
import json
import sys
import time
from typing import List, Dict, Any

import requests
from requests.exceptions import RequestException


class IDORTester:
    def __init__(self, base_url: str, endpoint: str, id_param: str, id_list: List[str]):
        """
        :param base_url: Base URL of the target API (e.g., https://example.com)
        :param endpoint: Endpoint path (e.g., /api/users/{id})
        :param id_param: Name of the path parameter to replace (e.g., id)
        :param id_list: List of IDs to test
        """
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint
        self.id_param = id_param
        self.id_list = id_list
        self.findings: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []

    def _build_url(self, obj_id: str) -> str:
        return f"{self.base_url}{self.endpoint.replace('{' + self.id_param + '}', obj_id)}"

    def _request(self, url: str) -> Dict[str, Any]:
        try:
            resp = requests.get(url, timeout=10)
            return {
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "body": resp.text[:200]  # truncate for brevity
            }
        except RequestException as e:
            return {
                "error": str(e)
            }

    def _analyze_responses(self, responses: List[Dict[str, Any]]) -> None:
        """
        Simple heuristic: if any response returns 200 and another returns 403/404,
        we flag a potential IDOR.
        """
        success_codes = {200, 201}
        failure_codes = {403, 404, 401}
        for resp in responses:
            if "status_code" not in resp:
                continue
            if resp["status_code"] in success_codes:
                self.findings.append({
                    "type": "potential_idor",
                    "detail": f"ID {resp.get('id')} returned success status {resp['status_code']}"
                })
                break

    def run(self) -> None:
        responses = []
        for obj_id in self.id_list:
            url = self._build_url(obj_id)
            result = self._request(url)
            result["url"] = url
            result["id"] = obj_id
            self.results.append(result)
            responses.append(result)
            time.sleep(0.5)
        self._analyze_responses(responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IDOR testing tool")
    parser.add_argument("--target", required=False, help="Base URL of the target API")
    parser.add_argument("--endpoint", required=False, help="Endpoint with placeholder, e.g., /api/users/{id}")
    parser.add_argument("--id-param", default="id", help="Placeholder name in endpoint")
    parser.add_argument("--ids", help="Comma‑separated list of IDs to test")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test")
    return parser.parse_args()


def self_test() -> None:
    """
    Self‑test uses httpbin.org which echoes the request.
    It pretends that IDs 1 and 2 exist (200) and ID 999 does not (404).
    """
    test_ids = ["1", "2", "999"]
    tester = IDORTester(
        base_url="https://httpbin.org",
        endpoint="/status/{id}",
        id_param="id",
        id_list=test_ids
    )
    tester.run()
    output = {
        "tool": "idor_test_tool",
        "version": "1.0.0",
        "target": "https://httpbin.org",
        "status": "self_test_completed",
        "findings": tester.findings,
        "results": tester.results
    }
    print(json.dumps(output, indent=2))


def main() -> None:
    args = parse_args()

    if args.self_test:
        self_test()
        return

    # Validate required arguments for normal run
    if not all([args.target, args.endpoint, args.ids]):
        print(json.dumps({
            "tool": "idor_test_tool",
            "version": "1.0.0",
            "target": args.target or "",
            "status": "error",
            "findings": [],
            "results": [],
            "error": "Missing required arguments: --target, --endpoint, --ids"
        }, indent=2))
        sys.exit(1)

    id_list = [i.strip() for i in args.ids.split(",") if i.strip()]

    tester = IDORTester(
        base_url=args.target,
        endpoint=args.endpoint,
        id_param=args.id_param,
        id_list=id_list
    )
    tester.run()

    output = {
        "tool": "idor_test_tool",
        "version": "1.0.0",
        "target": args.target,
        "status": "completed",
        "findings": tester.findings,
        "results": tester.results
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()