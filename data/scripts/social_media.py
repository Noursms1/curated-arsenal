# CATEGORY: OSINT - Social Media
import argparse
import json
import sys
import time
from typing import Any, Dict, List

import requests

TOOL_NAME = "SocialOSINT"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5
GITHUB_API = "https://api.github.com"


def safe_get(url: str, params: Dict[str, Any] = None) -> Any:
    """Perform a GET request with error handling and rate limiting."""
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}
    finally:
        time.sleep(SLEEP_INTERVAL)


def get_user_info(username: str) -> Dict[str, Any]:
    """Fetch basic GitHub user profile information."""
    url = f"{GITHUB_API}/users/{username}"
    data = safe_get(url)
    if "error" in data:
        return {"status": "error", "detail": data["error"]}
    return {
        "status": "ok",
        "login": data.get("login"),
        "name": data.get("name"),
        "company": data.get("company"),
        "location": data.get("location"),
        "public_repos": data.get("public_repos"),
        "followers": data.get("followers"),
        "following": data.get("following"),
        "created_at": data.get("created_at"),
    }


def get_user_repos(username: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Fetch a limited list of public repositories for the user."""
    url = f"{GITHUB_API}/users/{username}/repos"
    params = {"per_page": limit, "sort": "updated"}
    data = safe_get(url, params=params)
    if isinstance(data, dict) and "error" in data:
        return [{"status": "error", "detail": data["error"]}]
    repos = []
    for repo in data:
        repos.append(
            {
                "name": repo.get("name"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description"),
                "language": repo.get("language"),
                "stargazers_count": repo.get("stargazers_count"),
                "forks_count": repo.get("forks_count"),
                "updated_at": repo.get("updated_at"),
            }
        )
    return repos


def get_user_followers(username: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Fetch a limited list of followers for the user."""
    url = f"{GITHUB_API}/users/{username}/followers"
    params = {"per_page": limit}
    data = safe_get(url, params=params)
    if isinstance(data, dict) and "error" in data:
        return [{"status": "error", "detail": data["error"]}]
    followers = []
    for user in data:
        followers.append(
            {
                "login": user.get("login"),
                "html_url": user.get("html_url"),
                "type": user.get("type"),
            }
        )
    return followers


def run_osint(target: str) -> Dict[str, Any]:
    """Execute all OSINT capabilities for a given target."""
    findings = {}
    results = {}

    profile = get_user_info(target)
    findings["profile"] = "ok" if profile.get("status") == "ok" else "error"
    results["profile"] = profile

    repos = get_user_repos(target)
    findings["repos"] = "ok" if repos and not repos[0].get("status") else "error"
    results["repos"] = repos

    followers = get_user_followers(target)
    findings["followers"] = "ok" if followers and not followers[0].get("status") else "error"
    results["followers"] = followers

    overall_status = "success" if all(v == "ok" for v in findings.values()) else "partial_failure"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": overall_status,
        "findings": findings,
        "results": results,
    }
    return output


def self_test() -> None:
    """Run a simple self‑test using a known GitHub account."""
    test_user = "octocat"
    result = run_osint(test_user)

    # Basic validation: ensure each capability returned data without errors
    passed = all(
        v == "ok" for v in result["findings"].values()
    ) and isinstance(result["results"]["profile"], dict)

    test_output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_user,
        "status": "success" if passed else "failure",
        "findings": result["findings"],
        "results": result["results"],
    }
    print(json.dumps(test_output, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Social media OSINT tool")
    parser.add_argument("target", nargs="?", help="Username to investigate")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps(
            {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": None,
                "status": "error",
                "findings": {},
                "results": {"error": "No target username provided"},
            },
            indent=2,
        ))
        sys.exit(1)

    output = run_osint(args.target)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()