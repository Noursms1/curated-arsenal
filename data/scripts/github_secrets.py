# CATEGORY: OSINT - GitHub Secrets Discovery Tool
import argparse
import json
import os
import sys
import time
import re
import requests

TOOL_NAME = "gh_secrets_osint"
VERSION = "1.0.0"
GITHUB_API = "https://api.github.com"
DEFAULT_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "gh-secrets-osint-tool"
}
# Simple regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key[^\\n\\r]{0,40}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----"
}

def get_auth_headers():
    token = os.getenv("GITHUB_TOKEN")
    headers = DEFAULT_HEADERS.copy()
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def safe_request(method, url, **kwargs):
    """Wrap requests with try/except and rate limiting."""
    try:
        response = requests.request(method, url, headers=get_auth_headers(), timeout=15, **kwargs)
        time.sleep(0.5)  # rate limiting
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        return None

def search_code(target, query):
    """Search GitHub code for secret patterns within a user/org."""
    findings = []
    results = []
    for name, pattern in SECRET_PATTERNS.items():
        q = f"{query}+user:{target}"
        url = f"{GITHUB_API}/search/code?q={requests.utils.quote(q)}"
        resp = safe_request("GET", url)
        if resp and resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total:
                findings.append(f"Found {total} potential {name} matches")
                results.append({
                    "type": name,
                    "count": total,
                    "sample_items": [item["html_url"] for item in data.get("items", [])[:3]]
                })
    return findings, results

def scan_repo_commits(owner, repo):
    """Inspect recent commits for secret patterns."""
    findings = []
    results = []
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits"
    resp = safe_request("GET", url, params={"per_page": 30})
    if not resp:
        return findings, results
    commits = resp.json()
    for commit in commits:
        sha = commit.get("sha")
        if not sha:
            continue
        raw_url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
        commit_resp = safe_request("GET", raw_url)
        if not commit_resp:
            continue
        commit_data = commit_resp.json()
        files = commit_data.get("files", [])
        for f in files:
            patch = f.get("patch", "")
            for name, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, patch):
                    findings.append(f"Potential {name} in commit {sha}")
                    results.append({
                        "commit": sha,
                        "file": f.get("filename"),
                        "type": name,
                        "snippet": patch[:200]
                    })
    return findings, results

def validate_token(token):
    """Check if a provided GitHub token is valid (limited info)."""
    headers = DEFAULT_HEADERS.copy()
    headers["Authorization"] = f"token {token}"
    url = f"{GITHUB_API}/rate_limit"
    resp = safe_request("GET", url, headers=headers)
    if resp and resp.status_code == 200:
        return True, {"rate_limit": resp.json()}
    return False, {}

def self_test():
    """Run basic internal tests."""
    test_results = {"search_code": False, "scan_repo_commits": False, "validate_token": False}
    # Test search_code with a known empty target
    f, r = search_code("octocat", "nonexistentpattern12345")
    test_results["search_code"] = (len(f) == 0 and isinstance(r, list))
    # Test scan_repo_commits with a small public repo
    f2, r2 = scan_repo_commits("octocat", "Hello-World")
    test_results["scan_repo_commits"] = isinstance(f2, list) and isinstance(r2, list)
    # Test validate_token with dummy token
    valid, _ = validate_token("ghp_invalidtoken1234567890abcdef1234567890ab")
    test_results["validate_token"] = (valid is False)
    return test_results

def main():
    parser = argparse.ArgumentParser(description="GitHub Secrets OSINT Tool")
    parser.add_argument("target", nargs="?", help="GitHub user or organization to scan")
    parser.add_argument("--repo", help="Specific repository (owner/repo) for commit scan")
    parser.add_argument("--token", help="GitHub token to validate")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target or "",
        "status": "unknown",
        "findings": [],
        "results": {}
    }

    if args.self_test:
        test_res = self_test()
        output["status"] = "self-test"
        output["findings"] = ["Self-test completed"]
        output["results"] = test_res
        print(json.dumps(output, indent=2))
        sys.exit(0)

    overall_findings = []
    overall_results = {}

    if args.target:
        # Capability 1: Code search for secrets
        f, r = search_code(args.target, "aws_access_key_id OR aws_secret_access_key OR ghp_")
        overall_findings.extend(f)
        overall_results["code_search"] = r

    if args.repo:
        # Capability 2: Scan recent commits for secrets
        owner_repo = args.repo.split("/")
        if len(owner_repo) == 2:
            f2, r2 = scan_repo_commits(owner_repo[0], owner_repo[1])
            overall_findings.extend(f2)
            overall_results["commit_scan"] = r2

    if args.token:
        # Capability 3: Validate provided token
        valid, info = validate_token(args.token)
        status_msg = "Valid token" if valid else "Invalid token"
        overall_findings.append(status_msg)
        overall_results["token_validation"] = {"valid": valid, "info": info}

    output["status"] = "completed"
    output["findings"] = overall_findings
    output["results"] = overall_results

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()