#!/usr/bin/env python3
"""
CATEGORY: OSINT, RECON, SECURITY
TECHNIQUES: GitHub REST API enumeration, regex secret pattern detection, workflow file analysis
CHAIN_CONTRIBUTIONS: Integrates commit diff scanning, GitHub Actions workflow inspection, and repository file content search to provide comprehensive secret discovery across an organization.
"""

import argparse
import json
import sys
import time
import re
from typing import List, Dict, Any, Optional

import requests

# -------------------- Constants --------------------
VERSION = "1.0.0"
API_BASE = "https://api.github.com"
REQUEST_TIMEOUT = 10  # seconds
RATE_LIMIT_DELAY = 0.5  # seconds between API calls

# -------------------- Secret Patterns --------------------
SECRET_REGEXES = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(r"(?i)aws_secret_access_key[^=]*=[^\"'\n]*[\"'][A-Za-z0-9/+=]{40}[\"']"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "generic_api_key": re.compile(r"(?i)api[_-]?key[^=]*=[^\"'\n]*[\"'][A-Za-z0-9/+=]{20,}[\"']"),
    "generic_password": re.compile(r"(?i)password[^=]*=[^\"'\n]*[\"'][^\"'\n]{6,}[\"']"),
    "generic_secret": re.compile(r"(?i)secret[^=]*=[^\"'\n]*[\"'][^\"'\n]{6,}[\"']"),
}

# -------------------- Helper Functions --------------------
def safe_request(method: str, url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
    """Perform a HTTP request with timeout, error handling and rate limiting."""
    try:
        response = requests.request(method, url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        time.sleep(RATE_LIMIT_DELAY)
        if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and response.headers['X-RateLimit-Remaining'] == '0':
            reset = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
            wait = max(reset - int(time.time()), 0) + 5
            sys.stderr.write(f"[!] Rate limit exceeded, sleeping for {wait}s\n")
            time.sleep(wait)
            return safe_request(method, url, headers, params)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        sys.stderr.write(f"[!] Request error for {url}: {e}\n")
        return None

def extract_secrets(text: str) -> List[Dict[str, str]]:
    """Return list of detected secrets with type and snippet."""
    findings = []
    for secret_type, regex in SECRET_REGEXES.items():
        for match in regex.finditer(text):
            findings.append({
                "type": secret_type,
                "snippet": match.group(0).strip()
            })
    return findings

def paginate(url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Collect all pages of a GitHub API list endpoint."""
    results = []
    page = 1
    while True:
        paged_params = dict(params or {})
        paged_params.update({"per_page": 100, "page": page})
        resp = safe_request("GET", url, headers, paged_params)
        if resp is None:
            break
        data = resp.json()
        if not isinstance(data, list):
            break
        results.extend(data)
        if len(data) < 100:
            break
        page += 1
    return results

# -------------------- Core Scanning Logic --------------------
def scan_repository(owner: str, repo: str, token: str) -> Dict[str, Any]:
    """Scan a single repository for secrets in commits, workflow files, and root files."""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    findings = []

    # 1. Scan recent commits (last 30 days)
    commits_url = f"{API_BASE}/repos/{owner}/{repo}/commits"
    commits = paginate(commits_url, headers, {"since": (time.time() - 30*24*60*60)})
    for commit in commits:
        sha = commit.get("sha")
        if not sha:
            continue
        commit_detail_url = f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}"
        resp = safe_request("GET", commit_detail_url, headers)
        if resp is None:
            continue
        commit_data = resp.json()
        files = commit_data.get("files", [])
        for f in files:
            patch = f.get("patch", "")
            if not patch:
                continue
            secret_hits = extract_secrets(patch)
            for hit in secret_hits:
                findings.append({
                    "repo": f"{owner}/{repo}",
                    "location": f"commit:{sha}:{f.get('filename')}",
                    "type": hit["type"],
                    "snippet": hit["snippet"]
                })

    # 2. Scan GitHub Actions workflow files
    workflows_url = f"{API_BASE}/repos/{owner}/{repo}/contents/.github/workflows"
    resp = safe_request("GET", workflows_url, headers)
    if resp and resp.status_code == 200:
        workflow_files = resp.json()
        if isinstance(workflow_files, list):
            for wf in workflow_files:
                if wf.get("type") != "file":
                    continue
                dl_url = wf.get("download_url")
                if not dl_url:
                    continue
                wf_resp = safe_request("GET", dl_url, headers)
                if wf_resp is None:
                    continue
                content = wf_resp.text
                secret_hits = extract_secrets(content)
                for hit in secret_hits:
                    findings.append({
                        "repo": f"{owner}/{repo}",
                        "location": f"workflow:{wf.get('name')}",
                        "type": hit["type"],
                        "snippet": hit["snippet"]
                    })

    # 3. Scan root-level configuration files (e.g., .env, config.yml, *.json)
    root_files = [" .env", "env", ".env", "config.yml", "config.yaml", "settings.py", "settings.json"]
    for filename in root_files:
        file_url = f"{API_BASE}/repos/{owner}/{repo}/contents/{filename}"
        resp = safe_request("GET", file_url, headers)
        if resp and resp.status_code == 200:
            file_data = resp.json()
            if file_data.get("encoding") == "base64":
                import base64
                try:
                    decoded = base64.b64decode(file_data.get("content", "")).decode('utf-8', errors='ignore')
                except Exception:
                    continue
                secret_hits = extract_secrets(decoded)
                for hit in secret_hits:
                    findings.append({
                        "repo": f"{owner}/{repo}",
                        "location": f"file:{filename}",
                        "type": hit["type"],
                        "snippet": hit["snippet"]
                    })

    return {
        "repo": f"{owner}/{repo}",
        "findings": findings,
        "status": "completed"
    }

def scan_organization(org: str, token: str) -> Dict[str, Any]:
    """Enumerate all repos in an organization and scan each."""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    repos_url = f"{API_BASE}/orgs/{org}/repos"
    repos = paginate(repos_url, headers)
    all_findings = []
    for repo in repos:
        name = repo.get("name")
        if not name:
            continue
        result = scan_repository(org, name, token)
        all_findings.extend(result.get("findings", []))
    return {
        "tool": "gh_secret_scanner",
        "version": VERSION,
        "target": org,
        "status": "completed",
        "technologies": ["GitHub", "Python", "Regex"],
        "findings": all_findings,
        "results": len(all_findings)
    }

# -------------------- Self Test --------------------
def run_self_test() -> int:
    """Execute a lightweight self‑test against a known public repository."""
    test_org = "githubtraining"
    test_repo = "hellogitworld"
    dummy_token = ""  # No token needed for public repos; will work unauthenticated with low rate limits.
    headers = {"Accept": "application/vnd.github.v3+json"}
    # Simple check: ensure we can fetch repo info and that no findings are reported.
    repo_url = f"{API_BASE}/repos/{test_org}/{test_repo}"
    resp = safe_request("GET", repo_url, headers)
    if resp is None or resp.status_code != 200:
        sys.stderr.write("[!] Self‑test failed: cannot access test repository.\n")
        return 1
    # Run minimal scan (only workflow files) to keep it fast.
    findings = []
    workflows_url = f"{API_BASE}/repos/{test_org}/{test_repo}/contents/.github/workflows"
    wf_resp = safe_request("GET", workflows_url, headers)
    if wf_resp and wf_resp.status_code == 200:
        wf_files = wf_resp.json()
        if isinstance(wf_files, list):
            for wf in wf_files:
                dl_url = wf.get("download_url")
                if dl_url:
                    content_resp = safe_request("GET", dl_url, headers)
                    if content_resp:
                        secret_hits = extract_secrets(content_resp.text)
                        findings.extend(secret_hits)
    output = {
        "tool": "gh_secret_scanner",
        "version": VERSION,
        "target": f"{test_org}/{test_repo}",
        "status": "self-test",
        "technologies": ["GitHub", "Python", "Regex"],
        "findings": findings,
        "results": len(findings)
    }
    print(json.dumps(output, indent=2))
    return 0 if len(findings) == 0 else 1

# -------------------- CLI --------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub organization secret scanner")
    parser.add_argument("--org", help="GitHub organization name to scan")
    parser.add_argument("--repo", help="Specific repository to scan (owner/repo). Overrides --org.")
    parser.add_argument("--token", help="GitHub personal access token (required for private repos and higher rate limits)", required=False)
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self test and exit")
    args = parser.parse_args()

    if args.self_test:
        exit_code = run_self_test()
        sys.exit(exit_code)

    token = args.token or ""
    if not token and not args.repo:
        sys.stderr.write("[!] A token is recommended for unauthenticated requests to avoid strict rate limits.\n")

    if args.repo:
        if "/" not in args.repo:
            sys.stderr.write("[!] --repo must be in the form owner/repo\n")
            sys.exit(1)
        owner, repo = args.repo.split("/", 1)
        result = scan_repository(owner, repo, token)
        output = {
            "tool": "gh_secret_scanner",
            "version": VERSION,
            "target": f"{owner}/{repo}",
            "status": result.get("status", "unknown"),
            "technologies": ["GitHub", "Python", "Regex"],
            "findings": result.get("findings", []),
            "results": len(result.get("findings", []))
        }
        print(json.dumps(output, indent=2))
    elif args.org:
        result = scan_organization(args.org, token)
        print(json.dumps(result, indent=2))
    else:
        sys.stderr.write("[!] Either --org or --repo must be specified.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()