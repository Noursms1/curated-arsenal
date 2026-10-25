# CATEGORY: API - OAuth Misconfiguration Scanner
import argparse
import json
import sys
import time
import urllib.parse
import uuid

import requests

TOOL_NAME = "OAuthMisconfigScanner"
VERSION = "1.0"

def discover_endpoints(base_url):
    """Discover OAuth/OpenID configuration endpoints."""
    well_known_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server"
    ]
    config = {}
    for path in well_known_paths:
        url = urllib.parse.urljoin(base_url, path)
        try:
            resp = requests.get(url, timeout=10)
            time.sleep(0.5)
            if resp.status_code == 200:
                data = resp.json()
                config.update({
                    "authorization_endpoint": data.get("authorization_endpoint"),
                    "token_endpoint": data.get("token_endpoint"),
                    "issuer": data.get("issuer"),
                    "jwks_uri": data.get("jwks_uri")
                })
                break
        except Exception:
            continue
    return config

def test_token_endpoint(token_endpoint):
    """Attempt to obtain a token without client authentication."""
    findings = []
    results = {}
    if not token_endpoint:
        return findings, results

    payload = {
        "grant_type": "client_credentials",
        "scope": "openid"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(token_endpoint, data=payload, headers=headers, timeout=10)
        time.sleep(0.5)
        results["status_code"] = resp.status_code
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "access_token" in data:
                    findings.append("Token endpoint issues tokens without client authentication.")
                else:
                    findings.append("Token endpoint responded 200 but no access_token in response.")
            except Exception:
                findings.append("Token endpoint returned non‑JSON response with 200 status.")
        elif resp.status_code == 401:
            findings.append("Token endpoint correctly requires authentication.")
        else:
            findings.append(f"Unexpected status code {resp.status_code} from token endpoint.")
    except Exception as e:
        findings.append(f"Error contacting token endpoint: {str(e)}")
    return findings, results

def test_redirect_uri(authorization_endpoint):
    """Check for open redirect vulnerability in the authorization endpoint."""
    findings = []
    results = {}
    if not authorization_endpoint:
        return findings, results

    malicious_url = "https://attacker.com/evil"
    state = str(uuid.uuid4())
    params = {
        "response_type": "code",
        "client_id": "public-client",
        "redirect_uri": malicious_url,
        "scope": "openid",
        "state": state
    }
    url = authorization_endpoint + "?" + urllib.parse.urlencode(params)
    try:
        resp = requests.get(url, allow_redirects=False, timeout=10)
        time.sleep(0.5)
        results["status_code"] = resp.status_code
        location = resp.headers.get("Location", "")
        if resp.status_code in (302, 303) and malicious_url in location:
            findings.append("Open redirect detected: authorization endpoint redirects to unvalidated redirect_uri.")
        else:
            findings.append("No open redirect observed on authorization endpoint.")
    except Exception as e:
        findings.append(f"Error testing redirect_uri: {str(e)}")
    return findings, results

def test_exposed_client_secret(base_url):
    """Attempt to retrieve client secret from a public endpoint (heuristic)."""
    findings = []
    results = {}
    test_path = "/client"
    url = urllib.parse.urljoin(base_url, test_path)
    params = {"client_id": "public-client"}
    try:
        resp = requests.get(url, params=params, timeout=10)
        time.sleep(0.5)
        results["status_code"] = resp.status_code
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "client_secret" in data:
                    findings.append("Client secret exposed via public endpoint.")
                else:
                    findings.append("Public client endpoint does not expose client_secret.")
            except Exception:
                findings.append("Public client endpoint returned non‑JSON data.")
        else:
            findings.append("Public client endpoint not accessible or returned unexpected status.")
    except Exception as e:
        findings.append(f"Error contacting public client endpoint: {str(e)}")
    return findings, results

def run_scan(target):
    overall_findings = []
    overall_results = {}

    # 1. Discover endpoints
    config = discover_endpoints(target)
    overall_results["discovered_configuration"] = config
    if not config:
        overall_findings.append("Failed to discover OAuth/OpenID configuration.")
        return overall_findings, overall_results

    # 2. Test token endpoint
    token_findings, token_results = test_token_endpoint(config.get("token_endpoint"))
    overall_findings.extend(token_findings)
    overall_results["token_endpoint_test"] = token_results

    # 3. Test redirect_uri handling
    redirect_findings, redirect_results = test_redirect_uri(config.get("authorization_endpoint"))
    overall_findings.extend(redirect_findings)
    overall_results["redirect_uri_test"] = redirect_results

    # 4. Test for exposed client secret
    secret_findings, secret_results = test_exposed_client_secret(target)
    overall_findings.extend(secret_findings)
    overall_results["client_secret_exposure_test"] = secret_results

    return overall_findings, overall_results

def self_test():
    """Run a basic self‑test against httpbin.org."""
    test_target = "https://httpbin.org"
    findings, results = run_scan(test_target)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_target,
        "status": "self-test-completed",
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="OAuth Misconfiguration Scanner")
    parser.add_argument("target", nargs="?", help="Base URL of the target API (e.g., https://example.com)")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target URL provided."],
            "results": {}
        }, indent=2))
        sys.exit(1)

    target = args.target.rstrip("/") + "/"
    findings, results = run_scan(target)

    status = "completed" if findings else "no-findings"
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()