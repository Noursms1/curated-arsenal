#!/usr/bin/env python3
"""
CATEGORY: API
TECHNIQUES: OAuth2, Open Redirect, State Parameter Validation, PKCE Enforcement, Token Leakage Detection
CHAIN_CONTRIBUTIONS: Integrates with existing recon modules for endpoint discovery, feeds findings into reporting pipeline.
"""

import sys
import argparse
import json
import time
import uuid
import hashlib
import base64
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.exceptions import RequestException, Timeout

# Global constants
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds between HTTP calls
USER_AGENT = "AutonomousForge-OAuthTester/1.0"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def _rate_limited_get(url, params=None, headers=None):
    """Wrapper for GET with rate limiting and error handling."""
    time.sleep(RATE_LIMIT)
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=False)
        return resp
    except (RequestException, Timeout) as e:
        logging.error(f"Request to {url} failed: {e}")
        return None

def _generate_code_verifier():
    """Generate a high‑entropy PKCE code verifier."""
    verifier = base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).rstrip(b'=').decode('utf-8')
    return verifier[:128]  # RFC 7636 max length

def _code_challenge(verifier):
    """Create a S256 code challenge from a verifier."""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')
    return challenge

def test_open_redirect(auth_endpoint, client_id, redirect_uri):
    """
    Attempt to use a malicious redirect_uri and see if the provider accepts it.
    Returns dict with result.
    """
    malicious = "https://evil.example.com/callback"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": malicious,
        "scope": "openid",
        "state": str(uuid.uuid4())
    }
    headers = {"User-Agent": USER_AGENT}
    resp = _rate_limited_get(auth_endpoint, params=params, headers=headers)
    if not resp:
        return {"open_redirect": "error"}

    location = resp.headers.get("Location", "")
    if malicious in location:
        return {"open_redirect": "vulnerable", "redirected_to": location}
    else:
        return {"open_redirect": "safe"}

def test_state_parameter(auth_endpoint, client_id, redirect_uri):
    """
    Verify that the provider requires a state parameter and that it is reflected.
    Returns dict with result.
    """
    # 1) No state parameter
    params_no_state = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid"
    }
    resp_no_state = _rate_limited_get(auth_endpoint, params=params_no_state, headers={"User-Agent": USER_AGENT})
    if not resp_no_state:
        return {"state_parameter": "error"}

    # 2) Predictable static state
    static_state = "STATIC123"
    params_static = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": static_state
    }
    resp_static = _rate_limited_get(auth_endpoint, params=params_static, headers={"User-Agent": USER_AGENT})
    if not resp_static:
        return {"state_parameter": "error"}

    findings = {}
    # Analyze responses
    for label, resp in [("no_state", resp_no_state), ("static_state", resp_static)]:
        location = resp.headers.get("Location", "")
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        returned_state = qs.get("state", [])
        if label == "no_state":
            if returned_state:
                findings["state_missing"] = "reflected_without_request"
            else:
                findings["state_missing"] = "not_reflected"
        else:
            if returned_state and returned_state[0] == static_state:
                findings["state_static"] = "reflected"
            else:
                findings["state_static"] = "not_reflected"

    return {"state_parameter": findings}

def test_pkce_enforcement(auth_endpoint, client_id, redirect_uri):
    """
    Check if the provider enforces PKCE for public clients.
    Returns dict with result.
    """
    verifier = _generate_code_verifier()
    challenge = _code_challenge(verifier)

    # 1) Send request with code_challenge_method but missing code_challenge
    params_missing_challenge = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "code_challenge_method": "S256",
        "state": str(uuid.uuid4())
    }
    resp_missing = _rate_limited_get(auth_endpoint, params=params_missing_challenge, headers={"User-Agent": USER_AGENT})
    if not resp_missing:
        return {"pkce": "error"}

    # 2) Send request with both challenge and method
    params_full = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": str(uuid.uuid4())
    }
    resp_full = _rate_limited_get(auth_endpoint, params=params_full, headers={"User-Agent": USER_AGENT})
    if not resp_full:
        return {"pkce": "error"}

    findings = {}
    # Analyze location headers for error indications
    for label, resp in [("missing_challenge", resp_missing), ("full_pkce", resp_full)]:
        location = resp.headers.get("Location", "")
        if "error" in location.lower():
            findings[label] = "rejected"
        else:
            findings[label] = "accepted"

    return {"pkce": findings}

def test_token_leakage(auth_endpoint, client_id, redirect_uri):
    """
    Detect if access tokens are leaked via URL fragments or response bodies.
    Since we cannot complete the full flow without user interaction,
    we inspect the redirect_uri parameter handling for implicit flow.
    Returns dict with result.
    """
    params = {
        "response_type": "token",  # implicit flow
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": str(uuid.uuid4())
    }
    resp = _rate_limited_get(auth_endpoint, params=params, headers={"User-Agent": USER_AGENT})
    if not resp:
        return {"token_leakage": "error"}

    location = resp.headers.get("Location", "")
    parsed = urlparse(location)
    fragment = parsed.fragment
    if fragment:
        frag_params = parse_qs(fragment)
        if "access_token" in frag_params:
            return {"token_leakage": "vulnerable", "token_in_fragment": True}
    # Some providers may return token in body (unlikely for GET)
    if "access_token" in resp.text:
        return {"token_leakage": "vulnerable", "token_in_body": True}
    return {"token_leakage": "safe"}

def run_all_tests(args):
    findings = {}
    try:
        findings.update(test_open_redirect(args.endpoint, args.client_id, args.redirect_uri))
        findings.update(test_state_parameter(args.endpoint, args.client_id, args.redirect_uri))
        findings.update(test_pkce_enforcement(args.endpoint, args.client_id, args.redirect_uri))
        findings.update(test_token_leakage(args.endpoint, args.client_id, args.redirect_uri))
    except Exception as e:
        logging.exception(f"Unexpected error during testing: {e}")
        return {"status": "error", "error": str(e), "findings": findings}

    return {
        "tool": "OAuth2MisconfigTester",
        "version": "1.0",
        "target": args.endpoint,
        "status": "completed",
        "technologies": ["OAuth2", "OpenID Connect"],
        "findings": findings,
        "results": "see findings"
    }

def self_test():
    """
    Minimal self‑test using mocked responses.
    """
    import unittest
    from unittest.mock import patch, MagicMock

    class OAuthTesterTest(unittest.TestCase):
        def setUp(self):
            self.endpoint = "https://example.com/oauth/authorize"
            self.client_id = "testclient"
            self.redirect_uri = "https://app.example.com/callback"

        @patch('requests.get')
        def test_open_redirect_vulnerable(self, mock_get):
            mock_resp = MagicMock()
            mock_resp.headers = {"Location": "https://evil.example.com/callback?code=123"}
            mock_get.return_value = mock_resp
            result = test_open_redirect(self.endpoint, self.client_id, self.redirect_uri)
            self.assertEqual(result["open_redirect"], "vulnerable")

        @patch('requests.get')
        def test_state_parameter_reflection(self, mock_get):
            # No state case
            mock_no_state = MagicMock()
            mock_no_state.headers = {"Location": "https://app.example.com/callback?code=abc"}
            # Static state case
            mock_static = MagicMock()
            mock_static.headers = {"Location": "https://app.example.com/callback?code=abc&state=STATIC123"}
            mock_get.side_effect = [mock_no_state, mock_static]

            result = test_state_parameter(self.endpoint, self.client_id, self.redirect_uri)
            self.assertIn("state_missing", result["state_parameter"])
            self.assertIn("state_static", result["state_parameter"])

        @patch('requests.get')
        def test_pkce_enforcement(self, mock_get):
            mock_missing = MagicMock()
            mock_missing.headers = {"Location": "https://app.example.com/callback?error=invalid_request"}
            mock_full = MagicMock()
            mock_full.headers = {"Location": "https://app.example.com/callback?code=xyz"}
            mock_get.side_effect = [mock_missing, mock_full]

            result = test_pkce_enforcement(self.endpoint, self.client_id, self.redirect_uri)
            self.assertEqual(result["pkce"]["missing_challenge"], "rejected")
            self.assertEqual(result["pkce"]["full_pkce"], "accepted")

        @patch('requests.get')
        def test_token_leakage(self, mock_get):
            mock_resp = MagicMock()
            mock_resp.headers = {"Location": "https://app.example.com/callback#access_token=leaked&token_type=bearer"}
            mock_get.return_value = mock_resp

            result = test_token_leakage(self.endpoint, self.client_id, self.redirect_uri)
            self.assertEqual(result["token_leakage"], "vulnerable")
            self.assertTrue(result["token_in_fragment"])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OAuthTesterTest)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

def parse_args():
    parser = argparse.ArgumentParser(description="OAuth 2.0 Misconfiguration Tester")
    parser.add_argument("-e", "--endpoint", required=False, help="Authorization endpoint URL")
    parser.add_argument("-c", "--client-id", required=False, help="OAuth client identifier")
    parser.add_argument("-r", "--redirect-uri", required=False, help="Registered redirect URI")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test suite")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.self_test:
        self_test()
    # Ensure required arguments are present for normal run
    missing = [name for name in ("endpoint", "client_id", "redirect_uri") if getattr(args, name) is None]
    if missing:
        logging.error(f"Missing required arguments: {', '.join(missing)}")
        sys.exit(1)

    result = run_all_tests(args)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()