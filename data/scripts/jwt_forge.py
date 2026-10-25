#!/usr/bin/env python3
"""
CATEGORY: API Security
TECHNIQUES: JWT None Algorithm Detection, Weak Secret Brute‑Force, Algorithm Confusion (RS256→HS256)
CHAIN_CONTRIBUTIONS: token_parsing, signature_verification, jwks_fetch, rate_limiter, self_test_suite
"""

import argparse
import base64
import json
import sys
import time
import threading
from typing import List, Dict, Any, Optional

import jwt  # PyJWT
import requests

# Global constants
TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds between external requests
TOOL_NAME = "jwt_forge"
VERSION = "1.0.0"


def rate_limited_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """Perform a rate‑limited HTTP request with proper error handling."""
    time.sleep(RATE_LIMIT)
    try:
        resp = requests.request(method, url, timeout=TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp
    except Exception as e:
        return None


def b64url_decode(data: str) -> bytes:
    """Decode base64url string, adding padding if necessary."""
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def parse_jwt(token: str) -> Dict[str, Any]:
    """Parse JWT without verification and return header and payload."""
    try:
        header_b64, payload_b64, _ = token.split('.')
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        return {"header": header, "payload": payload}
    except Exception:
        return {}


def detect_none_alg(token: str) -> bool:
    """Return True if the token uses the 'none' algorithm."""
    parsed = parse_jwt(token)
    return parsed.get("header", {}).get("alg", "").lower() == "none"


def verify_hs256(token: str, secret: str) -> bool:
    """Verify HS256 signed token with provided secret."""
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        return True
    except jwt.InvalidTokenError:
        return False
    except Exception:
        return False


def brute_force_secret(token: str, wordlist_path: str) -> Optional[str]:
    """Attempt to brute‑force HS256 secret using a wordlist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            for line in f:
                secret = line.strip()
                if not secret:
                    continue
                if verify_hs256(token, secret):
                    return secret
    except Exception:
        pass
    return None


def fetch_jwks(jwks_url: str) -> Optional[Dict[str, Any]]:
    """Fetch JWKS (JSON Web Key Set) from a URL."""
    resp = rate_limited_request("GET", jwks_url)
    if resp and resp.headers.get("Content-Type", "").startswith("application/json"):
        try:
            return resp.json()
        except Exception:
            return None
    return None


def get_rsa_public_key(jwks: Dict[str, Any], kid: str) -> Optional[str]:
    """Extract PEM‑encoded RSA public key from JWKS for given kid."""
    try:
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    except Exception:
        return None
    return None


def algorithm_confusion_test(token: str, jwks_url: str) -> bool:
    """
    Test RS256→HS256 confusion:
    - Retrieve RSA public key from JWKS.
    - Use that key as HMAC secret to verify the token.
    Returns True if verification succeeds (indicating vulnerability).
    """
    parsed = parse_jwt(token)
    header = parsed.get("header", {})
    if header.get("alg") != "RS256":
        return False

    kid = header.get("kid")
    if not kid:
        return False

    jwks = fetch_jwks(jwks_url)
    if not jwks:
        return False

    public_key = get_rsa_public_key(jwks, kid)
    if not public_key:
        return False

    # Attempt HS256 verification using the RSA public key PEM as secret
    try:
        jwt.decode(token, public_key, algorithms=["HS256"])
        return True
    except jwt.InvalidTokenError:
        return False
    except Exception:
        return False


def build_output(target: str,
                 status: str,
                 technologies: List[str],
                 findings: List[str],
                 results: Dict[str, Any]) -> str:
    """Construct standardized JSON output."""
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "technologies": technologies,
        "findings": findings,
        "results": results
    }
    return json.dumps(output, indent=2)


def run_analysis(args: argparse.Namespace) -> str:
    findings = []
    results = {}
    technologies = ["JWT", "OAuth2", "OpenID Connect"]

    token = args.token
    target = args.url if args.url else "local-token"

    # 1. None algorithm detection
    if detect_none_alg(token):
        findings.append("Token uses 'none' algorithm (no signature).")
        results["none_alg"] = True
    else:
        results["none_alg"] = False

    # 2. Weak secret brute‑force
    if args.wordlist:
        secret = brute_force_secret(token, args.wordlist)
        if secret:
            findings.append(f"Weak secret discovered: '{secret}'.")
            results["brute_force_secret"] = secret
        else:
            results["brute_force_secret"] = None

    # 3. Algorithm confusion test
    if args.jwks:
        vulnerable = algorithm_confusion_test(token, args.jwks)
        if vulnerable:
            findings.append("Algorithm confusion vulnerability (RS256 token accepted as HS256).")
            results["alg_confusion"] = True
        else:
            results["alg_confusion"] = False

    status = "completed"
    return build_output(target, status, technologies, findings, results)


def self_test() -> int:
    """Run a minimal self‑test suite."""
    # Test token with none algorithm
    none_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    assert detect_none_alg(none_token) is True, "None algorithm detection failed"

    # Test HS256 verification with known secret
    secret = "supersecret"
    hs_token = jwt.encode({"sub": "123"}, secret, algorithm="HS256")
    assert verify_hs256(hs_token, secret) is True, "HS256 verification failed"
    assert verify_hs256(hs_token, "wrong") is False, "HS256 false positive"

    # Test brute‑force (using tiny wordlist)
    test_wordlist = "/tmp/jwt_forge_test_wordlist.txt"
    with open(test_wordlist, "w", encoding="utf-8") as f:
        f.write("guess\n")
        f.write(secret + "\n")
    found = brute_force_secret(hs_token, test_wordlist)
    assert found == secret, "Brute‑force failed"

    # Clean up test wordlist
    try:
        import os
        os.remove(test_wordlist)
    except Exception:
        pass

    # Algorithm confusion test requires external JWKS; skip in self‑test
    print("All self‑tests passed.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog=TOOL_NAME, description="Advanced JWT security tester.")
    parser.add_argument("--token", required=True, help="JWT token to analyze.")
    parser.add_argument("--url", help="Target URL (for reporting purposes).")
    parser.add_argument("--wordlist", help="Path to secret wordlist for brute‑force.")
    parser.add_argument("--jwks", help="URL to JWKS endpoint for algorithm confusion test.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test suite and exit.")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    try:
        output = run_analysis(args)
        print(output)
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        err_output = build_output(
            target=args.url or "unknown",
            status="error",
            technologies=[],
            findings=[f"Unexpected error: {str(e)}"],
            results={}
        )
        print(err_output, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()