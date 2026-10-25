# CATEGORY: API - JWT Analysis Tool
import argparse
import base64
import json
import sys
import time
from typing import Any, Dict, List, Optional

import jwt
import requests

TOOL_NAME = "jwt-analyzer"
VERSION = "1.0.0"


def b64url_decode(input_str: str) -> bytes:
    """Decode base64url string, adding padding if necessary."""
    padding = "=" * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode JWT without verification."""
    try:
        header_b64, payload_b64, _ = token.split(".", 2)
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        return {"header": header, "payload": payload}
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")


def fetch_jwks(jwks_url: str) -> Optional[Dict[str, Any]]:
    """Fetch JWKS from a URL with error handling."""
    try:
        resp = requests.get(jwks_url, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def get_key_from_jwks(jwks: Dict[str, Any], kid: str) -> Optional[str]:
    """Extract PEM key from JWKS matching the given kid."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            try:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            except Exception:
                continue
    return None


def verify_signature(token: str, key: Any) -> bool:
    """Verify JWT signature using the provided key."""
    try:
        jwt.decode(token, key=key, algorithms=["RS256", "HS256"], options={"verify_exp": False})
        return True
    except Exception:
        return False


def analyze_jwt(token: str, secret: Optional[str], jwks_url: Optional[str]) -> Dict[str, Any]:
    findings: List[str] = []
    results: Dict[str, Any] = {}

    # Capability 1: Decode
    try:
        decoded = decode_jwt(token)
        results["decoded"] = decoded
    except Exception as e:
        findings.append(str(e))
        return {"status": "error", "findings": findings, "results": results}

    header = decoded.get("header", {})
    alg = header.get("alg", "")
    kid = header.get("kid")

    # Capability 2: Insecure algorithm detection
    if alg.lower() == "none":
        findings.append("Insecure algorithm 'none' detected.")
    elif alg.startswith("HS") and secret is None:
        findings.append(f"HS algorithm '{alg}' used but no secret provided for verification.")

    # Capability 3: Expiration check
    payload = decoded.get("payload", {})
    exp = payload.get("exp")
    if exp is not None:
        try:
            import datetime
            now = datetime.datetime.utcnow().timestamp()
            if now > exp:
                findings.append("Token has expired.")
        except Exception:
            pass

    # Capability 4: Signature verification (key or JWKS)
    verified = False
    verification_method = None
    if secret:
        verification_method = "secret"
        verified = verify_signature(token, secret)
    elif jwks_url:
        verification_method = "jwks"
        jwks = fetch_jwks(jwks_url)
        if jwks and kid:
            key_obj = get_key_from_jwks(jwks, kid)
            if key_obj:
                verified = verify_signature(token, key_obj)
            else:
                findings.append("Matching kid not found in JWKS.")
        else:
            findings.append("Failed to fetch JWKS or missing kid.")
    else:
        findings.append("No verification key provided; signature not verified.")

    if verification_method:
        results["verification_method"] = verification_method
        results["signature_verified"] = verified
        if not verified:
            findings.append("Signature verification failed.")

    status = "success" if not findings else "warning"
    return {"status": status, "findings": findings, "results": results}


def self_test() -> None:
    """Run basic self‑tests and output JSON."""
    test_jwt = jwt.encode({"sub": "1234567890", "name": "John Doe", "iat": 1516239022}, "secret", algorithm="HS256")
    analysis = analyze_jwt(test_jwt, secret="secret", jwks_url=None)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_jwt,
        "status": analysis["status"],
        "findings": analysis["findings"],
        "results": analysis["results"],
    }
    print(json.dumps(output, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT analysis utility.")
    parser.add_argument("--jwt", help="JWT token to analyze.")
    parser.add_argument("--secret", help="Secret or symmetric key for verification.")
    parser.add_argument("--jwks-url", help="URL to fetch JWKS for RSA verification.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.jwt:
        sys.stderr.write("Error: --jwt is required unless --self-test is used.\n")
        sys.exit(1)

    analysis = analyze_jwt(args.jwt, args.secret, args.jwks_url)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.jwt,
        "status": analysis["status"],
        "findings": analysis["findings"],
        "results": analysis["results"],
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()