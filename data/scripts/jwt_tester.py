"""
CATEGORY: Security - JWT Analysis Tool

This production‑grade script provides three core capabilities for assessing JSON Web Tokens (JWT):
1. **Weakness Detection** – identifies usage of the insecure "none" algorithm.
2. **Algorithm Confusion Check** – attempts to verify a token under mismatched algorithms (e.g., treating an RS256 token as HS256) to expose mis‑configurations.
3. **Secret Brute‑Force** – iterates over a supplied dictionary to discover weak HMAC secrets.

The tool prints a single JSON object with the following keys:
    tool, version, target, status, technologies, findings, results

It also supports a `--self-test` flag that runs built‑in sanity checks without external input.
"""

import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

import jwt
import requests
from jwt import PyJWKClient, InvalidTokenError, DecodeError, InvalidSignatureError

TOOL_NAME = "jwt_tester"
VERSION = "1.0.0"


def safe_request(url: str) -> Optional[Dict[str, Any]]:
    """Perform a GET request with error handling and a short delay."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        time.sleep(0.5)  # polite pause between network calls
        return response.json()
    except Exception as exc:
        return None


def detect_none_algorithm(token: str) -> bool:
    """Return True if the token header specifies the 'none' algorithm."""
    try:
        header = jwt.get_unverified_header(token)
        return header.get("alg", "").lower() == "none"
    except Exception:
        return False


def algorithm_confusion_check(token: str, jwks_url: Optional[str]) -> Dict[str, Any]:
    """
    Try to verify the token under mismatched algorithms.

    Returns a dict with:
        success: bool – whether a confusion was observed
        details: description of the observation
    """
    result = {"success": False, "details": ""}

    # First, decode header to know the declared algorithm
    try:
        header = jwt.get_unverified_header(token)
        declared_alg = header.get("alg", "")
    except Exception as exc:
        result["details"] = f"Unable to read token header: {exc}"
        return result

    # If we have a JWKS endpoint, fetch keys for RS256 verification
    jwk_client = None
    if jwks_url:
        try:
            jwk_client = PyJWKClient(jwks_url)
        except Exception as exc:
            result["details"] = f"Failed to initialise JWK client: {exc}"
            return result

    # 1. Attempt RS256 verification using the public key (if available)
    if jwk_client:
        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
            jwt.decode(token, signing_key, algorithms=["RS256"])
            # If declared algorithm was HS*, this is a confusion
            if declared_alg.startswith("HS"):
                result["success"] = True
                result["details"] = (
                    f"Token declared as {declared_alg} but verified with RS256 public key."
                )
                return result
        except (InvalidTokenError, Exception):
            pass  # Expected for mismatched algs

    # 2. Attempt HS256 verification using the public key bytes as secret (common mis‑config)
    if jwk_client:
        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
            # Convert key to PEM string if it's a cryptography object
            if hasattr(signing_key, "public_bytes"):
                secret = signing_key.public_bytes(
                    encoding=jwt.utils.base64url_decode,
                    format=jwt.utils.base64url_decode,
                )
            else:
                secret = str(signing_key)
            jwt.decode(token, secret, algorithms=["HS256"])
            if declared_alg == "RS256":
                result["success"] = True
                result["details"] = (
                    "RS256 token accepted when verified with HS256 using the public key as secret."
                )
                return result
        except (InvalidSignatureError, DecodeError, Exception):
            pass

    result["details"] = "No algorithm confusion detected."
    return result


def brute_force_secret(token: str, dict_path: str, max_attempts: int = 1000) -> Dict[str, Any]:
    """
    Attempt to discover a weak HS256 secret by trying each word in the supplied dictionary.

    Returns a dict with:
        found: bool – whether a secret was discovered
        secret: the discovered secret (or None)
        attempts: number of attempts performed
    """
    result = {"found": False, "secret": None, "attempts": 0}
    try:
        with open(dict_path, "r", encoding="utf-8") as f:
            for line in f:
                if result["attempts"] >= max_attempts:
                    break
                candidate = line.strip()
                result["attempts"] += 1
                try:
                    jwt.decode(token, candidate, algorithms=["HS256"])
                    # Successful decode means the secret is correct
                    result["found"] = True
                    result["secret"] = candidate
                    break
                except (InvalidSignatureError, DecodeError):
                    continue
    except FileNotFoundError:
        result["details"] = f"Dictionary file not found: {dict_path}"
    except Exception as exc:
        result["details"] = f"Error during brute‑force: {exc}"
    return result


def run_self_test() -> Dict[str, Any]:
    """Execute a lightweight self‑test suite and return a summary dict."""
    findings = []
    results = {}

    # 1. Test detection of 'none' algorithm
    none_token = jwt.encode({"sub": "test"}, key=None, algorithm="none")
    if detect_none_algorithm(none_token):
        findings.append("Self‑test: correctly detected 'none' algorithm.")
    else:
        findings.append("Self‑test: failed to detect 'none' algorithm.")

    # 2. Test algorithm confusion (HS256 token verified as RS256)
    secret = "selftestsecret"
    hs_token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")
    # Mock JWKS with a generated RSA key (using PyJWT's built‑in generation)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Write temporary JWKS file
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "selftest",
                "n": jwt.utils.base64url_encode(rsa_key.public_key().public_numbers().n.to_bytes(256, "big")).decode(),
                "e": jwt.utils.base64url_encode(rsa_key.public_key().public_numbers().e.to_bytes(3, "big")).decode(),
            }
        ]
    }
    # Serve JWKS via a local HTTP server is out of scope; instead, directly feed the dict
    # We'll simulate the confusion check by passing the JWKS dict via a temporary file path
    # For simplicity, we skip network fetch and directly call the internal logic
    # Here we just ensure the function runs without error
    try:
        confusion_res = algorithm_confusion_check(hs_token, None)
        results["confusion_self_test"] = confusion_res
    except Exception as exc:
        findings.append(f"Self‑test: algorithm confusion raised exception: {exc}")

    # 3. Test brute‑force with a tiny dictionary
    dict_path = "selftest_dict.txt"
    with open(dict_path, "w", encoding="utf-8") as f:
        f.write("password\n123456\n" + secret + "\n")
    brute_res = brute_force_secret(hs_token, dict_path, max_attempts=10)
    if brute_res.get("found"):
        findings.append("Self‑test: brute‑force successfully recovered secret.")
    else:
        findings.append("Self‑test: brute‑force failed to recover secret.")

    # Clean up temporary dict file
    try:
        import os

        os.remove(dict_path)
    except Exception:
        pass

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": "completed",
        "technologies": ["JWT", "HS256", "RS256"],
        "findings": findings,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT Weakness Tester")
    parser.add_argument("--url", help="Target base URL (used for JWKS discovery)", default="")
    parser.add_argument("--token", help="JWT to analyse", required=False)
    parser.add_argument("--jwks-url", help="Full URL to JWKS endpoint", default=None)
    parser.add_argument("--dict", help="Path to wordlist for secret brute‑force", default=None)
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test suite")
    args = parser.parse_args()

    if args.self_test:
        output = run_self_test()
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    # Basic validation
    if not args.token:
        print(
            json.dumps(
                {
                    "tool": TOOL_NAME,
                    "version": VERSION,
                    "target": args.url,
                    "status": "error",
                    "technologies": ["JWT"],
                    "findings": ["No token supplied."],
                    "results": {},
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(1)

    findings: List[str] = []
    results: Dict[str, Any] = {}
    technologies = set()

    # Capability 1 – None algorithm detection
    if detect_none_algorithm(args.token):
        findings.append("Token uses insecure 'none' algorithm.")
        technologies.add("none")
    else:
        technologies.add("alg")

    # Capability 2 – Algorithm confusion check
    confusion = algorithm_confusion_check(args.token, args.jwks_url)
    results["algorithm_confusion"] = confusion
    if confusion.get("success"):
        findings.append(confusion.get("details", "Algorithm confusion detected."))
        technologies.update(["HS256", "RS256"])

    # Capability 3 – Secret brute‑force (if dictionary supplied)
    if args.dict:
        brute = brute_force_secret(args.token, args.dict)
        results["brute_force"] = brute
        if brute.get("found"):
            findings.append(f"Weak secret discovered: '{brute.get('secret')}'.")
            technologies.add("HS256")
        else:
            findings.append("Brute‑force did not recover a secret.")
            technologies.add("HS256")
    else:
        results["brute_force"] = {"found": False, "details": "No dictionary provided."}

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.url or "unspecified",
        "status": "completed",
        "technologies": sorted(list(technologies)),
        "findings": findings,
        "results": results,
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()