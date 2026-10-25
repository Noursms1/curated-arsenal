# CATEGORY: API - JWT Analysis Tool
import argparse
import base64
import json
import sys
import time
import hmac
import hashlib
import datetime
import requests

TOOL_NAME = "jwt-analyzer"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

def b64url_decode(input_str):
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")
    header_b, payload_b, signature_b = parts
    header = json.loads(b64url_decode(header_b).decode('utf-8'))
    payload = json.loads(b64url_decode(payload_b).decode('utf-8'))
    signature = signature_b  # keep encoded form for verification
    return header, payload, signature

def verify_hs_signature(token, secret):
    header_b, payload_b, signature_b = token.split('.')
    signing_input = f"{header_b}.{payload_b}".encode('utf-8')
    alg = json.loads(b64url_decode(header_b).decode('utf-8')).get('alg', '')
    if not alg.startswith('HS'):
        return False, f"Algorithm {alg} not HMAC based"
    hash_func = getattr(hashlib, alg.lower().replace('hs', 'sha'), None)
    if not hash_func:
        return False, f"Unsupported HMAC algorithm {alg}"
    expected_sig = hmac.new(secret.encode('utf-8'), signing_input, hash_func).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode('utf-8').rstrip('=')
    return hmac.compare_digest(expected_sig_b64, signature_b), "Signature verification completed"

def fetch_jwks(jwks_url):
    try:
        resp = requests.get(jwks_url, timeout=5)
        time.sleep(SLEEP_INTERVAL)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch JWKS: {e}")

def verify_rsa_signature(token, jwks):
    # Placeholder for RSA verification; real implementation would require cryptography library.
    # For production, integrate with jwt or cryptography packages.
    return False, "RSA verification not implemented in this lightweight tool"

def analyze_jwt(token, args):
    findings = []
    results = {}
    status = "success"

    try:
        header, payload, signature = decode_jwt(token)
        results['header'] = header
        results['payload'] = payload
    except Exception as e:
        status = "error"
        findings.append(f"Decoding error: {e}")
        return status, findings, results

    alg = header.get('alg', 'none')
    if alg == 'none':
        findings.append("Token uses 'none' algorithm - insecure")
    elif alg.startswith('HS'):
        if not args.secret:
            findings.append(f"HMAC algorithm {alg} used but no secret provided for verification")
        else:
            verified, msg = verify_hs_signature(token, args.secret)
            results['signature_verified'] = verified
            findings.append(msg)
    elif alg.startswith('RS') or alg.startswith('ES'):
        if not args.jwks_url:
            findings.append(f"RSA/ECDSA algorithm {alg} used but no JWKS URL provided")
        else:
            try:
                jwks = fetch_jwks(args.jwks_url)
                verified, msg = verify_rsa_signature(token, jwks)
                results['signature_verified'] = verified
                findings.append(msg)
            except Exception as e:
                findings.append(str(e))
    else:
        findings.append(f"Unrecognized algorithm: {alg}")

    # Expiration check
    exp = payload.get('exp')
    if exp:
        try:
            exp_dt = datetime.datetime.utcfromtimestamp(exp)
            now = datetime.datetime.utcnow()
            if now > exp_dt:
                findings.append("Token is expired")
            else:
                findings.append(f"Token expires in {(exp_dt - now).total_seconds():.0f} seconds")
        except Exception as e:
            findings.append(f"Invalid exp claim: {e}")

    # Issuer check (optional)
    iss = payload.get('iss')
    if iss and args.expected_issuer and iss != args.expected_issuer:
        findings.append(f"Issuer mismatch: expected {args.expected_issuer}, got {iss}")

    return status, findings, results

def self_test():
    test_secret = "testsecret"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": int(datetime.datetime.utcnow().timestamp()), "exp": int((datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).timestamp())}
    header_b = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b}.{payload_b}".encode()
    signature = hmac.new(test_secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    token = f"{header_b}.{payload_b}.{signature_b}"

    class Args:
        secret = test_secret
        jwks_url = None
        expected_issuer = None

    status, findings, results = analyze_jwt(token, Args())
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": token,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(description="JWT analysis utility")
    parser.add_argument("jwt", nargs="?", help="JWT token to analyze")
    parser.add_argument("--secret", help="Secret for HMAC verification")
    parser.add_argument("--jwks-url", help="URL to fetch JWKS for RSA/ECDSA verification")
    parser.add_argument("--expected-issuer", help="Expected issuer claim")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.jwt:
        sys.stderr.write("Error: JWT token is required unless --self-test is used\n")
        sys.exit(1)

    status, findings, results = analyze_jwt(args.jwt, args)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.jwt,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()