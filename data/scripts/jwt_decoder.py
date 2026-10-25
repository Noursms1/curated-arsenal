import sys, json, base64, hashlib, hmac

"""JWT Decoder and optional validator.

Usage:
    echo '<jwt>' | python jwt_decoder.py [secret]
or
    python jwt_decoder.py <jwt> [secret]

If a secret is supplied, the tool verifies the signature using HS256.
It prints a JSON object containing the header, payload and the result of the verification.
"""

def b64url_decode(inp):
    inp += '=' * (-len(inp) % 4)
    return base64.urlsafe_b64decode(inp.encode())

def main():
    # read token from stdin if piped, otherwise from argv
    data = sys.stdin.read().strip() if not sys.stdin.isatty() else ''
    if len(sys.argv) > 1:
        token = sys.argv[1]
    elif data:
        token = data
    else:
        print(json.dumps({"error": "No token provided"}, ensure_ascii=False))
        return

    secret = sys.argv[2] if len(sys.argv) > 2 else None
    parts = token.split('.')
    if len(parts) != 3:
        print(json.dumps({"error": "Invalid JWT format"}, ensure_ascii=False))
        return
    header_b, payload_b, signature_b = parts
    try:
        header = json.loads(b64url_decode(header_b))
        payload = json.loads(b64url_decode(payload_b))
    except Exception as e:
        print(json.dumps({"error": "Decoding error", "detail": str(e)}, ensure_ascii=False))
        return

    result = {"header": header, "payload": payload}
    if secret is not None:
        try:
            alg = header.get("alg", "")
            if alg != "HS256":
                result["signature_valid"] = False
            else:
                signing_input = f"{header_b}.{payload_b}".encode()
                expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                actual_sig = b64url_decode(signature_b)
                result["signature_valid"] = hmac.compare_digest(expected_sig, actual_sig)
        except Exception:
            result["signature_valid"] = False
    else:
        result["signature_valid"] = None

    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
