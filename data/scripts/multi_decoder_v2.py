# -*- coding: utf-8 -*-
"""PCT Multi-Decoder v3.0 - 3 fixes over v2"""
import sys
import base64
import binascii
import urllib.parse
import json
import codecs
import re


def identify_hash(s):
    """كشف نوع الـ Hash من طوله وصيغته"""
    s = s.strip()
    if s.startswith(("$2a$", "$2b$", "$2y$")): return "Bcrypt"
    if s.startswith("$argon2"): return "Argon2"
    if s.startswith("$6$"): return "SHA-512 crypt"
    if s.startswith("$5$"): return "SHA-256 crypt"
    if not re.fullmatch(r"[a-fA-F0-9]+", s): return None
    length_map = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
                  96: "SHA-384", 128: "SHA-512"}
    return length_map.get(len(s))


def is_valid_base64(s):
    """التحقق من Base64 مع دعم padding-less (FIX #2)"""
    s = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s): return False, None
    # كان: len(s) % 4 != 0 -> return False  (صارم زيادة)
    # الآن: يقبل 0, 2, 3 (padding-less) - مش 1
    if len(s) % 4 not in (0, 2, 3): return False, None
    if len(s) < 4: return False, None
    try:
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded, validate=True).decode('utf-8')
        if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in decoded):
            return True, decoded
    except Exception:
        pass
    return False, None


def dec_hex_safe(s):
    """Hex decoder مع validation قوي (FIX #1)"""
    try:
        s_clean = re.sub(r"[\s:\-]", "", s)
        if len(s_clean) % 2 != 0: return None
        if not re.fullmatch(r"[0-9a-fA-F]+", s_clean): return None
        if len(s_clean) < 4: return None
        result = binascii.unhexlify(s_clean).decode('utf-8', 'strict')
        printable = sum(1 for c in result if c.isprintable() or c in '\n\r\t')
        if printable / max(len(result), 1) < 0.9: return None
        return result
    except Exception:
        return None


def try_decode(s):
    out = {
        "input": s,
        "input_length": len(s),
        "detected": [],
        "decoded": {},
        "hash_identified": None,
        "note": ""
    }

    # 1. JSON detection
    try:
        json.loads(s)
        out["note"] = "Input is already valid JSON (plaintext). No decoding needed."
        out["decoded"]["info"] = "Valid JSON detected"
        return out
    except Exception:
        pass

    # 2. Hash identifier (FIX #3)
    hash_type = identify_hash(s)
    if hash_type:
        out["detected"].append({"name": f"Hash: {hash_type}", "confidence": 95})
        out["hash_identified"] = hash_type
        out["note"] = f"This looks like a {hash_type} hash (cannot be decoded, only cracked)."
        return out

    # 3. Base64 (padding-less support)
    is_b64, b64_result = is_valid_base64(s)
    if is_b64:
        out["detected"].append({"name": "Base64", "confidence": 90})
        out["decoded"]["base64"] = b64_result
        if b64_result.startswith("http"):
            out["decoded"]["url_detected"] = True

    # 4. Hex (with strict validation)
    hex_result = dec_hex_safe(s)
    if hex_result:
        out["detected"].append({"name": "Hex", "confidence": 85})
        out["decoded"]["hex"] = hex_result

    # 5. URL
    url_result = urllib.parse.unquote(s)
    if url_result != s:
        out["detected"].append({"name": "URL Encoding", "confidence": 80})
        out["decoded"]["url"] = url_result

    # 6. ROT13 (only if nothing detected)
    if not out["decoded"]:
        rot13_result = codecs.decode(s, 'rot_13')
        if rot13_result != s and " " in rot13_result:
            out["detected"].append({"name": "ROT13", "confidence": 70})
            out["decoded"]["rot13"] = rot13_result

    if not out["detected"]:
        out["note"] = "No encoding detected. May be plaintext or unsupported format."

    return out


if __name__ == "__main__":
    s = sys.argv[1] if len(sys.argv) > 1 else input("Text: ")
    print(json.dumps(try_decode(s), indent=2, ensure_ascii=False))
