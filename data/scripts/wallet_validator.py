import sys, re, json
def validate(addr):
    patterns = {
        "ethereum": r"^0x[a-fA-F0-9]{40}$",
        "tron": r"^T[a-zA-Z0-9]{33}$",
        "bitcoin": r"^(1|3)[a-zA-Z0-9]{25,34}$|^bc1[a-z0-9]{39,59}$",
    }
    out = {"address": addr, "valid": False, "chain": None}
    for chain, pat in patterns.items():
        if re.match(pat, addr): out["valid"] = True; out["chain"] = chain; break
    return out
if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else input("Address: ")
    print(json.dumps(validate(a), indent=2, ensure_ascii=False))
