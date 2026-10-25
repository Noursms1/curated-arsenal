import sys, json, re

"""evm_address_validator
أداة سطر أوامر تتحقق من صحة عنوان محفظة EVM.
تستقبل العنوان عبر وسيط سطر الأوامر أو من stdin وتطبع نتيجة JSON.
"""

def is_valid_evm_address(addr: str) -> bool:
    """يتحقق ما إذا كان العنوان يطابق النمط 0x متبوعًا بـ 40 حرفًا سداسي عشري."""
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", addr))

def main():
    if len(sys.argv) > 1:
        address = sys.argv[1].strip()
    else:
        address = sys.stdin.read().strip()

    address = address.lower()
    valid = is_valid_evm_address(address)
    result = {
        "address": address,
        "valid": valid,
        "chains": ["Ethereum", "BSC", "Polygon", "Avalanche", "Fantom"] if valid else []
    }
    sys.stdout.write(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
