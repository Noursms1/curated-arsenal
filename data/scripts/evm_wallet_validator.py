#!/usr/bin/env python3
"""Wallet address validator for EVM chains.

يقرأ العنوان من سطر الأوامر أو من stdin، يتحقق من صيغته (0x متبوع بـ 40 حرفًا سداسيًا) ويطبع نتيجة JSON.
"""
import sys, json, re

def is_valid_address(addr):
    """تتحقق إذا ما كان العنوان يطابق نمط 0x + 40 حرفًا سداسيًا."""
    if not isinstance(addr, str):
        return False
    if not addr.startswith('0x') or len(addr) != 42:
        return False
    hex_part = addr[2:]
    return bool(re.fullmatch(r'[0-9a-fA-F]{40}', hex_part))

def main():
    if len(sys.argv) > 1:
        address = sys.argv[1].strip()
    else:
        address = sys.stdin.read().strip()
    valid = is_valid_address(address)
    result = {"address": address, "valid": valid}
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
