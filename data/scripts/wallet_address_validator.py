#!/usr/bin/env python3
"""
أداة للتحقق من صحة عنوان إيثيريوم وفق معيار EIP‑55.
تستقبل العنوان من سطر الأوامر أو stdin وتطبع نتيجة JSON.
"""

import sys
import json
import re
import hashlib

def is_valid_hex_address(addr: str) -> bool:
    """يتأكد أن العنوان يتبع صيغة 0x متبوعة بـ40 حرفًا سداسي عشري."""
    return bool(re.fullmatch(r'0x[0-9a-fA-F]{40}', addr))

def checksum_address(addr: str) -> str:
    """يرجع النسخة ذات التحقق من المجموع (EIP‑55)."""
    addr_clean = addr.lower().replace('0x', '')
    keccak = hashlib.new('sha3_256')
    keccak.update(addr_clean.encode('utf-8'))
    hash_hex = keccak.hexdigest()
    checksummed = '0x'
    for i, c in enumerate(addr_clean):
        if int(hash_hex[i], 16) >= 8:
            checksummed += c.upper()
        else:
            checksummed += c.lower()
    return checksummed

def main():
    if len(sys.argv) > 1:
        input_addr = sys.argv[1].strip()
    else:
        input_addr = sys.stdin.read().strip()
    result = {
        "address": input_addr,
        "valid": False,
        "checksum_correct": False,
        "checksummed": None
    }
    if is_valid_hex_address(input_addr):
        result["valid"] = True
        checksummed = checksum_address(input_addr)
        result["checksummed"] = checksummed
        result["checksum_correct"] = (input_addr == checksummed)
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
