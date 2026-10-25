#!/usr/bin/env python3
"""
أداة للتحقق من صحة عنوان محفظة إيثيريوم (أو أي شبكة EVM) من حيث الصيغة.
تستقبل العنوان عبر سطر الأوامر أو stdin وتطبع نتيجة JSON.
"""

import sys
import json
import re

def is_valid_eth_address(addr: str) -> bool:
    # يجب أن يبدأ بـ 0x ويتبع 40 حرفًا سداسي عشري
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", addr.strip()))

def main():
    if len(sys.argv) > 1:
        address = sys.argv[1]
    else:
        address = sys.stdin.read().strip()
    valid = is_valid_eth_address(address)
    result = {
        "address": address,
        "valid": valid,
        "chain": "ethereum"
    }
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
