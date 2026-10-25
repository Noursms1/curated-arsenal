'''#!/usr/bin/env python3
"""erc20_approval_checker

أداة سطر أوامر تفحص قيمة allowance لتوكن ERC‑20 بين مالك (owner) و spender.
تستقبل ثلاثة معطيات عبر سطر الأوامر أو stdin (بترتيب: token_address owner_address spender_address).
تطبع نتيجة بصيغة JSON على stdout.
"""
import sys
import json
import requests

# Constants
RPC_URL = "https://cloudflare-eth.com"
METHOD_ID = "0xdd62ed3e"  # keccak256('allowance(address,address)')[:4]
MAX_UINT256 = (1 << 256) - 1

def pad_address(addr: str) -> str:
    """تحويل عنوان إيثيريوم إلى تمثيل 32‑byte مملوء بصفر من اليسار (بدون 0x)."""
    addr = addr.lower().replace("0x", "")
    return addr.rjust(64, "0")

def build_data(owner: str, spender: str) -> str:
    """تكوين حقل data لاستدعاء allowance(owner, spender)."""
    return METHOD_ID + pad_address(owner) + pad_address(spender)

def query_allowance(token: str, owner: str, spender: str) -> int:
    """تنفيذ eth_call للحصول على قيمة allowance كعدد صحيح."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": token, "data": build_data(owner, spender)}, "latest"]
    }
    resp = requests.post(RPC_URL, json=payload, timeout=10, verify=False)
    resp.raise_for_status()
    result = resp.json()
    hex_value = result.get("result", "0x0")
    return int(hex_value, 16)

def main():
    # قراءة المعطيات من argv أو stdin
    if len(sys.argv) == 4:
        _, token_addr, owner_addr, spender_addr = sys.argv
    else:
        # قراءة سطر واحد من stdin وفصله بمسافات
        data = sys.stdin.read().strip().split()
        if len(data) != 3:
            print(json.dumps({"error": "Expected three arguments: token_address owner_address spender_address"}))
            sys.exit(1)
        token_addr, owner_addr, spender_addr = data

    # توحيد الصيغة مع 0x
    token_addr = token_addr if token_addr.startswith("0x") else "0x" + token_addr
    owner_addr = owner_addr if owner_addr.startswith("0x") else "0x" + owner_addr
    spender_addr = spender_addr if spender_addr.startswith("0x") else "0x" + spender_addr

    try:
        allowance = query_allowance(token_addr, owner_addr, spender_addr)
        unlimited = allowance == MAX_UINT256
        output = {
            "token": token_addr,
            "owner": owner_addr,
            "spender": spender_addr,
            "allowance": str(allowance),
            "unlimited": unlimited
        }
    except Exception as e:
        output = {"error": str(e)}

    print(json.dumps(output, ensure_ascii=False))

if __name__ == "__main__":
    main()
'''