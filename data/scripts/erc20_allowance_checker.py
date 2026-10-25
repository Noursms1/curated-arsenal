import sys
import json
import requests
from urllib.parse import urljoin

def build_allowance_data(owner: str, spender: str) -> str:
    """تُعيد بيانات الـ calldata لتابع allowance(address,address) في ERC20.
    يتم ترميز العناوين إلى 32 بايت كلًّا مع بادئة 0x.
    """
    method_id = '0xdd62ed3e'  # keccak256('allowance(address,address)')[:4]
    owner = owner.lower().replace('0x', '').rjust(64, '0')
    spender = spender.lower().replace('0x', '').rjust(64, '0')
    return method_id + owner + spender

def query_allowance(rpc_url: str, token: str, owner: str, spender: str) -> int:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": token,
                "data": build_allowance_data(owner, spender)
            },
            "latest"
        ]
    }
    try:
        resp = requests.post(rpc_url, json=payload, timeout=10, verify=False)
        resp.raise_for_status()
        result = resp.json()
        hex_val = result.get('result', '0x0')
        return int(hex_val, 16)
    except Exception as e:
        # في حالة الفشل نعيد -1 للإشارة إلى الخطأ
        return -1

def main():
    """تشغيل الأداة من سطر الأوامر.
    الاستخدام: python erc20_allowance_checker.py <rpc_url> <token_address> <owner_address> <spender_address>
    """
    if len(sys.argv) != 5:
        sys.stderr.write('Usage: python erc20_allowance_checker.py <rpc_url> <token_address> <owner_address> <spender_address>\n')
        sys.exit(1)

    rpc_url, token, owner, spender = sys.argv[1:5]
    allowance = query_allowance(rpc_url, token, owner, spender)
    output = {
        "token": token,
        "owner": owner,
        "spender": spender,
        "allowance": allowance
    }
    print(json.dumps(output, ensure_ascii=False))

if __name__ == "__main__":
    main()
