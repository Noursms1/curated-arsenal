import sys, json, hashlib, requests

def _pad_hex(value: str, length: int = 64) -> str:
    """تجهيز قيمة hex لتكون بطول ثابت (64 حرف = 32 بايت)."""
    value = value.lower().replace('0x', '')
    return value.rjust(length, '0')

def _encode_allowance_data(owner: str, spender: str) -> str:
    """تكويد بيانات استدعاء الدالة allowance(address,address)."""
    # selector = first 4 bytes of keccak256('allowance(address,address)')
    selector = hashlib.new('keccak256', b'allowance(address,address)').hexdigest()[:8]
    return '0x' + selector + _pad_hex(owner) + _pad_hex(spender)

def _call_rpc(rpc_url: str, to: str, data: str) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"]
    }
    resp = requests.post(rpc_url, json=payload, timeout=10, verify=False)
    resp.raise_for_status()
    result = resp.json()
    if 'error' in result:
        raise RuntimeError(result['error'].get('message', 'RPC error'))
    return result.get('result', '0x0')

def _hex_to_int(hex_str: str) -> int:
    return int(hex_str, 16)

def main():
    """تشغيل الأداة من سطر الأوامر.
    الاستخدام: python token_allowance_checker.py <token_address> <owner_address> <spender_address> [rpc_url]
    """
    if len(sys.argv) < 4:
        sys.stderr.write('Usage: python token_allowance_checker.py <token> <owner> <spender> [rpc_url]\n')
        sys.exit(1)
    token = sys.argv[1]
    owner = sys.argv[2]
    spender = sys.argv[3]
    rpc_url = sys.argv[4] if len(sys.argv) > 4 else 'https://cloudflare-eth.com'

    try:
        data = _encode_allowance_data(owner, spender)
        raw = _call_rpc(rpc_url, token, data)
        allowance = _hex_to_int(raw)
        output = {
            "token": token,
            "owner": owner,
            "spender": spender,
            "allowance": allowance
        }
        print(json.dumps(output, ensure_ascii=False))
    except Exception as e:
        err = {"error": str(e)}
        print(json.dumps(err, ensure_ascii=False))
        sys.exit(1)

if __name__ == '__main__':
    main()
