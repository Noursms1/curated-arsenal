import sys
import json
import requests

RPC_URL = "https://cloudflare-eth.com"
METHOD_ID = "0xdd62ed3e"  # keccak256('allowance(address,address)')[:4]

def pad_address(addr: str) -> str:
    addr = addr.lower().replace("0x", "")
    if len(addr) != 40:
        raise ValueError(f"عنوان غير صالح: {addr}")
    return addr.rjust(64, "0")

def build_data(owner: str, spender: str) -> str:
    return METHOD_ID + pad_address(owner) + pad_address(spender)

def get_allowance(owner: str, token: str, spender: str) -> int:
    data = build_data(owner, spender)
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": token, "data": data}, "latest"]
    }
    resp = requests.post(RPC_URL, json=payload, timeout=10, verify=False)
    resp.raise_for_status()
    result = resp.json()
    if "error" in result:
        raise RuntimeError(result["error"].get("message", "RPC error"))
    hex_value = result.get("result", "0x0")
    return int(hex_value, 16)

def main():
    if len(sys.argv) != 4:
        print(json.dumps({"error": "Usage: python token_approval_checker.py <owner> <token> <spender>"}))
        sys.exit(1)
    owner, token, spender = sys.argv[1:4]
    try:
        allowance = get_allowance(owner, token, spender)
        output = {
            "owner": owner,
            "token": token,
            "spender": spender,
            "allowance": str(allowance)
        }
    except Exception as e:
        output = {"error": str(e)}
    print(json.dumps(output, ensure_ascii=False))

if __name__ == "__main__":
    main()
