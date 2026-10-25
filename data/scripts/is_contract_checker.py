'''Check if an Ethereum address is a contract by querying a public JSON-RPC endpoint.'''
import sys, json, requests

def is_contract(address):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        resp = requests.post(
            "https://cloudflare-eth.com",
            json=payload,
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        result = resp.json()
        code = result.get("result", "")
        return code != "0x", code
    except Exception:
        return False, ""

def main():
    if len(sys.argv) > 1:
        addr = sys.argv[1].strip()
    else:
        addr = sys.stdin.read().strip()
    if not addr.startswith("0x") or len(addr) != 42:
        print(json.dumps({"error": "Invalid Ethereum address"}))
        return
    is_ctr, code = is_contract(addr)
    output = {
        "address": addr,
        "is_contract": is_ctr,
        "code": code
    }
    print(json.dumps(output))

if __name__ == "__main__":
    main()
