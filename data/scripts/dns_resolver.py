import sys
import socket
import json

def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip, "status": "success"}
    except Exception as e:
        return {"domain": domain, "error": str(e), "status": "failed"}

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(resolve(target), indent=2))