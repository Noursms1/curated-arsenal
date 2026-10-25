import os
import re

SCANNER_FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

if not os.path.exists(SCANNER_FILE):
    print("[!] Scanner file not found")
    exit(1)

with open(SCANNER_FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Find and replace the entire main() function cleanly
pattern = r'def main\(\).*?(?=\nif __name__)'
match = re.search(pattern, content, re.DOTALL)

if not match:
    print("[!] Could not find main() function")
    exit(1)

new_main = '''def main():
    import argparse
    import json as _json
    
    parser = argparse.ArgumentParser(description="Advanced Domain Scanner")
    parser.add_argument("target", help="Domain or URL to scan")
    parser.add_argument("--no-redirect", action="store_true", help="Don't follow redirects")
    args = parser.parse_args()
    
    target = args.target
    is_url = target.startswith(("http://", "https://"))
    has_path = "/" in target.replace("://", "")
    
    # If it's a URL with a path (like /login), scan it directly without redirects
    if is_url and has_path:
        url = target
        follow = not args.no_redirect
        
        result = fetch_url(url, follow_redirects=follow)
        
        if "error" in result:
            print(_json.dumps({"error": result["error"], "target": target}, ensure_ascii=False))
            return
            
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        
        output = {
            "target": target,
            "domain": domain,
            "status": result.get("status"),
            "final_url": result.get("final_url"),
            "followed_redirects": follow,
            "redirects": result.get("redirects", []),
            "server": result.get("headers", {}).get("Server", "Unknown"),
            "technologies": detect_technologies(result.get("content", ""), result.get("headers", {})),
            "security_headers": {},
        }
        
        SEC = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for h in SEC:
            output["security_headers"][h] = result.get("headers", {}).get(h, "MISSING")
            
        print(_json.dumps(output, indent=2, ensure_ascii=False))
        return
    
    # Otherwise, do the standard domain scan (with redirects)
    result = scan_domain(target)
    print(_json.dumps(result, indent=2, ensure_ascii=False))


'''

content = content[:match.start()] + new_main + content[match.end():]

with open(SCANNER_FILE, "w", encoding="utf-8") as f:
    f.write(content)

import py_compile
try:
    py_compile.compile(SCANNER_FILE, doraise=True)
    print("[+] Scanner main() rewritten perfectly!")
    print("[+] Now it handles --no-redirect and paths correctly")
except py_compile.PyCompileError as e:
    print("[!] Syntax error:", e)