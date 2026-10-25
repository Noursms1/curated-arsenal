import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Find the "if __name__" block (goes to end of file)
pattern = r'if __name__ == "__main__":.*$'
match = re.search(pattern, content, re.DOTALL)

if not match:
    print("[!] Could not find if __name__ block")
    exit(1)

# New CLI entry point with argparse + --no-redirect support
new_entry = '''def main():
    """CLI Entry Point with redirect control."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Domain Scanner")
    parser.add_argument("target", help="Domain, IP, or URL to scan")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects (keeps original URL)")
    args = parser.parse_args()
    
    target = args.target
    
    # Detect if target is a full URL with path
    is_url_with_path = target.startswith(("http://", "https://")) and target.count("/") > 3
    
    # Also detect path-only (like hackerone.com/login)
    stripped = target.replace("http://", "").replace("https://", "")
    has_path = "/" in stripped
    
    if has_path or args.no_redirect:
        # Direct URL scan without following redirects
        url = target if target.startswith(("http://", "https://")) else "https://" + target
        
        print("[*] جاري فحص الرابط مباشرة: " + url + "...", file=sys.stderr)
        
        result = fetch_url(url, timeout=10, follow_redirects=False)
        
        if "error" in result:
            print(json.dumps({"error": result["error"], "target": target}, ensure_ascii=False))
            return
        
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Build detailed output
        output = {
            "target": target,
            "domain": domain,
            "scan_type": "direct_url",
            "status": result.get("status"),
            "final_url": result.get("final_url", url),
            "followed_redirects": False,
            "redirects": result.get("redirects", []),
            "server": result.get("headers", {}).get("Server", "Unknown"),
            "content_length": len(result.get("content", "")),
            "technologies": detect_technologies(result.get("content", ""), result.get("headers", {})),
            "security_headers": {},
        }
        
        SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for h in SEC_HEADERS:
            output["security_headers"][h] = result.get("headers", {}).get(h, "MISSING")
            
        # SSL info
        try:
            output["ssl"] = get_ssl_info(domain)
        except Exception:
            output["ssl"] = {"info": "SSL check skipped"}
        
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return
    
    # Standard domain scan (with redirects)
    print("[*] جاري فحص النطاق: " + target + "...", file=sys.stderr)
    print("[*] هذا قد يستغرق 10-30 ثانية...", file=sys.stderr)
    
    scan_result = scan_domain(target)
    print(json.dumps(scan_result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
'''

# Replace the entire old block
content = content[:match.start()] + new_entry

with open(FILE, "w", encoding="utf-8") as f:
    f.write(content)

import py_compile
try:
    py_compile.compile(FILE, doraise=True)
    print("[+] advanced_domain_scanner_v2.py rewritten successfully!")
    print("[+] Added: def main() with argparse + --no-redirect support")
except py_compile.PyCompileError as e:
    print("[!] Syntax error:", e)
    exit(1)

# ============================================================
# TEST
# ============================================================
print()
print("=" * 60)
print("[*] TESTING")
print("=" * 60)

import subprocess, sys, json

# Test 1: Standard domain (should show Drupal)
print()
print("[TEST 1] Standard scan: hackerone.com")
print("-" * 60)
r1 = subprocess.run([sys.executable, FILE, "hackerone.com"], capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
try:
    data = json.loads(r1.stdout)
    print("  Technologies:", data.get("technologies", []))
    print("  Redirects:", data.get("redirects", []))
    print("  Final URL:", data.get("final_url", "N/A"))
except Exception as e:
    print("  Parse error:", e)

# Test 2: URL with path (should show Rails, no redirect)
print()
print("[TEST 2] Direct URL scan: hackerone.com/login --no-redirect")
print("-" * 60)
r2 = subprocess.run([sys.executable, FILE, "hackerone.com/login", "--no-redirect"], capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
try:
    data = json.loads(r2.stdout)
    print("  Technologies:", data.get("technologies", []))
    print("  Status:", data.get("status"))
    print("  Final URL:", data.get("final_url"))
    print("  Followed Redirects:", data.get("followed_redirects", "N/A"))
except Exception as e:
    print("  Parse error:", e)
    print("  Raw:", r2.stdout[:500])