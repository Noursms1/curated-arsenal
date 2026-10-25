import os
import re

BASE_DIR = r"C:\users\nour\curated-arsenal"
APP_FILE = os.path.join(BASE_DIR, "app.py")
COOKIE_FILE = os.path.join(BASE_DIR, "data", "scripts", "cookie_security_analyzer.py")

# ============================================================
# FIX 1: Smart Scanner path detection
# ============================================================
with open(APP_FILE, "r", encoding="utf-8") as f:
    app = f.read()

# Fix the condition for path detection
old_check = '''        elif "domain_scanner" in tool_name or "scanner" in tool_name:
            # Needs full URL/path for accurate detection
            if "/" in target and target.count("/") > 1:
                exec_target = target
                extra_args = ["--no-redirect"]
            else:
                exec_target = domain_only'''

new_check = '''        elif "domain_scanner" in tool_name or "scanner" in tool_name:
            # Check if target has a path (after stripping scheme)
            stripped = _re.sub(r"^https?://", "", target)
            has_path = "/" in stripped
            if has_path:
                exec_target = target if target.startswith(("http://", "https://")) else "https://" + target
                extra_args = ["--no-redirect"]
            else:
                exec_target = domain_only'''

if old_check in app:
    app = app.replace(old_check, new_check)
    with open(APP_FILE, "w", encoding="utf-8") as f:
        f.write(app)
    print("[+] FIX 1: Smart Scanner path detection fixed")
else:
    print("[!] Could not find path check block")


# ============================================================
# FIX 2: Cookie Analyzer - proper Set-Cookie parsing
# ============================================================
if os.path.exists(COOKIE_FILE):
    with open(COOKIE_FILE, "r", encoding="utf-8") as f:
        cookie = f.read()
    
    # Replace the whole main() function with proper parsing
    old_main = re.search(r'def main\(\).*?(?=\nif __name__)', cookie, re.DOTALL)
    if old_main:
        new_main = '''def main():
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = sys.stdin.read().strip()
    
    # Auto-add https:// prefix
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    result = {"url": url, "cookies": [], "error": None}
    
    try:
        import requests
        # Use requests to get proper cookie objects
        resp = requests.get(url, timeout=15, verify=False, allow_redirects=True)
        
        # requests handles Set-Cookie parsing correctly
        for c in resp.cookies:
            result["cookies"].append({
                "name": c.name,
                "value": (c.value[:20] + "...") if c.value and len(c.value) > 20 else c.value,
                "domain": c.domain or "",
                "path": c.path or "",
                "secure": bool(c.secure),
                "httponly": "HttpOnly" in str(c._rest),
                "samesite": c._rest.get("SameSite", "MISSING") if hasattr(c, "_rest") else "MISSING",
                "expires": c.expires
            })
        
        if not result["cookies"]:
            result["info"] = "No cookies in response (this is normal for some endpoints)"
            
    except Exception as e:
        result["error"] = str(e)
    
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2))


'''
        cookie = cookie[:old_main.start()] + new_main + cookie[old_main.end():]
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write(cookie)
        print("[+] FIX 2: Cookie Analyzer uses requests.cookies (proper parsing)")
    else:
        print("[!] Could not find main() in cookie analyzer")
else:
    print("[!] Cookie file not found")

# ============================================================
# VERIFY SYNTAX
# ============================================================
import py_compile
try:
    py_compile.compile(APP_FILE, doraise=True)
    print("[+] app.py: Syntax OK")
except py_compile.PyCompileError as e:
    print("[!] app.py Syntax error:", e)

try:
    py_compile.compile(COOKIE_FILE, doraise=True)
    print("[+] cookie_security_analyzer.py: Syntax OK")
except py_compile.PyCompileError as e:
    print("[!] cookie Syntax error:", e)

print("\n" + "=" * 60)
print("[✅] Fixes applied!")
print("Restart server and test:")
print("  - hackerone.com/login should detect Ruby on Rails")
print("  - Cookie analyzer should show proper cookie names")
print("=" * 60)