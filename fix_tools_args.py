import os
import re

BASE_DIR = r"C:\users\nour\curated-arsenal"
APP_FILE = os.path.join(BASE_DIR, "app.py")
SCANNER_FILE = os.path.join(BASE_DIR, "data", "scripts", "advanced_domain_scanner_v2.py")
COOKIE_FILE = os.path.join(BASE_DIR, "data", "scripts", "cookie_security_analyzer.py")
CRTSH_FILE = os.path.join(BASE_DIR, "data", "scripts", "crtsh.py")

# ============================================================
# FIX 1: Cookie Analyzer - auto-add https:// prefix
# ============================================================
if os.path.exists(COOKIE_FILE):
    with open(COOKIE_FILE, "r", encoding="utf-8") as f:
        ck = f.read()
    
    if 'if not url.startswith' not in ck:
        # Find where url is set
        ck = re.sub(
            r'(url\s*=\s*sys\.argv\[1\]\s*if\s*len\(sys\.argv\)\s*>\s*1\s*else\s*sys\.stdin\.read\(\)\.strip\(\))',
            r'\1\n    if not url.startswith(("http://", "https://")):\n        url = "https://" + url',
            ck
        )
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            f.write(ck)
        print("[+] Cookie Analyzer: auto-adds https:// prefix")
    else:
        print("[*] Cookie Analyzer already fixed")

# ============================================================
# FIX 2: Crtsh - strip path from domain
# ============================================================
if os.path.exists(CRTSH_FILE):
    with open(CRTSH_FILE, "r", encoding="utf-8") as f:
        crtsh = f.read()
    
    if 'clean_domain' not in crtsh and 'replace("http://"' not in crtsh:
        # Add domain cleaning at start
        if 'def main(' in crtsh:
            crtsh = crtsh.replace(
                'def main(',
                'def _clean_target(t):\n    return t.replace("http://", "").replace("https://", "").split("/")[0].split("?")[0]\n\ndef main(',
                1
            )
            # Apply to the argument
            crtsh = re.sub(
                r'(\w+)\s*=\s*sys\.argv\[1\]',
                r'\1 = _clean_target(sys.argv[1])',
                crtsh,
                count=1
            )
            with open(CRTSH_FILE, "w", encoding="utf-8") as f:
                f.write(crtsh)
            print("[+] Crtsh: strips path from domain")
        else:
            print("[!] Could not find main() in Crtsh")
    else:
        print("[*] Crtsh already has domain cleaning")

# ============================================================
# FIX 3: Advanced Domain Scanner - add --no-redirect flag + preserve path
# ============================================================
with open(SCANNER_FILE, "r", encoding="utf-8") as f:
    scanner = f.read()

# Add argparse if not present + no-redirect flag
if 'no_redirect' not in scanner:
    # Find main() function and replace argument parsing
    old_main_pattern = r'def main\(\).*?(?=\nif __name__)'
    match = re.search(old_main_pattern, scanner, re.DOTALL)
    
    if match:
        new_main = '''def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Domain or URL to scan")
    parser.add_argument("--no-redirect", action="store_true", help="Don't follow redirects (preserves path)")
    parser.add_argument("--path", action="store_true", help="Preserve URL path (e.g., /login)")
    args = parser.parse_args()
    
    target = args.target
    follow = not args.no_redirect
    
    # Preserve path if requested (or auto-detect if target has path)
    has_path = "/" in target.replace("://", "")
    
    if has_path or args.path:
        # Scan full URL with path, don't follow redirects
        import json as _j
        url = target if target.startswith(("http://", "https://")) else "https://" + target
        result = fetch_url(url, follow_redirects=False)
        
        if "error" in result:
            print(_j.dumps({"error": result["error"], "target": target}, ensure_ascii=False))
            return
        
        # Extract domain for DNS/SSL info
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        output = {
            "target": target,
            "domain": domain,
            "url_scanned": url,
            "final_url": result.get("final_url"),
            "status": result.get("status"),
            "redirects": result.get("redirects", []),
            "server": result.get("headers", {}).get("Server", "Unknown"),
            "security_headers": {},
            "technologies": detect_technologies(result.get("content", ""), result.get("headers", {})),
            "content_length": len(result.get("content", "")),
            "followed_redirect": False
        }
        
        # Security headers check
        SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for h in SEC_HEADERS:
            output["security_headers"][h] = result.get("headers", {}).get(h, "MISSING")
        
        print(_j.dumps(output, indent=2, ensure_ascii=False))
        return
    
    # Normal domain scan (existing behavior)
    result = scan_domain(target)
    print(json.dumps(result, indent=2, ensure_ascii=False))


'''
        scanner = scanner[:match.start()] + new_main + scanner[match.end():]
        
        with open(SCANNER_FILE, "w", encoding="utf-8") as f:
            f.write(scanner)
        
        import py_compile
        try:
            py_compile.compile(SCANNER_FILE, doraise=True)
            print("[+] Advanced Scanner: added --no-redirect + path preservation")
        except py_compile.PyCompileError as e:
            print("[!] Syntax error in scanner:", e)
    else:
        print("[!] Could not find main() in scanner")

# ============================================================
# FIX 4: Smart Scanner - pass appropriate args to each tool
# ============================================================
with open(APP_FILE, "r", encoding="utf-8") as f:
    app = f.read()

# Replace smart scan tool execution logic
old_exec = '''    for tool in selected_tools:
        tool_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
        if not os.path.exists(tool_path):
            results.append({
                "tool": tool["name"],
                "status": "skipped",
                "output": "File not found on disk."
            })
            continue
        
        try:
            proc = subprocess.run(
                [sys.executable, tool_path, target],
                capture_output=True, text=True, timeout=90,
                cwd=os.path.dirname(tool_path),
                encoding="utf-8", errors="replace"
            )'''

new_exec = '''    for tool in selected_tools:
        tool_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
        if not os.path.exists(tool_path):
            results.append({
                "tool": tool["name"],
                "status": "skipped",
                "output": "File not found on disk."
            })
            continue
        
        # Smart argument injection based on tool
        tool_name = tool.get("name", "").lower()
        extra_args = []
        
        # Determine proper target arg
        import re as _re
        domain_only = _re.sub(r"^https?://", "", target).split("/")[0].split("?")[0]
        
        if "dns_axfr" in tool_name or "axfr" in tool_name:
            # Needs 2 args: nameserver + domain - skip
            results.append({
                "tool": tool["name"],
                "status": "skipped",
                "output": "Requires nameserver IP + domain. Skipping in smart mode."
            })
            continue
        elif "crtsh" in tool_name or "subenum" in tool_name or "subdomain" in tool_name:
            # Needs domain only (no path)
            exec_target = domain_only
        elif "domain_scanner" in tool_name or "scanner" in tool_name:
            # Needs full URL/path for accurate detection
            if "/" in target and target.count("/") > 1:
                exec_target = target
                extra_args = ["--no-redirect"]
            else:
                exec_target = domain_only
        elif "cookie" in tool_name or "http_" in tool_name or "bypass" in tool_name:
            # Needs full URL with scheme
            exec_target = target if target.startswith(("http://", "https://")) else "https://" + target
        else:
            exec_target = target
        
        try:
            proc = subprocess.run(
                [sys.executable, tool_path, exec_target] + extra_args,
                capture_output=True, text=True, timeout=90,
                cwd=os.path.dirname(tool_path),
                encoding="utf-8", errors="replace"
            )'''

if old_exec in app:
    app = app.replace(old_exec, new_exec)
    with open(APP_FILE, "w", encoding="utf-8") as f:
        f.write(app)
    
    import py_compile
    try:
        py_compile.compile(APP_FILE, doraise=True)
        print("[+] Smart Scanner: proper arg injection per tool")
    except py_compile.PyCompileError as e:
        print("[!] Syntax error in app.py:", e)
else:
    print("[!] Could not find tool execution block")

print("\n" + "=" * 60)
print("[✅] All 4 fixes applied!")
print("=" * 60)