import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Check if USER_AGENT is defined
has_ua = bool(re.search(r'^USER_AGENT\s*=', content, re.MULTILINE))
print(f"[*] USER_AGENT defined: {has_ua}")

if not has_ua:
    print("[+] Adding USER_AGENT definition")
    # Insert after imports
    lines = content.split("\n")
    insert_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("import ") or line.strip().startswith("from "):
            insert_idx = i + 1
        elif line.strip() == "" and i > insert_idx:
            break
    
    ua_line = 'USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"'
    lines.insert(insert_idx, ua_line)
    content = "\n".join(lines)
    print(f"[+] USER_AGENT inserted at line {insert_idx + 1}")

# 2. Also add a safety fallback inside fetch_url
if 'USER_AGENT' in content and 'USER_AGENT_NOT_SET' not in content:
    # Add global fallback near top
    if 'try:\n    USER_AGENT' not in content:
        # Ensure it exists at module level
        pass

# 3. Also patch scan_domain for redirect tracking
old_scan_pattern = r'def scan_domain\([^)]*\):'
match = re.search(old_scan_pattern, content)
if match:
    print("[*] Found scan_domain, checking for redirect integration")
    # Look for the section where https_result is used
    if 'result["https_status"] = https_result.get("status")' in content:
        if 'result["final_url"]' not in content:
            content = content.replace(
                'result["https_status"] = https_result.get("status")',
                '''result["https_status"] = https_result.get("status")
        result["final_url"] = https_result.get("final_url", "https://" + domain)
        result["redirects"] = https_result.get("redirects", [])
        if result["final_url"].rstrip("/") != ("https://" + domain).rstrip("/"):
            result.setdefault("findings", []).append("Redirected to: " + result["final_url"])''',
                1
            )
            print("[+] scan_domain patched for redirects")
        else:
            print("[*] scan_domain already has redirect tracking")

with open(FILE, "w", encoding="utf-8") as f:
    f.write(content)

import py_compile
try:
    py_compile.compile(FILE, doraise=True)
    print("[+] Syntax OK")
except py_compile.PyCompileError as e:
    print("[!] Syntax error:", e)
    exit(1)

# ============================================================
# SELF-TEST
# ============================================================
print("\n" + "=" * 60)
print("[*] FINAL SELF-TEST")
print("=" * 60)

import sys, importlib.util
os.chdir(os.path.dirname(FILE))
spec = importlib.util.spec_from_file_location("scanner", FILE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

for target in ["hackerone.com", "api.hackerone.com", "example.com"]:
    print("\n" + "-" * 60)
    print("TARGET:", target)
    print("-" * 60)
    try:
        res = scanner.fetch_url("https://" + target)
        if "error" in res:
            print("[!] Fetch failed:", res["error"])
            continue
        
        print("[*] Final URL:", res.get("final_url"))
        if res.get("redirects"):
            for r in res["redirects"]:
                print("    →", r["status"], "→", r["to"])
        else:
            print("[*] Redirects: None")
        
        print("[*] Status:", res.get("status"))
        print("[*] Size:", len(res.get("content", "")), "bytes")
        
        techs = scanner.detect_technologies(res.get("content", ""), res.get("headers", {}), debug=False)
        print("[*] Technologies:", techs)
    except Exception as e:
        print("[!] Error:", type(e).__name__, "-", e)
        import traceback
        traceback.print_exc()