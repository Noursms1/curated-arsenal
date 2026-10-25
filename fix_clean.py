import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Fix double comma first
content = content.replace(",,", ",")

# 2. Replace the broken Drupal line with clean version
# Using [.] instead of \. and no \s (safer patterns)
NEW_DRUPAL_LINE = '    "Drupal": [r"drupalSettings", r"Drupal[.]behaviors", r"/core/misc/drupal[.]js", r"/misc/drupal[.]js", r"Generator.{0,50}Drupal"],'

lines = content.split("\n")
fixed = False
for i, line in enumerate(lines):
    if '"Drupal"' in line and ('r"' in line or "r'" in line):
        print(f"[*] Found Drupal line at {i+1}")
        print(f"    OLD: {line[:100]}...")
        lines[i] = NEW_DRUPAL_LINE
        print(f"    NEW: {NEW_DRUPAL_LINE[:100]}...")
        fixed = True
        break

if not fixed:
    print("[!] Could not find Drupal line")
    exit(1)

content = "\n".join(lines)

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
print("[*] SELF-TEST on hackerone.com")
print("=" * 60)

import sys, ssl, urllib.request, importlib.util
os.chdir(os.path.dirname(FILE))

spec = importlib.util.spec_from_file_location("scanner", FILE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request("https://hackerone.com", headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
    html = resp.read().decode("utf-8", errors="replace")
    hdrs = dict(resp.headers)
    print("[*] Fetched " + str(len(html)) + " bytes")
    print()
    
    techs = scanner.detect_technologies(html, hdrs, debug=True)
    print("\n[RESULT] Detected technologies:")
    for t in techs:
        print("  - " + t)