import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Replace ONLY the Drupal line with STRICT patterns
# Real Drupal sites always have one of these in HTML head/body:
# - <meta name="Generator" content="Drupal X">
# - drupalSettings = {...}  (JS object, ONLY in Drupal)
# - Drupal.behaviors...    (JS, ONLY in Drupal)
# - /core/misc/drupal.js   (Drupal 8+ core asset)
# - /misc/drupal.js        (Drupal 7 core asset)
OLD_DRUPAL = r'"Drupal": \[r"/sites/default/files/(?:css|js|public)/", r"drupalSettings\\s*=", r"X-Generator.*Drupal"\],'

NEW_DRUPAL = r'"Drupal": [r"drupalSettings\\s*=\\s*\\{", r"Drupal\\.behaviors", r"/core/misc/drupal\\.js", r"/misc/drupal\\.js", r"<meta\\s+name=[\x27\x22]Generator[\x27\x22]\\s+content=[\x27\x22]Drupal"],'

# Try to replace with regex since the exact string may have slight variations
pattern = r'"Drupal":\s*\[.*?\]'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + NEW_DRUPAL + content[match.end():]
    print("[+] Drupal pattern made STRICT")
    print("[+] OLD:", match.group(0)[:80], "...")
    print("[+] NEW:", NEW_DRUPAL[:80], "...")
else:
    print("[!] Could not find Drupal pattern, manual fix needed")
    # Fallback: just find the line
    for line in content.split("\n"):
        if '"Drupal"' in line:
            print("[*] Found Drupal line:", line[:150])

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
# SELF-TEST with DETAILED DEBUG
# ============================================================
print("\n" + "=" * 60)
print("[*] SELF-TEST with match context")
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
    html_content = resp.read().decode("utf-8", errors="replace")
    resp_headers = dict(resp.headers)
    print("[*] Fetched " + str(len(html_content)) + " bytes")
    
    techs = scanner.detect_technologies(html_content, resp_headers, debug=True)
    print("\n[RESULT] Detected technologies:")
    for t in techs:
        print("  - " + t)