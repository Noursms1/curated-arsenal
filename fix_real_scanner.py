import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

if not os.path.exists(FILE):
    print("[!] File not found:", FILE)
    exit(1)

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

print("[*] Original size:", len(content), "chars")

# ============================================================
# 1. REPLACE TECH_SIGNATURES dict
# ============================================================
NEW_DICT = '''TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"X-Powered-By.*WordPress"],
    "Drupal": [r"Drupal\\.settings", r"drupalSettings", r"/sites/default/files/", r"X-Generator.*Drupal", r"Drupal-"],
    "Joomla": [r"joomla", r"/components/com_"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom", r"_reactRootContainer"],
    "Vue.js": [r"vue\\.js", r"__vue__", r"data-v-"],
    "Angular": [r"ng-version", r"angular", r"ng-app"],
    "Ruby on Rails": [r"csrf-param[^>]*authenticity_token", r"/assets/[a-z\\-]+-[a-zA-Z0-9]{6,}\\.", r"rails-ujs", r"X-Runtime", r"x-request-id", r"action_dispatch"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN", r"Laravel"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express.js": [r"X-Powered-By.*Express"],
    "PHP": [r"X-Powered-By.*PHP", r"PHPSESSID"],
    "ASP.NET": [r"ASP\\.NET", r"X-Powered-By.*ASP", r"__VIEWSTATE"],
    "jQuery": [r"jquery(?:\\.min)?\\.js", r"jQuery v?[0-9]"],
    "Bootstrap": [r"bootstrap(?:\\.min)?\\.(?:css|js)", r"class=\\"[^\\"]*\\bcontainer-fluid\\b"],
    "Nginx": [r"^nginx", r"nginx/"],
    "Apache": [r"apache", r"Apache/"],
    "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cf-cache-status"],
    "Shopify": [r"shopify", r"cdn\\.shopify", r"X-ShopId"],
    "Google Analytics": [r"google-analytics\\.com", r"gtag\\(", r"ga\\('create'"],
    "Facebook Pixel": [r"fbq\\(", r"facebook\\.com/tr"],
}'''

pattern = r'TECH_SIGNATURES\s*=\s*\{[^}]*\}'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + NEW_DICT + content[match.end():]
    print("[+] Replaced TECH_SIGNATURES")
else:
    print("[!] TECH_SIGNATURES not found - manual check needed")

# ============================================================
# 2. REPLACE detect_technologies function
# ============================================================
NEW_FUNC = '''def detect_technologies(content, headers):
    """Detect technologies used by the target with high precision."""
    found = set()
    if not content:
        content = ""
    header_str = ""
    try:
        header_str = " ".join(str(f"{k}: {v}") for k, v in dict(headers).items())
    except Exception:
        header_str = str(headers)

    # Scan both content and headers
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, header_str, re.IGNORECASE):
                    found.add(tech)
                    break
            except Exception:
                continue

    # Server header check
    server_lower = ""
    try:
        server_lower = str(headers.get("Server", "")).lower()
    except Exception:
        pass
    if "nginx" in server_lower:
        found.add("Nginx")
    if "apache" in server_lower:
        found.add("Apache")
    if "cloudflare" in server_lower:
        found.add("Cloudflare")

    return sorted(list(found))'''

# Match from "def detect_technologies" to next "def " or end
pattern_func = r'def detect_technologies\([^)]*\):.*?(?=\ndef |\ndef [a-z_])'
match_func = re.search(pattern_func, content, re.DOTALL)
if match_func:
    content = content[:match_func.start()] + NEW_FUNC + "\n\n\n" + content[match_func.end():]
    print("[+] Replaced detect_technologies")
else:
    print("[!] detect_technologies not found")

# ============================================================
# 3. SAVE + VERIFY
# ============================================================
with open(FILE, "w", encoding="utf-8") as f:
    f.write(content)

print("[+] File saved. New size:", len(content), "chars")

import py_compile
try:
    py_compile.compile(FILE, doraise=True)
    print("[+] Syntax valid!")
except py_compile.PyCompileError as e:
    print("[!] Syntax error:", e)

# Quick self-test
print("\n[*] Running self-test on hackerone.com...")
import subprocess, sys
result = subprocess.run([sys.executable, FILE, "hackerone.com"], capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
# Find technologies in output
import json as _json
try:
    start = result.stdout.find("{")
    if start >= 0:
        data = _json.loads(result.stdout[start:])
        print("[TECH DETECTED]:", data.get("technologies", []))
except Exception as e:
    print("[!] Could not parse output:", e)