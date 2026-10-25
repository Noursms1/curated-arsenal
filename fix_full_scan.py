import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# ============================================================
# 1. Full TECH_SIGNATURES replacement (clean, valid Python)
# ============================================================
NEW_DICT = '''TECH_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"/wp-json/"],
    "Drupal": [r"/sites/default/files/", r"drupalSettings", r"Drupal[.]behaviors", r"/core/misc/drupal[.]js", r"/misc/drupal[.]js", r"Generator.{0,30}Drupal"],
    "Joomla": [r"/components/com_", r"/media/system/js/"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom[.]production", r"_reactRootContainer"],
    "Vue.js": [r"vue(?:[.]min)?[.]js", r"__vue__"],
    "Angular": [r"ng-version=", r"ng-app="],
    "Ruby on Rails": [r"csrf-param", r"csrf-token", r"/assets/[a-zA-Z0-9_\\-]+/[a-zA-Z0-9_\\-]+-[a-zA-Z0-9]{6,}[.](?:css|js)", r"action_dispatch", r"X-Request-Id"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express.js": [r"X-Powered-By:\\s*Express"],
    "PHP": [r"X-Powered-By:\\s*PHP", r"PHPSESSID"],
    "ASP.NET": [r"__VIEWSTATE", r"ASP[.]NET"],
    "jQuery": [r"jquery(?:[-.]\\d+(?:[.]\\d+)+)?(?:[.]min)?[.]js", r"jQuery v?[0-9]"],
    "Bootstrap": [r"bootstrap(?:[.]min)?[.](?:css|js)"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache/"],
    "Cloudflare": [r"cf-ray", r"cf-cache-status"],
    "Shopify": [r"cdn[.]shopify", r"X-ShopId"],
    "Google Analytics": [r"google-analytics[.]com", r"gtag\\(", r"googletagmanager[.]com"],
    "Facebook Pixel": [r"connect[.]facebook[.]net", r"fbq\\("],
}'''

# Find and replace TECH_SIGNATURES block
pattern = r'TECH_SIGNATURES\s*=\s*\{.*?\n\}'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + NEW_DICT + content[match.end():]
    print("[+] TECH_SIGNATURES replaced")
else:
    print("[!] Could not find TECH_SIGNATURES")
    exit(1)

# ============================================================
# 2. Full detect_technologies replacement (scan ALL content)
# ============================================================
NEW_FUNC = '''def detect_technologies(content, headers, debug=False):
    """Detect technologies by scanning FULL content + headers."""
    found = set()
    matches_log = []
    
    if not content:
        content = ""
    
    # Scan FULL content (up to 500KB)
    scan_content = content[:500000]
    
    header_str = ""
    try:
        if hasattr(headers, "items"):
            header_str = " ".join([str(k) + ": " + str(v) for k, v in headers.items()])
        else:
            header_str = str(headers)
    except Exception:
        header_str = str(headers)

    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            try:
                # Check headers first (usually more reliable)
                h_match = re.search(pattern, header_str, re.IGNORECASE)
                if h_match:
                    found.add(tech)
                    if debug:
                        matches_log.append("[HEADER] " + tech + ": " + pattern)
                    break
                
                # Then check body
                b_match = re.search(pattern, scan_content, re.IGNORECASE)
                if b_match:
                    found.add(tech)
                    if debug:
                        matches_log.append("[BODY@" + str(b_match.start()) + "] " + tech + ": " + pattern)
                    break
            except Exception:
                continue

    if debug:
        import sys
        for m in matches_log:
            print("[DEBUG] " + m, file=sys.stderr)

    return sorted(list(found))'''

pattern_func = r'def detect_technologies\([^)]*\):.*?(?=\ndef [a-z_])'
match_func = re.search(pattern_func, content, re.DOTALL)
if match_func:
    content = content[:match_func.start()] + NEW_FUNC + "\n\n\n" + content[match_func.end():]
    print("[+] detect_technologies replaced (full scan)")
else:
    print("[!] Could not find detect_technologies")
    exit(1)

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
# 3. SELF-TEST
# ============================================================
print("\n" + "=" * 60)
print("[*] FINAL TEST")
print("=" * 60)

import sys, importlib.util
os.chdir(os.path.dirname(FILE))
spec = importlib.util.spec_from_file_location("scanner", FILE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

for target in ["hackerone.com", "api.hackerone.com", "wordpress.org", "github.com"]:
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
                print("    ->", r["status"], "->", r["to"])
        
        print("[*] Size:", len(res.get("content", "")), "bytes")
        
        techs = scanner.detect_technologies(res.get("content", ""), res.get("headers", {}), debug=True)
        print("[*] Technologies:", techs)
    except Exception as e:
        print("[!] Error:", type(e).__name__, "-", e)