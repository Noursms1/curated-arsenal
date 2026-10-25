import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Using \x22 for double-quote, \x27 for single-quote to avoid conflicts
NEW_DICT = r'''TECH_SIGNATURES = {
    "WordPress": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
    "Drupal": [r"/sites/default/files/(?:css|js|public)/", r"drupalSettings\s*=", r"X-Generator.*Drupal"],
    "Joomla": [r"/components/com_", r"/media/system/js/"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom\.production", r"_reactRootContainer"],
    "Vue.js": [r"vue(?:\.min)?\.js", r"__vue__"],
    "Angular": [r"ng-version=", r"ng-app="],
    "Ruby on Rails": [r"csrf-param", r"/assets/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+-[a-zA-Z0-9]{6,}\.(?:css|js)", r"X-Runtime", r"action_dispatch"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express.js": [r"X-Powered-By:\s*Express"],
    "PHP": [r"X-Powered-By:\s*PHP", r"PHPSESSID"],
    "ASP.NET": [r"X-Powered-By:\s*ASP", r"__VIEWSTATE"],
    "jQuery": [r"jquery(?:-\d+(?:\.\d+)+)?(?:\.min)?\.js"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.(?:css|js)"],
    "Nginx": [r"^nginx/"],
    "Apache": [r"Apache/"],
    "Cloudflare": [r"cf-ray", r"cf-cache-status"],
    "Shopify": [r"cdn\.shopify", r"X-ShopId"],
    "Google Analytics": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"ga\(\x27create\x27"],
    "Facebook Pixel": [r"connect\.facebook\.net/[^/]+/fbevents\.js", r"fbq\(\x27init\x27"],
}'''

pattern = r'TECH_SIGNATURES\s*=\s*\{.*?\n\}'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + NEW_DICT + content[match.end():]
    print("[+] TECH_SIGNATURES replaced with SAFE patterns")
else:
    print("[!] TECH_SIGNATURES not found")

NEW_FUNC = '''def detect_technologies(content, headers, debug=False):
    """Detect technologies with STRICT patterns."""
    found = set()
    matches_log = []
    
    if not content:
        content = ""
    scan_content = content[:50000]
    
    header_str = ""
    try:
        header_str = " ".join([str(k) + ": " + str(v) for k, v in dict(headers).items()])
    except Exception:
        header_str = str(headers)

    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            try:
                if re.search(pattern, header_str, re.IGNORECASE):
                    found.add(tech)
                    if debug:
                        matches_log.append("[HEADER] " + tech + ": " + pattern)
                    break
                elif re.search(pattern, scan_content, re.IGNORECASE):
                    found.add(tech)
                    if debug:
                        matches_log.append("[BODY] " + tech + ": " + pattern)
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
    print("[+] detect_technologies replaced")

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
try:
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        html_content = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.headers)
        print("[*] Fetched " + str(len(html_content)) + " bytes")
        
        techs = scanner.detect_technologies(html_content, resp_headers, debug=True)
        print("\n[RESULT] Detected technologies:")
        for t in techs:
            print("  - " + t)
except Exception as e:
    print("[!] Fetch failed: " + str(e))