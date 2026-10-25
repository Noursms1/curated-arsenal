import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

NEW_DICT = '''TECH_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"/wp-json/"],
    "Drupal": [r"/sites/default/files/", r"drupalSettings", r"Drupal[.]behaviors", r"/core/misc/drupal[.]js", r"/misc/drupal[.]js", r"Generator.{0,30}Drupal"],
    "Joomla": [r"/components/com_", r"/media/system/js/"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom[.]production", r"_reactRootContainer", r"data-reactroot", r"react[.]production[.]min"],
    "Next.js": [r"/_next/static/", r"__NEXT_DATA__"],
    "Nuxt.js": [r"__NUXT__", r"/_nuxt/"],
    "Vue.js": [r"vue(?:[.]min)?[.]js", r"__vue__", r"data-v-[a-f0-9]{8}"],
    "Angular": [r"ng-version=", r"ng-app=", r"angular(?:[.]min)?[.]js"],
    "Svelte": [r"__svelte", r"svelte-"],
    "Astro": [r"data-astro-", r"/_astro/"],
    "Ruby on Rails": [r"csrf-param", r"csrf-token", r"/assets/[a-zA-Z0-9_\\-]+/[a-zA-Z0-9_\\-]+-[a-zA-Z0-9]{6,}[.](?:css|js)", r"action_dispatch", r"X-Request-Id"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express.js": [r"X-Powered-By:\\s*Express"],
    "PHP": [r"X-Powered-By:\\s*PHP", r"PHPSESSID"],
    "ASP.NET": [r"__VIEWSTATE", r"ASP[.]NET"],
    "jQuery": [r"jquery(?:[-.]\\d+(?:[.]\\d+)+)?(?:[.]min)?[.]js", r"jQuery v?[0-9]"],
    "Bootstrap": [r"bootstrap(?:[.]min)?[.](?:css|js)"],
    "Tailwind CSS": [r"tailwind"],
    "Turbo (Hotwire)": [r"data-turbo-track", r"turbo-frame", r"@hotwired/turbo"],
    "Stimulus": [r"data-controller=", r"data-action="],
    "GitHub": [r"github[.]com/", r"githubusercontent[.]com", r"github-actions", r"data-hydro-click"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache/"],
    "Cloudflare": [r"cf-ray", r"cf-cache-status"],
    "Shopify": [r"cdn[.]shopify", r"X-ShopId"],
    "Google Analytics": [r"google-analytics[.]com", r"gtag\\(", r"googletagmanager[.]com"],
    "Facebook Pixel": [r"connect[.]facebook[.]net", r"fbq\\("],
    "Sentry": [r"sentry[.]io", r"sentry-release-id", r"sentry-trace"],
    "Datadog RUM": [r"datadoghq-browser-agent", r"datadog-rum"],
}'''

pattern = r'TECH_SIGNATURES\s*=\s*\{.*?\n\}'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + NEW_DICT + content[match.end():]
    print("[+] TECH_SIGNATURES expanded to 30+ technologies")

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
# SELF-TEST on multiple targets
# ============================================================
print("\n" + "=" * 60)
print("[*] COMPREHENSIVE TEST")
print("=" * 60)

import sys, importlib.util
os.chdir(os.path.dirname(FILE))
spec = importlib.util.spec_from_file_location("scanner", FILE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

TARGETS = [
    "github.com",
    "hackerone.com",
    "hackerone.com/login",       # Rails main app (no redirect)
    "wordpress.org",
    "vercel.com",
    "nextjs.org",
    "vuejs.org",
]

for target in TARGETS:
    print("\n" + "-" * 60)
    print("TARGET:", target)
    print("-" * 60)
    try:
        res = scanner.fetch_url("https://" + target)
        if "error" in res:
            print("[!] Fetch failed:", res["error"])
            continue
        
        print("[*] Final URL:", res.get("final_url"))
        print("[*] Size:", len(res.get("content", "")), "bytes")
        
        techs = scanner.detect_technologies(res.get("content", ""), res.get("headers", {}), debug=False)
        if techs:
            print("[*] Technologies:", techs)
        else:
            print("[*] Technologies: (none detected)")
    except Exception as e:
        print("[!] Error:", type(e).__name__, "-", e)