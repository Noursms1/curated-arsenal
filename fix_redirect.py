import os
import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# ============================================================
# PATCH 1: Add redirect detection to fetch_url (or main fetch)
# ============================================================
# Find the fetch_url function and add redirect tracking
old_fetch = re.search(r'def fetch_url\([^)]*\):.*?(?=\ndef [a-z_])', content, re.DOTALL)
if not old_fetch:
    print("[!] Could not find fetch_url function")
    exit(1)

new_fetch = '''def fetch_url(url, timeout=5, follow_redirects=True):
    """Fetch URL with redirect tracking."""
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    
    # Custom handler to track redirects
    class RedirectTracker(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self.redirects = []
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.redirects.append({"status": code, "to": newurl})
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    
    tracker = RedirectTracker()
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_303 = http_error_307 = http_error_302
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect()
        )
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            tracker
        )
    
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {
                "status": resp.getcode(),
                "headers": dict(resp.headers),
                "content": resp.read(500000).decode("utf-8", errors="replace"),
                "final_url": resp.geturl(),
                "redirects": tracker.redirects,
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "content": "",
            "final_url": url,
            "redirects": tracker.redirects,
        }
    except Exception as e:
        return {"error": str(e), "redirects": tracker.redirects}


'''
content = content[:old_fetch.start()] + new_fetch + content[old_fetch.end():]
print("[+] fetch_url replaced with redirect tracking")

# ============================================================
# PATCH 2: Update scan_domain to include redirect info
# ============================================================
old_scan = re.search(r'def scan_domain\([^)]*\):.*?(?=\nif __name__|\ndef [a-z_])', content, re.DOTALL)
if old_scan:
    # Just add a warning if there's a redirect
    scan_code = old_scan.group(0)
    
    # Add redirect info extraction - simpler approach: just add to results dict
    # Find where results are appended, add redirect check
    if '"redirects"' not in scan_code:
        # Add redirects to the result dict
        scan_code = scan_code.replace(
            'result["https_status"] = https_result.get("status")',
            'result["https_status"] = https_result.get("status")\n        result["final_url"] = https_result.get("final_url", "")\n        result["redirects"] = https_result.get("redirects", [])\n        if result["final_url"] and result["final_url"] != f"https://{domain}":\n            result.setdefault("findings", []).append(f"⚠️ Redirected to: {result[\'final_url\']}")'
        )
        content = content[:old_scan.start()] + scan_code + content[old_scan.end():]
        print("[+] scan_domain updated with redirect tracking")

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
# SELF-TEST on both URLs
# ============================================================
print("\n" + "=" * 60)
print("[*] TESTING both hackerone.com and api.hackerone.com")
print("=" * 60)

import sys, importlib.util
os.chdir(os.path.dirname(FILE))
spec = importlib.util.spec_from_file_location("scanner", FILE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

for target in ["hackerone.com", "api.hackerone.com"]:
    print("\n" + "-" * 60)
    print("TARGET:", target)
    print("-" * 60)
    try:
        res = scanner.fetch_url("https://" + target)
        if "error" in res:
            print("[!] Fetch failed:", res["error"])
            continue
        
        print("[*] Final URL:", res.get("final_url"))
        print("[*] Redirects:", res.get("redirects", []))
        print("[*] Status:", res.get("status"))
        
        techs = scanner.detect_technologies(res.get("content", ""), res.get("headers", {}), debug=False)
        print("[*] Technologies:", techs)
    except Exception as e:
        print("[!] Error:", e)