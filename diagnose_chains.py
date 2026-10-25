import os
import json

BASE_DIR = r"C:\users\nour\curated-arsenal"

print("=" * 60)
print("DIAGNOSTIC - Attack Chains")
print("=" * 60)

# 1. Check files exist
print("\n[1] Files:")
files_to_check = [
    "data/attack_chains.py",
    "templates/tool_detail.html",
    "static/css/style.css",
    "app.py"
]
for f in files_to_check:
    path = os.path.join(BASE_DIR, f)
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    print(f"  [{'OK' if exists else 'MISSING'}] {f} ({size} bytes)")

# 2. Check attack_chains.py content
print("\n[2] attack_chains.py content check:")
ac_path = os.path.join(BASE_DIR, "data", "attack_chains.py")
if os.path.exists(ac_path):
    with open(ac_path, "r", encoding="utf-8") as f:
        ac = f.read()
    checks = {
        "def analyze_attack_chains": "def analyze_attack_chains" in ac,
        "Rails chain": "XSS Session Hijacking" in ac,
        "Drupal chain": "Drupal CVE Exploitation" in ac,
        "MITM chain": "MITM Downgrade" in ac
    }
    for k, v in checks.items():
        print(f"  [{'OK' if v else 'MISSING'}] {k}")

# 3. Check app.py has endpoint
print("\n[3] app.py endpoint check:")
app_path = os.path.join(BASE_DIR, "app.py")
if os.path.exists(app_path):
    with open(app_path, "r", encoding="utf-8") as f:
        app = f.read()
    checks = {
        "/api/analyze_chains": "/api/analyze_chains" in app,
        "import attack_chains": "attack_chains" in app
    }
    for k, v in checks.items():
        print(f"  [{'OK' if v else 'MISSING'}] {k}")

# 4. Check HTML has panel and JS
print("\n[4] tool_detail.html check:")
html_path = os.path.join(BASE_DIR, "templates", "tool_detail.html")
if os.path.exists(html_path):
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    checks = {
        "chainsPanel div": 'id="chainsPanel"' in html,
        "chainsList div": 'id="chainsList"' in html,
        "analyzeChains function": "async function analyzeChains" in html,
        "extractScanResult function": "function extractScanResult" in html,
        "runTool triggers chains": "analyzeChains(scanResult)" in html
    }
    for k, v in checks.items():
        print(f"  [{'OK' if v else 'MISSING'}] {k}")

# 5. TEST: Simulate a scan result and run chain analyzer
print("\n[5] Runtime test - simulate Rails scan:")
try:
    import sys
    if os.path.join(BASE_DIR, "data") not in sys.path:
        sys.path.insert(0, os.path.join(BASE_DIR, "data"))
    import attack_chains
    import importlib
    importlib.reload(attack_chains)
    
    sample_scan = {
        "target": "https://hackerone.com/login",
        "domain": "hackerone.com",
        "status": 200,
        "technologies": ["Cloudflare", "Ruby on Rails", "Sentry"],
        "security_headers": {
            "Strict-Transport-Security": "MISSING",
            "Content-Security-Policy": "MISSING",
            "X-Frame-Options": "MISSING",
            "X-Content-Type-Options": "MISSING"
        },
        "open_ports": [],
        "findings": [],
        "redirects": []
    }
    
    chains = attack_chains.analyze_attack_chains(sample_scan)
    print(f"  [{'OK' if chains else 'EMPTY'}] Found {len(chains)} chains")
    for c in chains:
        print(f"      - {c['name']} ({c['severity']})")
except Exception as e:
    print(f"  [ERROR] {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)