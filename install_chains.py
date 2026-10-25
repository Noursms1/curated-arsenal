import os

BASE_DIR = r"C:\users\nour\curated-arsenal"

# =========================================================
# 1. CREATE data/attack_chains.py
# =========================================================
attack_chains_code = '''# -*- coding: utf-8 -*-
"""Attack Chain Analyzer - Links findings into exploit chains."""

DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 1433: "MSSQL", 11211: "Memcached"}
DB_PORTS_HIGH = {9200: "Elasticsearch", 7001: "WebLogic"}


def analyze_attack_chains(scan_result):
    """Analyze a scan result and return exploit chain suggestions."""
    if not scan_result:
        return []
    
    chains = []
    techs = [t.lower() for t in scan_result.get("technologies", [])]
    headers = scan_result.get("security_headers", {}) or {}
    findings = scan_result.get("findings", []) or []
    ports = [p.get("port") for p in scan_result.get("open_ports", []) or []]
    status = scan_result.get("status") or scan_result.get("https_status")
    redirects = scan_result.get("redirects", []) or []
    
    # CHAIN 1: Rails + Missing CSP + Missing X-Frame-Options => XSS Session Hijack
    if "ruby on rails" in techs:
        issues = []
        if headers.get("Content-Security-Policy") == "MISSING":
            issues.append("Missing CSP")
        if headers.get("X-Frame-Options") == "MISSING":
            issues.append("Missing X-Frame-Options")
        
        if issues:
            chains.append({
                "name": "XSS Session Hijacking Risk",
                "severity": "High",
                "score": 8.0,
                "reasoning": "Rails app detected. " + " + ".join(issues) + " means XSS payloads won't be blocked by CSP, and session cookies can be stolen if HttpOnly is missing.",
                "test_suggestion": "Look for reflected XSS in search/error params. If successful, exfiltrate document.cookie to a webhook."
            })
    
    # CHAIN 2: Missing HSTS + HTTPS site => MITM Downgrade
    if headers.get("Strict-Transport-Security") == "MISSING":
        chains.append({
            "name": "MITM Downgrade Attack",
            "severity": "Medium",
            "score": 5.5,
            "reasoning": "Missing HSTS means first-time visitors can be downgraded to HTTP via MITM. Session cookies could leak.",
            "test_suggestion": "Check if http:// versions return content (not 301). Check if Set-Cookie has Secure flag."
        })
    
    # CHAIN 3: Open Database Ports => Data Breach
    exposed_dbs = [DB_PORTS[p] + " (port " + str(p) + ")" for p in ports if p in DB_PORTS]
    exposed_critical = [DB_PORTS_HIGH[p] + " (port " + str(p) + ")" for p in ports if p in DB_PORTS_HIGH]
    
    if exposed_dbs:
        chains.append({
            "name": "Database Exposure - Critical",
            "severity": "Critical",
            "score": 9.5,
            "reasoning": "Database ports directly exposed to internet: " + ", ".join(exposed_dbs) + ". Likely accessible from anywhere.",
            "test_suggestion": "Use nmap/redis-cli/mysql-client to connect without credentials. Default creds often work (root:root, admin:admin, no password)."
        })
    
    if exposed_critical:
        chains.append({
            "name": "Critical Service Exposure",
            "severity": "Critical",
            "score": 9.0,
            "reasoning": "Critical services exposed: " + ", ".join(exposed_critical) + ". Elasticsearch/WebLogic are known for unauth RCE.",
            "test_suggestion": "Check if Elasticsearch returns data at /_cat/indices (no auth). WebLogic CVE-2020-14882 RCE."
        })
    
    # CHAIN 4: WordPress + User Enumeration + Brute Force
    if "wordpress" in techs:
        chains.append({
            "name": "WordPress Attack Surface",
            "severity": "High",
            "score": 7.5,
            "reasoning": "WordPress detected. Common vectors: /wp-admin/ brute force, /xmlrpc.php amplification, /wp-json/wp/v2/users user enumeration.",
            "test_suggestion": "1) Enumerate users via /wp-json/wp/v2/users. 2) Check /xmlrpc.php for system.multicall. 3) Test /wp-admin/ for credentials in /wp-content/debug.log"
        })
    
    # CHAIN 5: Drupal CVE Risk
    if "drupal" in techs:
        chains.append({
            "name": "Drupal CVE Exploitation",
            "severity": "High",
            "score": 8.5,
            "reasoning": "Drupal detected. High-profile CVEs: Drupalgeddon2 (CVE-2018-7600), REST RCE (CVE-2019-6340), File Upload RCE (CVE-2020-13671).",
            "test_suggestion": "Check version: /CHANGELOG.txt. If 7.x or 8.x < 8.5.1, test Drupalgeddon2 with POST /user/register?element_parents=... or similar."
        })
    
    # CHAIN 6: 401/403 => Auth Bypass Opportunity
    if status in (401, 403):
        chains.append({
            "name": "Auth Bypass Opportunity",
            "severity": "Medium",
            "score": 6.5,
            "reasoning": "Endpoint returned " + str(status) + ". Bypass techniques may exist.",
            "test_suggestion": "Try: X-Original-URL: /admin, X-Rewrite-URL: /admin, /admin;, //admin, /admin/..;/, %2fadmin, /admin%00"
        })
    
    # CHAIN 7: Multiple Redirects => Open Redirect Risk
    if len(redirects) >= 2:
        chains.append({
            "name": "Open Redirect Risk",
            "severity": "Medium",
            "score": 5.0,
            "reasoning": "Multiple redirects detected. Check if user input controls the redirect destination.",
            "test_suggestion": "Look for ?url=, ?redirect=, ?next=, ?return=, ?continue= parameters. Try //evil.com or https://evil.com."
        })
    
    # CHAIN 8: Cloudflare + Rails => WAF Bypass worth testing
    if "cloudflare" in techs and "ruby on rails" in techs:
        chains.append({
            "name": "WAF Bypass Opportunity",
            "severity": "Low",
            "score": 3.5,
            "reasoning": "Cloudflare WAF is protecting a Rails app. Common bypasses exist for SQLi and XSS payloads.",
            "test_suggestion": "Try payload obfuscation: /*!50000SELECT*/, %00, unicode encoding, or JSON endpoints which sometimes bypass WAF."
        })
    
    # CHAIN 9: Sentry exposed => Error Leak
    if "sentry" in techs:
        chains.append({
            "name": "Sentry Error Leak",
            "severity": "Low",
            "score": 4.0,
            "reasoning": "Sentry SDK detected. If DSN is exposed in HTML, attacker could inject fake errors or extract stack traces.",
            "test_suggestion": "Search HTML for 'sentry.io/api/' or 'sentry_key'. If found, send malformed requests to trigger errors and see full stack traces."
        })
    
    # Sort by score descending
    chains.sort(key=lambda x: -x.get("score", 0))
    
    return chains
'''

os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
with open(os.path.join(BASE_DIR, "data", "attack_chains.py"), "w", encoding="utf-8") as f:
    f.write(attack_chains_code)
print("[+] data/attack_chains.py created")


# =========================================================
# 2. ADD ENDPOINT IN app.py
# =========================================================
APP_FILE = os.path.join(BASE_DIR, "app.py")
with open(APP_FILE, "r", encoding="utf-8") as f:
    app = f.read()

if "/api/analyze_chains" in app:
    print("[!] Attack chain endpoint already exists")
else:
    chains_endpoint = '''@app.route("/api/analyze_chains", methods=["POST"])
def api_analyze_chains():
    """Analyze scan result for attack chains."""
    body = request.get_json(silent=True) or {}
    scan_result = body.get("scan_result", {})
    if not scan_result:
        return jsonify({"error": "scan_result required"}), 400
    
    try:
        import sys
        if os.path.join(BASE_DIR, "data") not in sys.path:
            sys.path.insert(0, os.path.join(BASE_DIR, "data"))
        import attack_chains as _ac
        chains = _ac.analyze_attack_chains(scan_result)
        return jsonify({"chains": chains, "total": len(chains)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


'''
    marker = '@app.route("/download/'
    pos = app.find(marker)
    if pos != -1:
        app = app[:pos] + chains_endpoint + app[pos:]
        with open(APP_FILE, "w", encoding="utf-8") as f:
            f.write(app)
        print("[+] Attack chain endpoint added")
    else:
        print("[!] Could not find insertion point")

import py_compile
try:
    py_compile.compile(APP_FILE, doraise=True)
    print("[+] app.py: Syntax OK")
except py_compile.PyCompileError as e:
    print("[!] app.py Syntax error:", e)


# =========================================================
# 3. UPDATE tool_detail.html - Add Attack Chain panel
# =========================================================
TOOL_DETAIL = os.path.join(BASE_DIR, "templates", "tool_detail.html")
with open(TOOL_DETAIL, "r", encoding="utf-8") as f:
    html = f.read()

# Add panel after CVE panel
if 'id="chainsPanel"' not in html:
    chains_panel = '''
            <div class="chains-panel" id="chainsPanel" style="display: none;">
                <h3 style="color: #ffa657;">⚡ Attack Chains Detected</h3>
                <div id="chainsList"></div>
            </div>
'''
    # Insert after CVE panel
    marker = '<div class="cve-panel" id="cvePanel"'
    if marker in html:
        # Find closing of cve-panel div
        pos = html.find(marker)
        depth = 0
        i = pos
        while i < len(html):
            if html[i:i+4] == '<div':
                depth += 1
                i += 4
            elif html[i:i+6] == '</div>':
                depth -= 1
                i += 6
                if depth == 0:
                    html = html[:i] + '\n' + chains_panel + html[i:]
                    break
            else:
                i += 1
        print("[+] Chains panel added to HTML")

# Add JS function
if "async function analyzeChains" not in html:
    chains_js = '''
        async function analyzeChains(scanResult) {
            const panel = document.getElementById('chainsPanel');
            const list = document.getElementById('chainsList');
            if (!scanResult || typeof scanResult !== 'object') {
                panel.style.display = 'none';
                return;
            }
            
            try {
                const res = await fetch("/api/analyze_chains", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({scan_result: scanResult})
                });
                const data = await res.json();
                
                if (!data.chains || data.chains.length === 0) {
                    panel.style.display = 'none';
                    return;
                }
                
                panel.style.display = 'block';
                let html = '<p style="font-size:12px; color:#8b949e; margin: 0 0 10px 0;">' + data.total + ' attack chains identified:</p>';
                
                data.chains.forEach(c => {
                    const color = c.severity === 'Critical' ? '#e74c3c' : (c.severity === 'High' ? '#f39c12' : (c.severity === 'Medium' ? '#f1c40f' : '#3498db'));
                    html += '<div style="background:#000; padding:10px; border-radius:4px; margin-bottom:8px; border-left: 3px solid ' + color + ';">';
                    html += '<div style="color:' + color + '; font-weight:bold; font-size:13px;">⚡ ' + c.name + ' (' + c.severity + ')</div>';
                    html += '<div style="font-size:11px; color:#c9d1d9; margin-top:4px;"><strong>Why:</strong> ' + c.reasoning + '</div>';
                    html += '<div style="font-size:11px; color:#ffa657; margin-top:4px;"><strong>Test:</strong> ' + c.test_suggestion + '</div>';
                    html += '</div>';
                });
                list.innerHTML = html;
            } catch(e) {
                console.error("Chain analysis failed:", e);
            }
        }

        function extractScanResult(output) {
            try {
                const start = output.indexOf("{");
                if (start === -1) return null;
                return JSON.parse(output.substring(start));
            } catch(e) {
                return null;
            }
        }
'''
    # Insert before function generateReport
    marker = '        function generateReport()'
    if marker in html:
        html = html.replace(marker, chains_js + '\n' + marker, 1)
        print("[+] Chains JS added")

# Trigger chains after runTool
old_trigger = '''                const techs = extractTechnologies(currentOutput);
                if (techs.length > 0) {
                    mapCVEs(techs);
                }'''
new_trigger = '''                const techs = extractTechnologies(currentOutput);
                if (techs.length > 0) {
                    mapCVEs(techs);
                }
                
                // Auto-analyze attack chains
                const scanResult = extractScanResult(currentOutput);
                if (scanResult) {
                    analyzeChains(scanResult);
                }'''
if old_trigger in html:
    html = html.replace(old_trigger, new_trigger)
    print("[+] runTool updated to trigger chain analysis")

with open(TOOL_DETAIL, "w", encoding="utf-8") as f:
    f.write(html)


# =========================================================
# 4. ADD CSS
# =========================================================
CSS_FILE = os.path.join(BASE_DIR, "static", "css", "style.css")
with open(CSS_FILE, "r", encoding="utf-8") as f:
    css = f.read()

if ".chains-panel" not in css:
    chains_css = '''
/* Attack Chains Panel */
.chains-panel {
    background: var(--card-bg);
    border: 1px solid #ffa657;
    border-radius: 8px;
    padding: 15px;
    margin-top: 15px;
}
.chains-panel h3 {
    margin: 0 0 10px 0;
    font-size: 14px;
}
'''
    with open(CSS_FILE, "a", encoding="utf-8") as f:
        f.write(chains_css)
    print("[+] Chains panel CSS added")

print()
print("=" * 60)
print("[✅] Attack Chain Analyzer installed!")
print("=" * 60)
print()
print("Restart Flask server, then:")
print("  1. Scan hackerone.com/login (Rails)")
print("  2. You'll see TWO new panels:")
print("     - CVE list")
print("     - Attack Chains with exploit reasoning")
print()