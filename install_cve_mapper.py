import os
import json
import re

BASE_DIR = r"C:\users\nour\curated-arsenal"
APP_FILE = os.path.join(BASE_DIR, "app.py")
CVE_DB_FILE = os.path.join(BASE_DIR, "data", "cve_mapping.json")
TOOL_DETAIL = os.path.join(BASE_DIR, "templates", "tool_detail.html")
CSS_FILE = os.path.join(BASE_DIR, "static", "css", "style.css")

# =========================================================
# 1. CREATE CVE DATABASE
# =========================================================
CVE_DB = {
    "WordPress": [
        {"cve": "CVE-2023-2982", "severity": "Critical", "cvss": 9.8, "affected": "<= 6.2.2", "desc": "Authentication Bypass via Social Login"},
        {"cve": "CVE-2022-21661", "severity": "High", "cvss": 8.8, "affected": "<= 5.8.2", "desc": "SQL Injection via WP_Query"}
    ],
    "Drupal": [
        {"cve": "CVE-2018-7600", "severity": "Critical", "cvss": 9.8, "affected": "7.x, 8.x < 8.5.1", "desc": "Drupalgeddon2 - RCE"},
        {"cve": "CVE-2019-6340", "severity": "Critical", "cvss": 9.8, "affected": "8.6.x < 8.6.10", "desc": "REST RCE"},
        {"cve": "CVE-2020-13671", "severity": "High", "cvss": 8.8, "affected": "7.x, 8.x, 9.x", "desc": "File Upload RCE"}
    ],
    "Ruby on Rails": [
        {"cve": "CVE-2024-26143", "severity": "High", "cvss": 7.5, "affected": "7.x, 6.x", "desc": "XSS in ActionController"},
        {"cve": "CVE-2024-47887", "severity": "Medium", "cvss": 6.5, "affected": "7.x, 6.x", "desc": "ActionPack DoS"},
        {"cve": "CVE-2019-5418", "severity": "High", "cvss": 7.5, "affected": "Rails 5.2.x < 5.2.2.1", "desc": "File Content Disclosure"}
    ],
    "Next.js": [
        {"cve": "CVE-2024-34351", "severity": "High", "cvss": 7.5, "affected": ">= 13.4.0, < 14.1.1", "desc": "SSRF via Server Actions"},
        {"cve": "CVE-2023-46298", "severity": "Medium", "cvss": 5.3, "affected": "< 13.5.1", "desc": "Cache Poisoning"}
    ],
    "Laravel": [
        {"cve": "CVE-2024-40075", "severity": "High", "cvss": 8.8, "affected": "Laravel < 10.48.20", "desc": "PHP Object Injection"}
    ],
    "jQuery": [
        {"cve": "CVE-2020-11023", "severity": "Medium", "cvss": 6.1, "affected": "< 3.5.0", "desc": "XSS via htmlPrefilter"},
        {"cve": "CVE-2019-11358", "severity": "Medium", "cvss": 6.1, "affected": "< 3.4.0", "desc": "Prototype Pollution"}
    ],
    "Apache": [
        {"cve": "CVE-2021-41773", "severity": "Critical", "cvss": 9.8, "affected": "2.4.49", "desc": "Path Traversal + RCE"},
        {"cve": "CVE-2021-42013", "severity": "Critical", "cvss": 9.8, "affected": "2.4.50", "desc": "Path Traversal bypass"}
    ],
    "Nginx": [
        {"cve": "CVE-2021-23017", "severity": "High", "cvss": 7.7, "affected": "1.19.0", "desc": "DNS Resolver off-by-one"}
    ],
    "PHP": [
        {"cve": "CVE-2024-4577", "severity": "Critical", "cvss": 9.8, "affected": "8.1, 8.2, 8.3 (Windows)", "desc": "CGI Argument Injection RCE"}
    ],
    "Django": [
        {"cve": "CVE-2024-38875", "severity": "Medium", "cvss": 5.3, "affected": "< 4.2.14", "desc": "DoS via strip_tags"},
        {"cve": "CVE-2023-31047", "severity": "High", "cvss": 7.5, "affected": "< 4.2.2", "desc": "File Upload Bypass"}
    ],
    "React": [
        {"cve": "CVE-2024-21668", "severity": "Medium", "cvss": 5.3, "affected": "react-dom < 18.2.0", "desc": "Prototype Pollution"}
    ]
}

os.makedirs(os.path.dirname(CVE_DB_FILE), exist_ok=True)
with open(CVE_DB_FILE, "w", encoding="utf-8") as f:
    json.dump(CVE_DB, f, indent=2, ensure_ascii=False)
print("[+] CVE database created: cve_mapping.json")


# =========================================================
# 2. ADD CVE ENDPOINT TO app.py
# =========================================================
with open(APP_FILE, "r", encoding="utf-8") as f:
    app = f.read()

# Check if CVE endpoint already exists
if "/api/cve/map" in app:
    print("[!] CVE endpoint already exists")
else:
    # Add CVE endpoint before the last @app.route
    cve_code = '''@app.route("/api/cve/map", methods=["POST"])
def api_cve_map():
    """Map detected technologies to known CVEs."""
    body = request.get_json(silent=True) or {}
    technologies = body.get("technologies", [])
    if not technologies:
        return jsonify({"error": "No technologies provided"}), 400
    
    cve_db_path = os.path.join(BASE_DIR, "data", "cve_mapping.json")
    try:
        with open(cve_db_path, "r", encoding="utf-8") as f:
            cve_db = json.load(f)
    except Exception:
        return jsonify({"error": "CVE database not found"}), 500
    
    findings = []
    for tech in technologies:
        if tech in cve_db:
            for cve in cve_db[tech]:
                findings.append({
                    "technology": tech,
                    "cve": cve["cve"],
                    "severity": cve["severity"],
                    "cvss": cve["cvss"],
                    "affected_versions": cve["affected"],
                    "description": cve["desc"]
                })
    
    # Sort by CVSS
    findings.sort(key=lambda x: -x["cvss"])
    
    return jsonify({
        "technologies": technologies,
        "total_cves": len(findings),
        "findings": findings,
        "note": "These CVEs apply only if the detected version is within the affected range."
    })


'''
    # Insert before @app.route("/download/
    marker = '@app.route("/download/'
    pos = app.find(marker)
    if pos != -1:
        app = app[:pos] + cve_code + app[pos:]
        with open(APP_FILE, "w", encoding="utf-8") as f:
            f.write(app)
        
        import py_compile
        try:
            py_compile.compile(APP_FILE, doraise=True)
            print("[+] CVE endpoint added to app.py")
        except py_compile.PyCompileError as e:
            print("[!] Syntax error in app.py:", e)
    else:
        print("[!] Could not find insertion point in app.py")


# =========================================================
# 3. UPDATE tool_detail.html - Add CVE section + Enhanced PDF
# =========================================================
with open(TOOL_DETAIL, "r", encoding="utf-8") as f:
    html = f.read()

# Add CVE panel in the sidebar
if 'id="cvePanel"' not in html:
    cve_panel = '''
            <div class="cve-panel" id="cvePanel" style="display: none;">
                <h3 style="color: #ff7b72;">🔴 Potential CVEs</h3>
                <div id="cveList"></div>
            </div>
'''
    # Insert after chart-box
    marker = '<div class="chart-box">'
    if marker in html:
        # Find closing of chart-box div
        pos = html.find(marker)
        # Find the next </div> after marker
        close_pos = html.find('</div>', pos) + len('</div>')
        html = html[:close_pos] + '\n' + cve_panel + html[close_pos:]
        print("[+] CVE panel added to HTML")

# Add JS for CVE mapping after runTool function
if "async function mapCVEs" not in html:
    cve_js = '''
        async function mapCVEs(technologies) {
            const panel = document.getElementById('cvePanel');
            const list = document.getElementById('cveList');
            if (!technologies || technologies.length === 0) {
                panel.style.display = 'none';
                return;
            }
            
            try {
                const res = await fetch("/api/cve/map", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({technologies: technologies})
                });
                const data = await res.json();
                
                if (data.total_cves === 0) {
                    panel.style.display = 'none';
                    return;
                }
                
                panel.style.display = 'block';
                let html = '<p style="font-size:12px; color:#8b949e; margin: 0 0 10px 0;">' + data.total_cves + ' potential CVEs found:</p>';
                
                data.findings.forEach(f => {
                    const color = f.severity === 'Critical' ? '#e74c3c' : (f.severity === 'High' ? '#f39c12' : '#f1c40f');
                    html += '<div style="background:#000; padding:8px; border-radius:4px; margin-bottom:6px; border-left: 3px solid ' + color + ';">';
                    html += '<div style="color:' + color + '; font-weight:bold; font-size:12px;">' + f.cve + ' (' + f.severity + ' ' + f.cvss + ')</div>';
                    html += '<div style="font-size:11px; color:#c9d1d9;">' + f.description + '</div>';
                    html += '<div style="font-size:10px; color:#8b949e;">Affected: ' + f.affected_versions + '</div>';
                    html += '</div>';
                });
                list.innerHTML = html;
            } catch(e) {
                console.error("CVE mapping failed:", e);
            }
        }

        function extractTechnologies(output) {
            try {
                const start = output.indexOf("{");
                if (start === -1) return [];
                const data = JSON.parse(output.substring(start));
                return data.technologies || [];
            } catch(e) {
                return [];
            }
        }
'''
    # Insert before the closing </script> that has generateReport
    marker = '        function generateReport()'
    if marker in html:
        html = html.replace(marker, cve_js + '\n' + marker, 1)
        print("[+] CVE mapping JS added")

# Update runTool to trigger CVE mapping
old_run = '''                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\\n[STDERR]\\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";'''
new_run = '''                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\\n[STDERR]\\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";
                
                // Auto-map CVEs from detected technologies
                const techs = extractTechnologies(currentOutput);
                if (techs.length > 0) {
                    mapCVEs(techs);
                }'''
if old_run in html:
    html = html.replace(old_run, new_run)
    print("[+] runTool updated for CVE mapping")

# Enhance PDF report to include technologies and CVEs
old_pdf_func = "function generateReport() {"
if old_pdf_func in html and "extractTechnologies(currentOutput)" not in html.split("function generateReport")[1][:500]:
    new_pdf_func = '''function generateReport() {
            const target = document.getElementById('args-input').value || '[TARGET]';
            const techs = extractTechnologies(currentOutput);
            const techList = techs.length > 0 ? techs.join(', ') : 'None detected';
            
            // Extract CVEs from the visible panel
            const cveElements = document.querySelectorAll('#cveList > div');
            let cveText = '';
            cveElements.forEach(el => {
                const cveLine = el.querySelector('div').innerText;
                const descLine = el.querySelectorAll('div')[1];
                if (descLine) {
                    cveText += '- ' + cveLine + ' - ' + descLine.innerText + '\\n';
                }
            });
            if (!cveText) cveText = '- No known CVEs mapped.\\n';
            
            const template = `# Security Assessment Report

## Target
\\`${target}\\`

## Tool Used
{{ tool.name }} (Category: {{ tool.category }})

## Detected Technologies
${techList}

## Potential CVEs
${cveText}

## Raw Output
\\`\\`\\`json
${currentOutput}
\\`\\`\\`

## Recommendations
1. Verify detected versions against official security advisories.
2. Check if CVEs apply to the specific version deployed.
3. Test for exploitation only on authorized targets.

---
*Generated by Curated Arsenal*`;

            document.getElementById('reportText').value = template;
            document.getElementById('reportModal').style.display = 'block';
        }'''
    
    # Replace the old function
    import re as _re
    pattern = r'function generateReport\(\) \{.*?\n        \}'
    match = _re.search(pattern, html, _re.DOTALL)
    if match:
        html = html[:match.start()] + new_pdf_func + html[match.end():]
        print("[+] PDF report enhanced with technologies and CVEs")

with open(TOOL_DETAIL, "w", encoding="utf-8") as f:
    f.write(html)


# =========================================================
# 4. ADD CSS for CVE panel
# =========================================================
with open(CSS_FILE, "r", encoding="utf-8") as f:
    css = f.read()

if ".cve-panel" not in css:
    cve_css = '''
/* CVE Panel */
.cve-panel {
    background: var(--card-bg);
    border: 1px solid #e74c3c;
    border-radius: 8px;
    padding: 15px;
    margin-top: 15px;
}
.cve-panel h3 {
    margin: 0 0 10px 0;
    font-size: 14px;
}
'''
    with open(CSS_FILE, "a", encoding="utf-8") as f:
        f.write(cve_css)
    print("[+] CVE panel CSS added")

print("\n" + "=" * 60)
print("[✅] CVE Mapper + Enhanced PDF Report installed!")
print("=" * 60)
print("\nRestart Flask server and try:")
print("  1. Run a scan on hackerone.com/login (Rails)")
print("  2. CVE panel should show Rails CVEs")
print("  3. Click 'Generate Report' - PDF will include technologies + CVEs")