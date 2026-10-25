import os
import re

BASE_DIR = r"C:\users\nour\curated-arsenal"
HTML_FILE = os.path.join(BASE_DIR, "templates", "tool_detail.html")

with open(HTML_FILE, "r", encoding="utf-8") as f:
    html = f.read()

# ============================================================
# 1. Add debug panel right after the terminal output
# ============================================================
if 'id="debugPanel"' not in html:
    debug_panel = '''
            <!-- DEBUG PANEL - Remove after fix -->
            <div id="debugPanel" style="background:#1a1a2e; border:2px solid #ffa657; border-radius:8px; padding:12px; margin-bottom:15px; font-family: monospace; font-size: 12px; color: #ffa657; display:none;">
                <div style="color:#ffa657; font-weight:bold; margin-bottom:8px;">🐛 DEBUG INFO (temporary)</div>
                <div id="debugSteps"></div>
            </div>
'''
    # Insert right after terminal output
    marker = '<pre id="terminal-output" class="terminal-output">Ready...</pre>'
    if marker in html:
        html = html.replace(marker, marker + '\n' + debug_panel)
        print("[+] Debug panel added to HTML")
    else:
        print("[!] Could not find terminal-output marker")

# ============================================================
# 2. Add debug logging function
# ============================================================
if "function debugLog" not in html:
    debug_func = '''
        function debugLog(msg, type) {
            const dp = document.getElementById('debugPanel');
            const ds = document.getElementById('debugSteps');
            if (!dp || !ds) return;
            dp.style.display = 'block';
            const color = type === 'error' ? '#ff6b6b' : (type === 'success' ? '#51cf66' : '#ffa657');
            ds.innerHTML += '<div style="color:' + color + '; margin: 3px 0;">[' + new Date().toLocaleTimeString() + '] ' + msg + '</div>';
        }

        function clearDebug() {
            const ds = document.getElementById('debugSteps');
            if (ds) ds.innerHTML = '';
        }
'''
    # Insert before function runTool
    marker = '        async function runTool()'
    if marker in html:
        html = html.replace(marker, debug_func + '\n' + marker, 1)
        print("[+] Debug functions added")

# ============================================================
# 3. Replace runTool with detailed debug version
# ============================================================
pattern = r'async function runTool\(\) \{.*?\n        \}'
match = re.search(pattern, html, re.DOTALL)

if match:
    new_run = '''async function runTool() {
            clearDebug();
            debugLog("=== Starting scan ===", "info");
            
            const args = document.getElementById('args-input').value;
            const out = document.getElementById('terminal-output');
            document.getElementById('run-btn').disabled = true;
            out.innerText = "Executing...";
            
            try {
                debugLog("Calling API: /api/run_tool/{{ tool.id }} with args: " + args, "info");
                const res = await fetch("/api/run_tool/{{ tool.id }}", { 
                    method: "POST", 
                    headers: {"Content-Type": "application/json"}, 
                    body: JSON.stringify({args: args}) 
                });
                
                debugLog("HTTP Status: " + res.status, "info");
                const data = await res.json();
                debugLog("Response keys: " + Object.keys(data).join(', '), "info");
                debugLog("stdout length: " + (data.stdout ? data.stdout.length : 0), "info");
                debugLog("stderr length: " + (data.stderr ? data.stderr.length : 0), "info");
                
                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\\n[STDERR]\\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";
                
                const pureJson = data.stdout || "";
                if (!pureJson) {
                    debugLog("ERROR: stdout is empty!", "error");
                    return;
                }
                
                // Parse JSON
                let scanResult = null;
                let techs = [];
                try {
                    scanResult = JSON.parse(pureJson);
                    techs = scanResult.technologies || [];
                    debugLog("JSON parsed OK. Technologies: " + JSON.stringify(techs), "success");
                } catch(e) {
                    debugLog("ERROR parsing JSON: " + e.message, "error");
                    debugLog("Raw stdout (first 200): " + pureJson.substring(0, 200), "error");
                }
                
                // Trigger CVE
                if (techs && techs.length > 0) {
                    debugLog("Calling mapCVEs with " + techs.length + " technologies", "info");
                    try {
                        await mapCVEs(techs);
                        debugLog("mapCVEs completed", "success");
                    } catch(e) {
                        debugLog("mapCVEs error: " + e.message, "error");
                    }
                } else {
                    debugLog("No technologies found, skipping CVE mapping", "info");
                }
                
                // Trigger Chains
                if (scanResult) {
                    debugLog("Calling analyzeChains", "info");
                    try {
                        await analyzeChains(scanResult);
                        debugLog("analyzeChains completed", "success");
                    } catch(e) {
                        debugLog("analyzeChains error: " + e.message, "error");
                    }
                }
                
                debugLog("=== Scan complete ===", "success");
                
            } catch (e) { 
                out.innerText = e.message;
                debugLog("FATAL ERROR: " + e.message, "error");
            }
            document.getElementById('run-btn').disabled = false;
        }'''
    
    html = html[:match.start()] + new_run + html[match.end():]
    print("[+] runTool replaced with debug version")
else:
    print("[!] Could not find runTool")

# ============================================================
# 4. Add debug logging to mapCVEs and analyzeChains
# ============================================================
# Patch mapCVEs
mapcve_pattern = r'async function mapCVEs\(technologies\) \{.*?\n        \}'
mapcve_match = re.search(mapcve_pattern, html, re.DOTALL)
if mapcve_match:
    old_mapcve = mapcve_match.group(0)
    # Add debug at start
    new_mapcve = old_mapcve.replace(
        'const panel = document.getElementById(\'cvePanel\');',
        'debugLog("mapCVEs: Starting with " + technologies.length + " techs", "info");\n            const panel = document.getElementById(\'cvePanel\');',
        1
    ).replace(
        'if (data.total_cves === 0) {',
        'debugLog("mapCVEs: API returned " + (data.total_cves || 0) + " CVEs", "info");\n                if (data.total_cves === 0) {',
        1
    ).replace(
        'panel.style.display = \'block\';',
        'panel.style.display = \'block\';\n                debugLog("mapCVEs: CVE panel SHOWN", "success");',
        1
    )
    if new_mapcve != old_mapcve:
        html = html.replace(old_mapcve, new_mapcve)
        print("[+] mapCVEs updated with debug")

# Patch analyzeChains
chain_pattern = r'async function analyzeChains\(scanResult\) \{.*?\n        \}'
chain_match = re.search(chain_pattern, html, re.DOTALL)
if chain_match:
    old_chain = chain_match.group(0)
    new_chain = old_chain.replace(
        'const panel = document.getElementById(\'chainsPanel\');',
        'debugLog("analyzeChains: Starting", "info");\n            const panel = document.getElementById(\'chainsPanel\');',
        1
    ).replace(
        'if (!data.chains || data.chains.length === 0) {',
        'debugLog("analyzeChains: API returned " + (data.chains ? data.chains.length : 0) + " chains", "info");\n                if (!data.chains || data.chains.length === 0) {',
        1
    ).replace(
        'panel.style.display = \'block\';',
        'panel.style.display = \'block\';\n                debugLog("analyzeChains: CHAINS panel SHOWN", "success");',
        1
    )
    if new_chain != old_chain:
        html = html.replace(old_chain, new_chain)
        print("[+] analyzeChains updated with debug")

with open(HTML_FILE, "w", encoding="utf-8") as f:
    f.write(html)

print()
print("=" * 60)
print("[OK] Debug panel + logging installed!")
print("=" * 60)
print()
print("NEXT:")
print("  1. Restart server")
print("  2. Ctrl+Shift+R in browser")
print("  3. Run a scan")
print("  4. Look for YELLOW DEBUG box below the terminal")
print("  5. Screenshot it and share")