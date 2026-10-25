import os
import re

BASE_DIR = r"C:\users\nour\curated-arsenal"
HTML_FILE = os.path.join(BASE_DIR, "templates", "tool_detail.html")

with open(HTML_FILE, "r", encoding="utf-8") as f:
    html = f.read()

# Find the runTool function
old_run = '''        async function runTool() {
            const args = document.getElementById('args-input').value;
            const out = document.getElementById('terminal-output');
            document.getElementById('run-btn').disabled = true;
            out.innerText = "Executing...";
            try {
                const res = await fetch("/api/run_tool/{{ tool.id }}", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({args: args}) });
                const data = await res.json();
                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\\n[STDERR]\\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";
                
                // Auto-map CVEs from detected technologies
                const techs = extractTechnologies(currentOutput);
                if (techs.length > 0) {
                    mapCVEs(techs);
                }
                
                // Auto-analyze attack chains
                const scanResult = extractScanResult(currentOutput);
                if (scanResult) {
                    analyzeChains(scanResult);
                }
            } catch (e) { out.innerText = e.message; }
            document.getElementById('run-btn').disabled = false;
        }'''

# Alternative pattern (in case the above doesn't match exactly)
if old_run not in html:
    # Try more flexible regex
    pattern = r'async function runTool\(\) \{.*?(?=\n        function|\n        async function|\n    </script>)'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        old_run = match.group(0)
        print("[*] Using regex pattern to find runTool")
    else:
        print("[!] Could not find runTool function")
        exit(1)

new_run = '''async function runTool() {
            const args = document.getElementById('args-input').value;
            const out = document.getElementById('terminal-output');
            document.getElementById('run-btn').disabled = true;
            out.innerText = "Executing...";
            try {
                const res = await fetch("/api/run_tool/{{ tool.id }}", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({args: args}) });
                const data = await res.json();
                
                // Display: stdout + stderr (what user sees in terminal)
                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\\n[STDERR]\\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";
                
                // Parse: only stdout (pure JSON from tool)
                const pureJson = data.stdout || "";
                console.log("[runTool] pureJson length:", pureJson.length);
                console.log("[runTool] pureJson preview:", pureJson.substring(0, 200));
                
                // Extract technologies directly from stdout
                let techs = [];
                let scanResult = null;
                try {
                    scanResult = JSON.parse(pureJson);
                    techs = scanResult.technologies || [];
                    console.log("[runTool] Parsed technologies:", techs);
                } catch(e) {
                    console.warn("[runTool] Could not parse stdout as JSON:", e.message);
                    // Fallback: try extracting from currentOutput
                    scanResult = extractScanResult(currentOutput);
                    techs = (scanResult && scanResult.technologies) || [];
                }
                
                // Trigger CVE mapper
                if (techs && techs.length > 0) {
                    mapCVEs(techs);
                }
                
                // Trigger attack chains
                if (scanResult) {
                    console.log("[runTool] Triggering attack chain analysis");
                    analyzeChains(scanResult);
                }
            } catch (e) { 
                out.innerText = e.message; 
                console.error("[runTool] Error:", e);
            }
            document.getElementById('run-btn').disabled = false;
        }'''

# Replace
if old_run in html:
    html = html.replace(old_run, new_run)
    print("[+] runTool replaced successfully")
else:
    # Try regex replace
    pattern = r'async function runTool\(\) \{.*?\n        \}'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        html = html[:match.start()] + new_run + html[match.end():]
        print("[+] runTool replaced via regex")
    else:
        print("[!] Could not replace runTool")
        exit(1)

with open(HTML_FILE, "w", encoding="utf-8") as f:
    f.write(html)

print()
print("=" * 60)
print("[OK] runTool now uses data.stdout directly!")
print("=" * 60)
print()
print("NEXT STEPS:")
print("  1. Restart server (Ctrl+C, then python app.py)")
print("  2. Hard refresh: Ctrl+Shift+R")
print("  3. Open DevTools (F12) -> Console")
print("  4. Run scan on hackerone.com/login")
print("  5. You should see [runTool] logs in Console")
print("  6. Attack Chains panel should appear")