import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================================================
# 1. UPDATE app.py (Add Smart Scanner API)
# =========================================================
app_file = os.path.join(BASE_DIR, "app.py")
with open(app_file, "r", encoding="utf-8") as f:
    app_content = f.read()

# Check if already exists
if "/api/smart_scan" in app_content:
    print("[!] Smart scan endpoint already exists, skipping.")
else:
    # Find where to insert (before @app.route("/api/chat/") or at end of routes)
    insert_marker = '@app.route("/api/chat/'
    pos = app_content.find(insert_marker)
    
    if pos == -1:
        # Fallback: insert before @app.route("/download/")
        insert_marker = '@app.route("/download/'
        pos = app_content.find(insert_marker)
    
    if pos == -1:
        print("[!] Could not find insertion point")
        exit(1)

    smart_scan_code = '''@app.route("/api/smart_scan", methods=["POST"])
def api_smart_scan():
    """Smart Target Scanner: Auto-detects target type, selects tools, runs them all."""
    import re
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400

    # 1. Detect Target Type
    target_type = "unknown"
    if re.match(r"^https?://", target):
        target_type = "url"
        target = re.sub(r"^https?://", "", target).split("/")[0]
    elif re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", target):
        target_type = "ip"
    elif "." in target:
        target_type = "domain"

    # 2. Load all tools
    tools = load_tools()
    
    # 3. Select compatible tools
    selected_tools = []
    for t in tools:
        cat = t.get("category", "").lower()
        name = t.get("name", "").lower()
        
        if target_type == "domain":
            if cat in ["recon", "network", "web"]:
                selected_tools.append(t)
        elif target_type == "ip":
            if cat in ["network"] or "port" in name:
                selected_tools.append(t)
        elif target_type == "url":
            if cat in ["web"]:
                selected_tools.append(t)

    # Limit to 5 tools to avoid extreme delays
    selected_tools = selected_tools[:5]

    if not selected_tools:
        return jsonify({"error": "No compatible tools found for this target type: " + target_type}), 404

    # 4. Run each tool sequentially, collect results
    results = []
    for tool in selected_tools:
        tool_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
        if not os.path.exists(tool_path):
            results.append({
                "tool": tool["name"],
                "status": "skipped",
                "output": "File not found on disk."
            })
            continue
        
        try:
            proc = subprocess.run(
                [sys.executable, tool_path, target],
                capture_output=True, text=True, timeout=90,
                cwd=os.path.dirname(tool_path),
                encoding="utf-8", errors="replace"
            )
            results.append({
                "tool": tool["name"],
                "status": "success" if proc.returncode == 0 else "error",
                "output": proc.stdout if proc.stdout else "",
                "stderr": proc.stderr[:500] if proc.stderr else ""
            })
        except subprocess.TimeoutExpired:
            results.append({
                "tool": tool["name"],
                "status": "timeout",
                "output": "Tool timed out after 90 seconds."
            })
        except Exception as e:
            results.append({
                "tool": tool["name"],
                "status": "error",
                "output": str(e)
            })

    return jsonify({
        "target": target,
        "detected_type": target_type,
        "tools_run": len(results),
        "results": results
    })


'''

    app_content = app_content[:pos] + smart_scan_code + app_content[pos:]
    
    with open(app_file, "w", encoding="utf-8") as f:
        f.write(app_content)
    
    import py_compile
    try:
        py_compile.compile(app_file, doraise=True)
        print("[+] app.py updated with Smart Scanner!")
    except py_compile.PyCompileError as e:
        print("[!] Syntax error: " + str(e))


# =========================================================
# 2. UPDATE index.html (Add Smart Scan UI)
# =========================================================
index_file = os.path.join(BASE_DIR, "templates", "index.html")
with open(index_file, "r", encoding="utf-8") as f:
    idx = f.read()

# Add smart scanner section after the workflow box
smart_ui = '''
        <!-- Smart Target Scanner -->
        <div class="workflow-box" style="border-color: #ff7b72; margin-top: 15px;">
            <h3 style="color: #ff7b72;">🎯 Smart Target Scanner</h3>
            <p style="font-size:12px; color:#8b949e;">Enter a target, we auto-detect its type, pick the right tools, and run them all in one terminal.</p>
            <div class="workflow-input">
                <input type="text" id="smartTarget" placeholder="Domain, IP, or URL (e.g., hackerone.com)">
                <button onclick="runSmartScan()" id="smartBtn" style="background: #ff7b72; color: white;">Auto Scan</button>
            </div>
            <pre id="smartOutput" class="wf-output" style="display:none; color: #ffcc00; max-height: 400px;"></pre>
        </div>
'''

# Insert after workflow box
marker = '</div>\n\n        <!-- Search & Filters -->'
if marker in idx:
    idx = idx.replace(marker, '</div>\n' + smart_ui + '\n        <!-- Search & Filters -->', 1)
else:
    # Fallback: insert before search-container
    idx = idx.replace('<div class="search-container">', smart_ui + '<div class="search-container">', 1)

# Add JS function
js_func = '''
        async function runSmartScan() {
            const target = document.getElementById('smartTarget').value;
            const btn = document.getElementById('smartBtn');
            const out = document.getElementById('smartOutput');
            if(!target) return alert("Enter a target!");

            btn.disabled = true; btn.innerText = "Scanning...";
            out.style.display = 'block';
            out.innerText = "🔍 Detecting target type and selecting tools...\\n\\n";

            try {
                const res = await fetch("/api/smart_scan", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({target: target})
                });
                const data = await res.json();
                
                if (data.error) {
                    out.innerText = "❌ " + data.error;
                } else {
                    let text = "🎯 Target: " + data.target + "\\n";
                    text += "📋 Detected Type: " + data.detected_type.toUpperCase() + "\\n";
                    text += "🔧 Tools Run: " + data.tools_run + "\\n";
                    text += "=".repeat(60) + "\\n\\n";
                    
                    data.results.forEach((r, i) => {
                        text += "[" + (i+1) + "/" + data.tools_run + "] " + r.tool + " (" + r.status + ")\\n";
                        text += "-".repeat(60) + "\\n";
                        text += (r.output || "(No output)") + "\\n";
                        if (r.stderr && r.stderr.trim()) {
                            text += "[STDERR]: " + r.stderr + "\\n";
                        }
                        text += "\\n" + "=".repeat(60) + "\\n\\n";
                    });
                    
                    out.innerText = text;
                }
            } catch (e) {
                out.innerText = "❌ Error: " + e.message;
            }
            btn.disabled = false; btn.innerText = "Auto Scan";
        }
'''

# Insert before </script> in the main script tag
idx = idx.replace('    </script>\n</body>', js_func + '\n    </script>\n</body>')

with open(index_file, "w", encoding="utf-8") as f:
    f.write(idx)

print("[+] index.html updated with Smart Scanner UI!")

print("\\n✅ Smart Scanner installed! Restart the server.")