import os
import json
import glob
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================================================
# 1. UPDATE TOOLS.JSON (Auto-categorize & Add Confidence)
# =========================================================
json_path = os.path.join(BASE_DIR, "data", "tools.json")
try:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    for t in data.get("tools", []):
        name = t["name"].lower()
        
        # Auto-categorize
        if any(k in name for k in ["sub", "dns", "crt", "osint"]):
            t["category"] = "Recon"
        elif any(k in name for k in ["port", "scan", "network"]):
            t["category"] = "Network"
        elif any(k in name for k in ["web", "http", "cookie", "bypass"]):
            t["category"] = "Web"
        else:
            t["category"] = "General"
            
        t["confidence"] = 90 if t.get("review_path") else 60
        if "metrics" not in t:
            t["metrics"] = {"Speed": 8, "Accuracy": 7, "Stealth": 9, "Coverage": 6, "Ease of Use": 8}
            
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("[+] tools.json updated with categories and confidence.")
except Exception as e:
    print("Error updating tools.json:", e)

# =========================================================
# 2. UPDATE app.py (Add Workflow API & Chat API)
# =========================================================
app_code = r'''# -*- coding: utf-8 -*-
import os
import json
import subprocess
import sys
from flask import Flask, render_template, send_from_directory, abort, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

def load_tools():
    try:
        with open(os.path.join(BASE_DIR, "data", "tools.json"), "r", encoding="utf-8") as f:
            return json.load(f).get("tools", [])
    except Exception:
        return []

@app.route("/")
def index():
    return render_template("index.html", tools=load_tools())

@app.route("/tool/<tool_id>")
def tool_detail(tool_id):
    tools = load_tools()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        abort(404)
    
    code_content = ""
    review_content = ""
    
    code_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
    if os.path.exists(code_path):
        with open(code_path, "r", encoding="utf-8") as f:
            code_content = f.read()
            
    review_rel_path = tool.get("review_path", "")
    if review_rel_path:
        review_path = os.path.join(BASE_DIR, review_rel_path)
        if os.path.exists(review_path):
            with open(review_path, "r", encoding="utf-8") as f:
                review_content = f.read()
    
    if not review_content:
        review_content = "No review available."
            
    return render_template("tool_detail.html", tool=tool, code=code_content, review=review_content)

@app.route("/api/run_tool/<tool_id>", methods=["POST"])
def api_run_tool(tool_id):
    tools = load_tools()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "Tool not found"}), 404

    body = request.get_json(silent=True) or {}
    args_str = body.get("args", "").strip()
    
    code_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
    if not os.path.exists(code_path):
        return jsonify({"error": "Script file missing on disk"}), 404

    args_list = args_str.split() if args_str else []
    try:
        result = subprocess.run(
            [sys.executable, code_path] + args_list,
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(code_path), encoding="utf-8", errors="replace"
        )
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# --- WORKFLOW (CHAINING) API ---
@app.route("/api/workflow/recon", methods=["POST"])
def api_workflow_recon():
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target domain required"}), 400

    tools = load_tools()
    subenum_tool = next((t for t in tools if "subenum" in t["name"].lower()), None)
    scanner_tool = next((t for t in tools if "domain_scanner" in t["name"].lower() or "scanner" in t["name"].lower()), None)
    
    if not subenum_tool:
        return jsonify({"error": "subenum tool not found in arsenal."}), 404
        
    # Step 1: Run Subdomain Enum
    subenum_path = os.path.join(BASE_DIR, subenum_tool["file_path"])
    try:
        r1 = subprocess.run([sys.executable, subenum_path, target], capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace")
        result_data = {"step1_subdomains": r1.stdout}
        
        # Try to parse subdomains for Step 2
        if scanner_tool:
            try:
                # Find JSON block in stdout
                s_idx = r1.stdout.find("{")
                if s_idx != -1:
                    parsed = json.loads(r1.stdout[s_idx:])
                    subs = parsed.get("subdomains", [])[:3] # Limit to first 3 for speed
                    
                    scanner_path = os.path.join(BASE_DIR, scanner_tool["file_path"])
                    step2_results = []
                    for sub in subs:
                        r2 = subprocess.run([sys.executable, scanner_path, sub], capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
                        step2_results.append({"target": sub, "output": r2.stdout})
                    
                    result_data["step2_scans"] = step2_results
            except Exception as ex:
                result_data["step2_error"] = str(ex)
                
        return jsonify(result_data)
    except Exception as e:
        return jsonify({"error": str(e)})

# --- AI CHAT API (Mock/Placeholder) ---
@app.route("/api/chat/<tool_id>", methods=["POST"])
def api_chat(tool_id):
    body = request.get_json(silent=True) or {}
    msg = body.get("message", "").lower()
    
    # Simple rule-based AI response
    if "what" in msg or "use" in msg or "does" in msg:
        reply = "This tool is designed to assist in security assessments. Check the 'Review' tab for exact usage instructions and examples."
    elif "fix" in msg or "error" in msg:
        reply = "If the tool fails, ensure the target is reachable and check the stderr output in the terminal for syntax errors."
    else:
        reply = "I am a local assistant. I can explain how to use this tool or help debug basic execution errors. Please be specific."
        
    return jsonify({"reply": reply})

@app.route("/download/<tool_id>")
def download_tool(tool_id):
    tools = load_tools()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        abort(404)
    directory = os.path.join(BASE_DIR, os.path.dirname(tool["file_path"]))
    filename = os.path.basename(tool["file_path"])
    return send_from_directory(directory, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
'''

with open(os.path.join(BASE_DIR, "app.py"), "w", encoding="utf-8") as f:
    f.write(app_code)

# =========================================================
# 3. UPDATE index.html (Search, Filters, Workflow)
# =========================================================
index_html = r'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Curated Arsenal | Security Tools</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <header>
        <h1>⚔️ Curated Arsenal</h1>
        <p>Production-ready security tools, reviewed and refined.</p>
        
        <!-- Workflow Section -->
        <div class="workflow-box">
            <h3>🚀 Auto Recon Workflow</h3>
            <p style="font-size:12px; color:#8b949e;">Runs Subdomain Enum, then scans the first 3 live subdomains.</p>
            <div class="workflow-input">
                <input type="text" id="wfTarget" placeholder="Enter target domain (e.g., hackerone.com)">
                <button onclick="runWorkflow()" id="wfBtn">Start Workflow</button>
            </div>
            <pre id="wfOutput" class="wf-output" style="display:none;"></pre>
        </div>

        <!-- Search & Filters -->
        <div class="search-container">
            <input type="text" id="searchInput" placeholder="🔍 Search tools..." onkeyup="filterTools()">
        </div>
        <div class="filters">
            <button class="filter-btn active" onclick="filterCategory('all')">All</button>
            <button class="filter-btn" onclick="filterCategory('recon')">Recon</button>
            <button class="filter-btn" onclick="filterCategory('network')">Network</button>
            <button class="filter-btn" onclick="filterCategory('web')">Web</button>
        </div>
    </header>
    
    <main>
        <div class="grid" id="toolsGrid">
            {% for tool in tools %}
            <a href="/tool/{{ tool.id }}" class="card" data-name="{{ tool.name | lower }}" data-cat="{{ tool.category | lower }}" data-tags="{{ tool.tags | join(' ') | lower }}">
                <h2>{{ tool.name }}</h2>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="category">{{ tool.category }}</span>
                    <span class="confidence">⭐ {{ tool.confidence }}%</span>
                </div>
                <p>{{ tool.description }}</p>
            </a>
            {% endfor %}
        </div>
        <div id="noResults" style="display: none; text-align: center; margin-top: 40px; color: #8b949e;">
            <h2>No tools found.</h2>
        </div>
    </main>

    <script>
        function filterTools() {
            const input = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.card');
            let visibleCount = 0;

            cards.forEach(card => {
                const name = card.getAttribute('data-name');
                const tags = card.getAttribute('data-tags');
                if (name.includes(input) || tags.includes(input)) {
                    card.style.display = 'block';
                    visibleCount++;
                } else {
                    card.style.display = 'none';
                }
            });
            document.getElementById('noResults').style.display = (visibleCount === 0) ? 'block' : 'none';
        }

        function filterCategory(cat) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {
                if (cat === 'all' || card.getAttribute('data-cat') === cat) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        async function runWorkflow() {
            const target = document.getElementById('wfTarget').value;
            const btn = document.getElementById('wfBtn');
            const out = document.getElementById('wfOutput');
            if(!target) return alert("Enter a target!");

            btn.disabled = true; btn.innerText = "Running...";
            out.style.display = 'block'; out.innerText = "Starting workflow... This may take a minute.";

            try {
                const res = await fetch("/api/workflow/recon", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({target: target})
                });
                const data = await res.json();
                out.innerText = JSON.stringify(data, null, 2);
            } catch (e) {
                out.innerText = "Error: " + e.message;
            }
            btn.disabled = false; btn.innerText = "Start Workflow";
        }
    </script>
</body>
</html>
'''
with open(os.path.join(BASE_DIR, "templates", "index.html"), "w", encoding="utf-8") as f:
    f.write(index_html)

# =========================================================
# 4. UPDATE tool_detail.html (Add AI Chat)
# =========================================================
html_detail = r'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ tool.name }} | Curated Arsenal</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
</head>
<body>
    <header>
        <a href="/" style="color: #00ffcc; text-decoration: none;">&larr; Back</a>
        <h1>{{ tool.name }}</h1>
    </header>
    
    <main class="detail-layout">
        <aside class="sidebar">
            <div class="meta-box">
                <p><strong>Category:</strong> {{ tool.category }}</p>
                <p><strong>Usage:</strong> <code>{{ tool.usage }}</code></p>
                <a href="/download/{{ tool.id }}" class="btn-download">&#11015; Download</a>
                <button onclick="downloadPDF()" class="btn-download" style="background: #e74c3c; border:none; cursor:pointer;">📄 PDF Report</button>
            </div>
            
            <!-- AI Chat -->
            <div class="chat-box">
                <h3>🤖 Tool Assistant</h3>
                <div id="chatHistory" class="chat-history"></div>
                <div class="chat-input">
                    <input type="text" id="chatMsg" placeholder="Ask how to use it...">
                    <button onclick="sendChat()">Send</button>
                </div>
            </div>

            <div class="chart-box">
                <h3>Capabilities</h3>
                <canvas id="radarChart"></canvas>
            </div>
        </aside>

        <section class="content">
            <div class="terminal-container">
                <div class="terminal-header" style="display:flex; justify-content:space-between;">
                    <span>● ● ● Terminal</span>
                    <div>
                        <button onclick="generateReport()" class="term-btn" style="background: #e74c3c; color: white;">📝 Generate Report</button>
                    </div>
                </div>
                <div class="terminal-input-row">
                    <span class="prompt">$</span>
                    <input type="text" id="args-input" placeholder="Arguments (e.g., example.com)" />
                    <button onclick="runTool()" id="run-btn">RUN</button>
                </div>
                <pre id="terminal-output" class="terminal-output">Ready...</pre>
            </div>

            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('code')">Source</button>
                <button class="tab-btn" onclick="showTab('review')">Review</button>
            </div>
            <div id="code" class="tab-content active"><pre><code class="language-python">{{ code }}</code></pre></div>
            <div id="review" class="tab-content"><div class="review-content">{{ review }}</div></div>
        </section>
    </main>

    <!-- Report Modal -->
    <div id="reportModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="document.getElementById('reportModal').style.display='none'">&times;</span>
            <h2>Bug Report</h2>
            <textarea id="reportText"></textarea>
            <button onclick="copyReport()" class="modal-btn">📋 Copy</button>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script>
        let currentOutput = "";
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }

        // Chart
        const metrics = {{ tool.metrics | default({}) | tojson | safe }};
        new Chart(document.getElementById('radarChart'), {
            type: 'radar',
            data: { labels: Object.keys(metrics), datasets: [{ data: Object.values(metrics), backgroundColor: 'rgba(0, 255, 204, 0.2)', borderColor: '#00ffcc' }] },
            options: { scales: { r: { ticks: { display: false, min: 0, max: 10 } } }, plugins: { legend: { display: false } } }
        });

        // Terminal
        async function runTool() {
            const args = document.getElementById('args-input').value;
            const out = document.getElementById('terminal-output');
            document.getElementById('run-btn').disabled = true;
            out.innerText = "Executing...";
            try {
                const res = await fetch("/api/run_tool/{{ tool.id }}", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({args: args}) });
                const data = await res.json();
                currentOutput = data.error ? data.error : (data.stdout + (data.stderr ? "\n[STDERR]\n" + data.stderr : ""));
                out.innerText = currentOutput || "(No output)";
            } catch (e) { out.innerText = e.message; }
            document.getElementById('run-btn').disabled = false;
        }

        // AI Chat
        async function sendChat() {
            const msg = document.getElementById('chatMsg').value;
            const hist = document.getElementById('chatHistory');
            if(!msg) return;
            hist.innerHTML += `<div class="chat-msg user">${msg}</div>`;
            document.getElementById('chatMsg').value = "";
            
            try {
                const res = await fetch("/api/chat/{{ tool.id }}", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({message: msg}) });
                const data = await res.json();
                hist.innerHTML += `<div class="chat-msg bot">${data.reply}</div>`;
                hist.scrollTop = hist.scrollHeight;
            } catch (e) {
                hist.innerHTML += `<div class="chat-msg bot">Error connecting to AI.</div>`;
            }
        }

        // Report
        function generateReport() {
            const target = document.getElementById('args-input').value || '[TARGET]';
            const template = `# Report\n\nTarget: ${target}\n\nOutput:\n\`\`\`\n${currentOutput}\n\`\`\``;
            document.getElementById('reportText').value = template;
            document.getElementById('reportModal').style.display = 'block';
        }
        function copyReport() {
            document.getElementById('reportText').select();
            document.execCommand('copy');
            alert("Copied!");
        }
    </script>
</body>
</html>
'''
with open(os.path.join(BASE_DIR, "templates", "tool_detail.html"), "w", encoding="utf-8") as f:
    f.write(html_detail)

# =========================================================
# 5. UPDATE style.css
# =========================================================
css_code = r'''
:root { --bg: #0d1117; --card-bg: #161b22; --text: #c9d1d9; --accent: #00ffcc; --border: #30363d; }
body { font-family: 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); margin: 0; }
header { text-align: center; padding: 30px 20px; border-bottom: 1px solid var(--border); }
h1 { margin: 0; color: var(--accent); }
main { max-width: 1400px; margin: 20px auto; padding: 0 20px; }

/* Workflow */
.workflow-box { background: var(--card-bg); border: 1px solid var(--accent); border-radius: 8px; padding: 15px; max-width: 600px; margin: 20px auto; text-align: left; }
.workflow-box h3 { margin: 0 0 10px 0; color: var(--accent); }
.workflow-input { display: flex; gap: 10px; margin-top: 10px; }
#wfTarget { flex: 1; padding: 10px; background: #000; border: 1px solid var(--border); color: white; border-radius: 4px; }
#wfBtn { background: var(--accent); color: #000; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
.wf-output { background: #000; padding: 10px; border-radius: 4px; font-size: 12px; margin-top: 10px; max-height: 200px; overflow-y: auto; color: #00ff00; }

/* Search & Filters */
.search-container { margin: 20px auto; display: flex; justify-content: center; }
#searchInput { width: 60%; padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 30px; color: white; outline: none; }
#searchInput:focus { border-color: var(--accent); }
.filters { display: flex; justify-content: center; gap: 10px; margin-bottom: 20px; }
.filter-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 20px; cursor: pointer; }
.filter-btn.active, .filter-btn:hover { border-color: var(--accent); color: var(--accent); }

.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-decoration: none; color: var(--text); transition: 0.2s; }
.card:hover { transform: translateY(-5px); border-color: var(--accent); }
.category { background: #21262d; padding: 4px 8px; border-radius: 4px; font-size: 12px; color: var(--accent); }
.confidence { font-size: 12px; color: #f1c40f; }

/* Details */
.detail-layout { display: grid; grid-template-columns: 350px 1fr; gap: 30px; }
.sidebar { display: flex; flex-direction: column; gap: 20px; }
.meta-box, .chart-box, .chat-box { background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 8px; }
.btn-download { display: block; margin-top: 10px; background: var(--accent); color: #000; padding: 10px; text-decoration: none; border-radius: 6px; font-weight: bold; text-align: center; width: 100%; box-sizing: border-box; }

/* Chat Box */
.chat-history { height: 150px; overflow-y: auto; background: #000; padding: 10px; border-radius: 4px; margin-bottom: 10px; font-size: 13px; }
.chat-msg { margin-bottom: 8px; padding: 5px 10px; border-radius: 10px; max-width: 90%; }
.chat-msg.user { background: #21262d; color: white; margin-left: auto; width: fit-content; }
.chat-msg.bot { background: var(--accent); color: #000; margin-right: auto; width: fit-content; }
.chat-input { display: flex; gap: 5px; }
.chat-input input { flex: 1; background: #000; border: 1px solid var(--border); color: white; padding: 8px; border-radius: 4px; }
.chat-input button { background: var(--accent); color: #000; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }

/* Terminal */
.terminal-container { background: #000; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
.terminal-header { background: #161b22; padding: 10px; border-bottom: 1px solid var(--border); font-family: monospace; color: #8b949e; }
.term-btn { background: #21262d; border: 1px solid var(--border); color: var(--text); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
.term-btn:hover { border-color: var(--accent); color: var(--accent); }
.terminal-input-row { display: flex; padding: 10px; border-bottom: 1px solid var(--border); gap: 10px; align-items: center; }
#args-input { flex: 1; background: transparent; border: none; color: #fff; font-family: monospace; outline: none; }
#run-btn { background: var(--accent); color: #000; border: none; padding: 5px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }
.terminal-output { margin: 0; padding: 15px; color: #00ff00; font-family: monospace; font-size: 14px; white-space: pre-wrap; min-height: 200px; max-height: 500px; overflow-y: auto; }

/* Tabs & Modal */
.tabs { display: flex; gap: 10px; margin-bottom: 20px; }
.tab-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 10px 20px; cursor: pointer; border-radius: 6px; }
.tab-btn.active { border-color: var(--accent); color: var(--accent); }
.tab-content { display: none; }
.tab-content.active { display: block; }
pre { margin: 0; border-radius: 8px; }
.review-content { background: var(--card-bg); padding: 20px; border-radius: 8px; white-space: pre-wrap; }

.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.8); }
.modal-content { background-color: var(--card-bg); margin: 5% auto; padding: 20px; border: 1px solid var(--border); width: 80%; max-width: 900px; border-radius: 8px; }
.close-btn { color: #8b949e; float: right; font-size: 28px; cursor: pointer; }
#reportText { width: 100%; height: 400px; background: #000; color: #00ffcc; font-family: monospace; padding: 15px; margin-bottom: 15px; box-sizing: border-box; }
.modal-btn { background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }

@media (max-width: 900px) { .detail-layout { grid-template-columns: 1fr; } }
'''
with open(os.path.join(BASE_DIR, "static", "css", "style.css"), "w", encoding="utf-8") as f:
    f.write(css_code)

print("✅ Full Platform Upgrade Complete!")
print("Restarting server recommended.")