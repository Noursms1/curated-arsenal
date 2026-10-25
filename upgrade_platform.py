import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================================================
# 1. UPDATE app.py (Add API to run the tool safely)
# =========================================================
app_code = '''# -*- coding: utf-8 -*-
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
    
    code_path = os.path.join(BASE_DIR, tool["file_path"])
    if os.path.exists(code_path):
        with open(code_path, "r", encoding="utf-8") as f:
            code_content = f.read()
            
    review_path = os.path.join(BASE_DIR, tool["review_path"])
    if os.path.exists(review_path):
        with open(review_path, "r", encoding="utf-8") as f:
            review_content = f.read()
            
    return render_template("tool_detail.html", tool=tool, code=code_content, review=review_content)

@app.route("/api/run_tool/<tool_id>", methods=["POST"])
def api_run_tool(tool_id):
    tools = load_tools()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        return jsonify({"error": "Tool not found"}), 404

    body = request.get_json(silent=True) or {}
    args_str = body.get("args", "").strip()
    
    code_path = os.path.join(BASE_DIR, tool["file_path"])
    if not os.path.exists(code_path):
        return jsonify({"error": "Script file missing on disk"}), 404

    # Use safe subprocess (shell=False)
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
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Execution timed out (60s)"})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/download/<tool_id>")
def download_tool(tool_id):
    tools = load_tools()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        abort(404)
    directory = os.path.join(BASE_DIR, os.path.dirname(tool["file_path"]))
    filename = os.path.basename(tool["file_path"])
    return send_from_directory(directory, filename, as_attachment=True)

@app.route("/api/tools")
def api_tools():
    return jsonify(load_tools())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
'''
with open(os.path.join(BASE_DIR, "app.py"), "w", encoding="utf-8") as f:
    f.write(app_code)

# =========================================================
# 2. UPDATE tools.json (Add metrics for the chart)
# =========================================================
json_path = os.path.join(BASE_DIR, "data", "tools.json")
try:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    for t in data.get("tools", []):
        # Add mock metrics if missing (0 to 10 scale)
        if "metrics" not in t:
            t["metrics"] = {
                "Speed": 8,
                "Accuracy": 7,
                "Stealth": 9,
                "Coverage": 6,
                "Ease of Use": 8
            }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
except Exception as e:
    print("Error updating tools.json:", e)

# =========================================================
# 3. UPDATE tool_detail.html (Add Terminal + Chart)
# =========================================================
html_code = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ tool.name }} | Curated Arsenal</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <a href="/" style="color: #00ffcc; text-decoration: none;">← Back to Arsenal</a>
        <h1>{{ tool.name }}</h1>
        <p>{{ tool.description }}</p>
    </header>
    
    <main class="detail-layout">
        <!-- Left Column: Info & Chart -->
        <aside class="sidebar">
            <div class="meta-box">
                <p><strong>Category:</strong> {{ tool.category }}</p>
                <p><strong>Usage:</strong> <code>{{ tool.usage }}</code></p>
                <a href="/download/{{ tool.id }}" class="btn-download">⬇ Download Script</a>
            </div>
            
            <div class="chart-box">
                <h3>Tool Capabilities</h3>
                <canvas id="radarChart"></canvas>
            </div>
        </aside>

        <!-- Right Column: Terminal & Code -->
        <section class="content">
            <!-- Terminal Runner -->
            <div class="terminal-container">
                <div class="terminal-header">
                    <span>● ● ● Terminal Runner</span>
                </div>
                <div class="terminal-input-row">
                    <span class="prompt">$</span>
                    <input type="text" id="args-input" placeholder="Enter arguments (e.g., example.com)" />
                    <button onclick="runTool()" id="run-btn">RUN</button>
                </div>
                <pre id="terminal-output" class="terminal-output">Ready to execute...</pre>
            </div>

            <!-- Tabs for Code/Review -->
            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('code')">Source Code</button>
                <button class="tab-btn" onclick="showTab('review')">Review</button>
            </div>

            <div id="code" class="tab-content active">
                <pre><code class="language-python">{{ code }}</code></pre>
            </div>
            <div id="review" class="tab-content">
                <div class="review-content">{{ review }}</div>
            </div>
        </section>
    </main>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }

        // --- RADAR CHART ---
        const metrics = {{ tool.metrics | tojson | safe }};
        const labels = Object.keys(metrics);
        const dataValues = Object.values(metrics);

        new Chart(document.getElementById('radarChart'), {
            type: 'radar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Score (out of 10)',
                    data: dataValues,
                    backgroundColor: 'rgba(0, 255, 204, 0.2)',
                    borderColor: '#00ffcc',
                    pointBackgroundColor: '#00ffcc',
                }]
            },
            options: {
                scales: {
                    r: {
                        angleLines: { color: '#30363d' },
                        grid: { color: '#30363d' },
                        pointLabels: { color: '#c9d1d9' },
                        ticks: { display: false, min: 0, max: 10 }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });

        // --- TERMINAL RUNNER ---
        async function runTool() {
            const args = document.getElementById('args-input').value;
            const btn = document.getElementById('run-btn');
            const output = document.getElementById('terminal-output');
            
            btn.disabled = true;
            btn.innerText = "...";
            output.innerText = "Executing...\\n";
            
            try {
                const res = await fetch("/api/run_tool/{{ tool.id }}", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({args: args})
                });
                const data = await res.json();
                
                if (data.error) {
                    output.innerText = "❌ Error: " + data.error;
                } else {
                    let txt = "";
                    if (data.stdout) txt += data.stdout;
                    if (data.stderr) txt += "\\n[STDERR]\\n" + data.stderr;
                    output.innerText = txt || "(No output)";
                }
            } catch (e) {
                output.innerText = "❌ Network Error: " + e.message;
            }
            
            btn.disabled = false;
            btn.innerText = "RUN";
        }
    </script>
</body>
</html>
'''
with open(os.path.join(BASE_DIR, "templates", "tool_detail.html"), "w", encoding="utf-8") as f:
    f.write(html_code)

# =========================================================
# 4. UPDATE style.css (Styles for Terminal and Layout)
# =========================================================
css_code = '''
:root {
    --bg: #0d1117; --card-bg: #161b22; --text: #c9d1d9;
    --accent: #00ffcc; --border: #30363d;
}
body { font-family: 'Segoe UI', sans-serif; background-color: var(--bg); color: var(--text); margin: 0; }
header { text-align: center; padding: 30px 20px; border-bottom: 1px solid var(--border); }
header h1 { margin: 0; color: var(--accent); }

main { max-width: 1400px; margin: 20px auto; padding: 0 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-decoration: none; color: var(--text); transition: 0.2s; }
.card:hover { transform: translateY(-5px); border-color: var(--accent); }
.category { background: #21262d; padding: 4px 8px; border-radius: 4px; font-size: 12px; color: var(--accent); }
.tag { background: #30363d; padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-right: 5px; }

/* Detail Layout */
.detail-layout { display: grid; grid-template-columns: 350px 1fr; gap: 30px; }
.sidebar { display: flex; flex-direction: column; gap: 20px; }
.meta-box, .chart-box { background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 8px; }
.meta-box code { background: #000; padding: 4px 8px; border-radius: 4px; color: var(--accent); word-break: break-all; }
.btn-download { display: inline-block; margin-top: 10px; background: var(--accent); color: #000; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box;}

/* Terminal Runner */
.terminal-container { background: #000; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
.terminal-header { background: #161b22; padding: 10px; border-bottom: 1px solid var(--border); font-family: monospace; color: #8b949e; }
.terminal-input-row { display: flex; padding: 10px; border-bottom: 1px solid var(--border); gap: 10px; align-items: center; }
.terminal-input-row .prompt { color: var(--accent); font-family: monospace; font-weight: bold; }
#args-input { flex: 1; background: transparent; border: none; color: #fff; font-family: monospace; outline: none; }
#run-btn { background: var(--accent); color: #000; border: none; padding: 5px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }
#run-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.terminal-output { margin: 0; padding: 15px; color: #00ff00; font-family: monospace; font-size: 14px; white-space: pre-wrap; min-height: 150px; max-height: 400px; overflow-y: auto; }

/* Tabs */
.tabs { display: flex; gap: 10px; margin-bottom: 20px; }
.tab-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 10px 20px; cursor: pointer; border-radius: 6px; }
.tab-btn.active { border-color: var(--accent); color: var(--accent); }
.tab-content { display: none; }
.tab-content.active { display: block; }
pre { margin: 0; border-radius: 8px; }
.review-content { background: var(--card-bg); padding: 20px; border-radius: 8px; white-space: pre-wrap; line-height: 1.6; }

@media (max-width: 900px) {
    .detail-layout { grid-template-columns: 1fr; }
}
'''
with open(os.path.join(BASE_DIR, "static", "css", "style.css"), "w", encoding="utf-8") as f:
    f.write(css_code)

print("✅ Upgrade complete! Restart Flask server.")
'''