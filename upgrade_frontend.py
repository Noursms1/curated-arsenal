import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================================================
# 1. UPDATE tool_detail.html
# =========================================================
html_code = r'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ tool.name }} | Curated Arsenal</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    
    <!-- Charts & PDF Libraries -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
</head>
<body>
    <header>
        <a href="/" style="color: #00ffcc; text-decoration: none;">&larr; Back to Arsenal</a>
        <h1>{{ tool.name }}</h1>
        <p>{{ tool.description }}</p>
    </header>
    
    <main class="detail-layout">
        <aside class="sidebar">
            <div class="meta-box">
                <p><strong>Category:</strong> {{ tool.category }}</p>
                <p><strong>Usage:</strong> <code>{{ tool.usage }}</code></p>
                <a href="/download/{{ tool.id }}" class="btn-download">&#11015; Download Script</a>
                <button onclick="downloadPDF()" class="btn-download" style="background: #e74c3c; margin-top: 5px; border: none; cursor: pointer;">&#128196; Download PDF Report</button>
            </div>
            
            <div class="chart-box">
                <h3>Tool Capabilities</h3>
                <canvas id="radarChart"></canvas>
            </div>
        </aside>

        <section class="content">
            <div class="terminal-container">
                <div class="terminal-header" style="display:flex; justify-content:space-between;">
                    <span>&#9679; &#9679; &#9679; Terminal Runner</span>
                    <div>
                        <button onclick="translateOutput()" class="term-btn">🌐 Translate Keys</button>
                        <button onclick="formatOutput()" class="term-btn">🎨 Beautify JSON</button>
                    </div>
                </div>
                <div class="terminal-input-row">
                    <span class="prompt">$</span>
                    <input type="text" id="args-input" placeholder="Enter arguments (e.g., example.com)" />
                    <button onclick="runTool()" id="run-btn">RUN</button>
                </div>
                <pre id="terminal-output" class="terminal-output">Ready to execute...</pre>
            </div>

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

    <!-- Hidden Div for PDF Generation -->
    <div id="pdf-content" style="display:none; padding: 40px; background: white; color: black; width: 800px; font-family: Arial;">
        <h1 style="color: #333;">Curated Arsenal - Scan Report</h1>
        <hr style="border: 1px solid #ccc; margin: 20px 0;">
        <p><strong>Tool:</strong> {{ tool.name }}</p>
        <p><strong>Category:</strong> {{ tool.category }}</p>
        <p><strong>Arguments:</strong> <span id="pdf-args">-</span></p>
        <p><strong>Date:</strong> <span id="pdf-date">-</span></p>
        <hr style="border: 1px solid #ccc; margin: 20px 0;">
        <h3>Output:</h3>
        <pre id="pdf-output" style="white-space: pre-wrap; font-size: 12px; background: #f4f4f4; padding: 15px; border-radius: 5px;"></pre>
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

        // --- RADAR CHART ---
        const metrics = {{ tool.metrics | tojson | safe }};
        new Chart(document.getElementById('radarChart'), {
            type: 'radar',
            data: {
                labels: Object.keys(metrics),
                datasets: [{
                    data: Object.values(metrics),
                    backgroundColor: 'rgba(0, 255, 204, 0.2)',
                    borderColor: '#00ffcc',
                    pointBackgroundColor: '#00ffcc',
                }]
            },
            options: {
                scales: { r: { angleLines: { color: '#30363d' }, grid: { color: '#30363d' }, pointLabels: { color: '#c9d1d9' }, ticks: { display: false, min: 0, max: 10 } } },
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
            output.innerText = "Executing...\n";
            
            try {
                const res = await fetch("/api/run_tool/{{ tool.id }}", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({args: args})
                });
                const data = await res.json();
                
                if (data.error) {
                    currentOutput = "❌ Error: " + data.error;
                    output.innerText = currentOutput;
                } else {
                    let txt = "";
                    if (data.stdout) txt += data.stdout;
                    if (data.stderr) txt += "\n[STDERR]\n" + data.stderr;
                    currentOutput = txt || "(No output)";
                    beautify();
                }
            } catch (e) {
                currentOutput = "❌ Network Error: " + e.message;
                output.innerText = currentOutput;
            }
            
            btn.disabled = false;
            btn.innerText = "RUN";
        }

        // --- FORMATTING & COLORING ---
        function colorizeJSON(json) {
            if (typeof json != 'string') json = JSON.stringify(json, undefined, 2);
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
                let cls = 'number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) cls = 'key';
                    else cls = 'string';
                } else if (/true|false/.test(match)) cls = 'boolean';
                else if (/null/.test(match)) cls = 'null';
                return '<span class="json-' + cls + '">' + match + '</span>';
            });
        }

        function beautify() {
            const output = document.getElementById('terminal-output');
            try {
                const parsed = JSON.parse(currentOutput);
                output.innerHTML = colorizeJSON(parsed);
            } catch (e) {
                output.innerText = currentOutput;
            }
        }

        function formatOutput() {
            beautify();
        }

        // --- TRANSLATION ---
        const dict = {
            "domain": "النطاق", "subdomains": "النطاقات الفرعية", "count": "العدد", 
            "source": "المصدر", "ip_address": "عنوان IP", "status": "الحالة", 
            "error": "خطأ", "ports": "المنافذ", "open_ports": "منافذ مفتوحة",
            "server": "الخادم", "url": "الرابط", "cookies": "الكوكيز",
            "security_headers": "هيدرز الحماية", "risk": "المخاطر", "score": "التقييم"
        };

        function translateKeys(obj) {
            if (Array.isArray(obj)) return obj.map(translateKeys);
            else if (obj !== null && typeof obj === 'object') {
                const newObj = {};
                for (let key in obj) {
                    const transKey = dict[key.toLowerCase()] || key;
                    newObj[transKey] = translateKeys(obj[key]);
                }
                return newObj;
            }
            return obj;
        }

        function translateOutput() {
            try {
                const parsed = JSON.parse(currentOutput);
                const translated = translateKeys(parsed);
                document.getElementById('terminal-output').innerHTML = colorizeJSON(translated);
            } catch (e) {
                alert("Output is not valid JSON, cannot translate keys.");
            }
        }

        // --- PDF GENERATION ---
        async function downloadPDF() {
            const { jsPDF } = window.jspdf;
            const pdfContent = document.getElementById('pdf-content');
            
            // Fill data
            document.getElementById('pdf-args').innerText = document.getElementById('args-input').value || "None";
            document.getElementById('pdf-date').innerText = new Date().toLocaleString();
            document.getElementById('pdf-output').innerText = currentOutput;

            // Capture
            const canvas = await html2canvas(pdfContent, { scale: 2 });
            const imgData = canvas.toDataURL('image/png');
            
            const pdf = new jsPDF('p', 'mm', 'a4');
            const pdfWidth = pdf.internal.pageSize.getWidth();
            const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
            
            pdf.addImage(imgData, 'PNG', 0, 10, pdfWidth, pdfHeight);
            pdf.save('{{ tool.id }}_Report.pdf');
        }
    </script>
</body>
</html>
'''

# =========================================================
# 2. UPDATE style.css
# =========================================================
css_code = r'''
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

.detail-layout { display: grid; grid-template-columns: 350px 1fr; gap: 30px; }
.sidebar { display: flex; flex-direction: column; gap: 20px; }
.meta-box, .chart-box { background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 8px; }
.meta-box code { background: #000; padding: 4px 8px; border-radius: 4px; color: var(--accent); word-break: break-all; }
.btn-download { display: inline-block; margin-top: 10px; background: var(--accent); color: #000; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; width: 100%; text-align: center; box-sizing: border-box; font-family: inherit; font-size: 16px;}

.terminal-container { background: #000; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
.terminal-header { background: #161b22; padding: 10px; border-bottom: 1px solid var(--border); font-family: monospace; color: #8b949e; }
.term-btn { background: #21262d; border: 1px solid var(--border); color: var(--text); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 10px; }
.term-btn:hover { border-color: var(--accent); color: var(--accent); }

.terminal-input-row { display: flex; padding: 10px; border-bottom: 1px solid var(--border); gap: 10px; align-items: center; }
.terminal-input-row .prompt { color: var(--accent); font-family: monospace; font-weight: bold; }
#args-input { flex: 1; background: transparent; border: none; color: #fff; font-family: monospace; outline: none; }
#run-btn { background: var(--accent); color: #000; border: none; padding: 5px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }
#run-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.terminal-output { margin: 0; padding: 15px; color: #00ff00; font-family: monospace; font-size: 14px; white-space: pre-wrap; min-height: 200px; max-height: 500px; overflow-y: auto; }

/* JSON Syntax Highlighting Colors */
.json-key { color: #ff7b72; }
.json-string { color: #a5d6ff; }
.json-number { color: #79c0ff; }
.json-boolean { color: #ffa657; }
.json-null { color: #8b949e; }

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

with open(os.path.join(BASE_DIR, "templates", "tool_detail.html"), "w", encoding="utf-8") as f:
    f.write(html_code)

with open(os.path.join(BASE_DIR, "static", "css", "style.css"), "w", encoding="utf-8") as f:
    f.write(css_code)

print("Upgrade complete! Restart Flask server.")