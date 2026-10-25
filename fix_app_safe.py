import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. Fix app.py (Handle empty review paths safely)
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
    
    # Read Code (Safe)
    code_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
    if tool.get("file_path") and os.path.exists(code_path) and os.path.isfile(code_path):
        with open(code_path, "r", encoding="utf-8") as f:
            code_content = f.read()
            
    # Read Review (Safe for empty paths)
    review_rel_path = tool.get("review_path", "")
    if review_rel_path:
        review_path = os.path.join(BASE_DIR, review_rel_path)
        if os.path.exists(review_path) and os.path.isfile(review_path):
            with open(review_path, "r", encoding="utf-8") as f:
                review_content = f.read()
    
    # Default review if empty
    if not review_content:
        review_content = "No review available for this tool yet."
            
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

print("Fixed app.py!")