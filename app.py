# -*- coding: utf-8 -*-
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
@app.route("/api/smart_scan", methods=["POST"])
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
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        target_type = "ip"
    elif "." in target:
        target_type = "domain"

    # 2. Load all tools
    tools = load_tools()
    
    # 3. Select compatible tools
    BLOCKED_KEYWORDS = ["cidr", "subnet", "calc"]
    selected_tools = []
    seen_names = set()
    
    SKIP_KEYWORDS = ["ipv6_", "snmp", "tcp_connect", "tcp_port", 
                     "dns_axfr", "cidr", "wallet", "eth_", "evm_", "erc20",
                     "token_", "jwt", "hash", "decoder", "base64", "signature",
                     "malware", "gas_price", "contract", "reentrancy",
                     "url_extractor", "yara", "password_hash"]
    
    for t in tools:
        cat = t.get("category", "").lower()
        name = t.get("name", "").lower()
        tid = t.get("id", "").lower()
        
        # Skip tools that need special args
        if any(k in tid or k in name for k in SKIP_KEYWORDS):
            continue
        
        # Skip CIDR/subnet calculators (they need CIDR input, not domains)
        if any(k in name for k in BLOCKED_KEYWORDS):
            continue
        
        # Skip duplicates (same base name)
        base_name = name.split("_")[0].split(" ")[0]
        if base_name in seen_names:
            continue
        
        if target_type == "domain":
            if cat in ["recon", "network", "web"]:
                selected_tools.append(t)
                seen_names.add(base_name)
        elif target_type == "ip":
            if cat in ["network"] or "port" in name:
                selected_tools.append(t)
                seen_names.add(base_name)
        elif target_type == "url":
            if cat in ["web"]:
                selected_tools.append(t)
                seen_names.add(base_name)

    # Limit to 5 tools
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
        
        # Smart argument injection based on tool
        tool_name = tool.get("name", "").lower()
        extra_args = []
        
        # Determine proper target arg
        import re as _re
        domain_only = _re.sub(r"^https?://", "", target).split("/")[0].split("?")[0]
        
        if "dns_axfr" in tool_name or "axfr" in tool_name:
            # Needs 2 args: nameserver + domain - skip
            results.append({
                "tool": tool["name"],
                "status": "skipped",
                "output": "Requires nameserver IP + domain. Skipping in smart mode."
            })
            continue
        elif "crtsh" in tool_name or "subenum" in tool_name or "subdomain" in tool_name:
            # Needs domain only (no path)
            exec_target = domain_only
        elif "domain_scanner" in tool_name or "scanner" in tool_name:
            # Check if target has a path (after stripping scheme)
            stripped = _re.sub(r"^https?://", "", target)
            has_path = "/" in stripped
            if has_path:
                exec_target = target if target.startswith(("http://", "https://")) else "https://" + target
                extra_args = ["--no-redirect"]
            else:
                exec_target = domain_only
        elif "cookie" in tool_name or "http_" in tool_name or "bypass" in tool_name:
            # Needs full URL with scheme
            exec_target = target if target.startswith(("http://", "https://")) else "https://" + target
        else:
            exec_target = target
        
        try:
            proc = subprocess.run(
                [sys.executable, tool_path, exec_target] + extra_args,
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

@app.route("/api/cve/map", methods=["POST"])
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


@app.route("/api/analyze_chains", methods=["POST"])
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




# ============================================================
# TIME BRIDGE - Simulation endpoint
# ============================================================
@app.route("/api/simulate/<tool_id>", methods=["POST"])
def api_simulate(tool_id):
    """Run 1000-run simulation on a tool."""
    import sys as _sys
    _sys.path.insert(0, os.path.join(BASE_DIR, "engine"))
    try:
        from tool_simulator import simulate_tool
        tools = load_tools()
        tool = next((t for t in tools if t["id"] == tool_id), None)
        if not tool:
            return jsonify({"error": "Tool not found"}), 404
        
        tool_path = os.path.join(BASE_DIR, tool.get("file_path", ""))
        if not os.path.exists(tool_path):
            return jsonify({"error": "Tool file not found"}), 404
        
        results = simulate_tool(tool_path, runs=1000)
        
        # Save back to tools.json
        tool["simulation"] = results
        tools_json_path = os.path.join(BASE_DIR, "data", "tools.json")
        with open(tools_json_path, "w", encoding="utf-8") as f:
            json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
