# -*- coding: utf-8 -*-
"""
Tool Simulator - Runs a tool 1000 times:
- 20 real tests (safe targets, with timeouts)
- 980 pattern-based checks (code analysis)
Produces failure/success patterns and verdict.
"""
import os
import sys
import subprocess
import re


def simulate_tool(tool_path, runs=1000):
    """Simulate tool success/failure across many scenarios."""
    results = {
        "total_runs": runs,
        "real_runs": 0,
        "pattern_runs": 0,
        "success_count": 0,
        "failure_count": 0,
        "failure_patterns": {},
        "success_patterns": [],
        "recommendations": [],
        "verdict": "UNKNOWN",
    }
    
    if not os.path.exists(tool_path):
        results["verdict"] = "ERROR"
        results["error"] = "Tool file not found"
        return results
    
    # ========== PART 1: 20 REAL TESTS ==========
    real_scenarios = [
        {"args": [], "expect": "fail", "reason": "no args"},
        {"args": ["--help"], "expect": "success", "reason": "help flag"},
        {"args": ["--self-test"], "expect": "success", "reason": "self-test"},
        {"args": ["example.com"], "expect": "success", "reason": "valid domain"},
        {"args": ["scanme.nmap.org"], "expect": "success", "reason": "nmap test"},
        {"args": ["testphp.vulnweb.com"], "expect": "success", "reason": "vuln test"},
        {"args": ["httpbin.org"], "expect": "success", "reason": "httpbin"},
        {"args": ["https://example.com"], "expect": "success", "reason": "with scheme"},
        {"args": ["127.0.0.1"], "expect": "fail", "reason": "private IP"},
        {"args": ["192.168.1.1"], "expect": "fail", "reason": "private IP"},
        {"args": ["invalid!@#.com"], "expect": "fail", "reason": "malformed"},
        {"args": [""], "expect": "fail", "reason": "empty"},
        {"args": ["a" * 300], "expect": "fail", "reason": "too long"},
        {"args": ["--unknown-flag"], "expect": "fail", "reason": "unknown flag"},
        {"args": ["example.com", "--timeout", "0"], "expect": "fail", "reason": "zero timeout"},
        {"args": ["example.com", "--timeout", "999"], "expect": "fail", "reason": "huge timeout"},
        {"args": ["-"], "expect": "fail", "reason": "dash only"},
        {"args": ["--port", "99999"], "expect": "fail", "reason": "invalid port"},
        {"args": ["--port", "-1"], "expect": "fail", "reason": "negative port"},
        {"args": ["example.com", "--verbose"], "expect": "success", "reason": "with flag"},
    ]
    
    for scenario in real_scenarios:
        try:
            cmd = [sys.executable, tool_path] + scenario["args"]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                cwd=os.path.dirname(tool_path),
                encoding="utf-8", errors="replace"
            )
            actual = "success" if proc.returncode == 0 else "fail"
            results["real_runs"] += 1
            if actual == scenario["expect"]:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1
                key = scenario["reason"] + " (expected " + scenario["expect"] + ", got " + actual + ")"
                results["failure_patterns"][key] = results["failure_patterns"].get(key, 0) + 1
        except subprocess.TimeoutExpired:
            results["real_runs"] += 1
            results["failure_count"] += 1
            results["failure_patterns"]["timeout in scenario: " + scenario["reason"]] = 1
        except Exception as e:
            results["real_runs"] += 1
            results["failure_count"] += 1
            results["failure_patterns"]["exception: " + str(e)[:60]] = 1
    
    # ========== PART 2: 980 PATTERN-BASED CHECKS ==========
    with open(tool_path, "r", encoding="utf-8") as f:
        code = f.read()
    
    checks = {
        "has_timeout": "timeout=" in code,
        "has_try_except": "try:" in code and "except" in code,
        "has_json_output": '"status"' in code and '"target"' in code,
        "has_self_test": "--self-test" in code or "self_test" in code,
        "no_os_system": "os.system" not in code,
        "no_eval": "eval(" not in code,
        "no_verify_false": "verify=False" not in code,
        "has_rate_limit": "time.sleep" in code,
        "has_input_validation": ("re.match" in code) or ("ipaddress" in code) or ("validate" in code.lower()),
        "has_metadata": "CATEGORY:" in code,
    }
    
    # Distribute 980 checks evenly (98 per check)
    weight_per_check = 980 // len(checks)  # = 98
    total_weight = weight_per_check * len(checks)  # = 980
    
    for check_name, passed in checks.items():
        results["pattern_runs"] += weight_per_check
        if passed:
            results["success_count"] += weight_per_check
            results["success_patterns"].append(check_name)
        else:
            results["failure_count"] += weight_per_check
            fail_key = check_name.replace("has_", "missing_").replace("no_", "uses_")
            results["failure_patterns"][fail_key] = results["failure_patterns"].get(fail_key, 0) + weight_per_check
    
    # ========== PART 3: RECOMMENDATIONS ==========
    if not checks["has_timeout"]:
        results["recommendations"].append("Add timeout=10 to all network calls")
    if not checks["has_try_except"]:
        results["recommendations"].append("Wrap network ops in try/except")
    if not checks["has_json_output"]:
        results["recommendations"].append("Ensure JSON output has 'status' and 'target' keys")
    if not checks["has_self_test"]:
        results["recommendations"].append("Add --self-test flag")
    if not checks["no_os_system"]:
        results["recommendations"].append("Replace os.system() with subprocess.run(shell=False)")
    if not checks["no_eval"]:
        results["recommendations"].append("Remove eval() — security risk")
    if not checks["no_verify_false"]:
        results["recommendations"].append("Remove verify=False — MITM risk")
    if not checks["has_rate_limit"]:
        results["recommendations"].append("Add time.sleep(0.5) between requests")
    if not checks["has_input_validation"]:
        results["recommendations"].append("Add input validation (regex/ipaddress)")
    if not checks["has_metadata"]:
        results["recommendations"].append("Add CATEGORY: to docstring")
    
    # ========== PART 4: VERDICT ==========
    total = results["real_runs"] + results["pattern_runs"]
    if total > 0:
        results["success_rate"] = round(results["success_count"] / total * 100, 2)
        results["failure_rate"] = round(results["failure_count"] / total * 100, 2)
    else:
        results["success_rate"] = 0
        results["failure_rate"] = 100
    
    if results["success_rate"] >= 85:
        results["verdict"] = "PASS"
    elif results["success_rate"] >= 70:
        results["verdict"] = "WARN"
    else:
        results["verdict"] = "FAIL"
    
    # Cap patterns dict size
    if len(results["failure_patterns"]) > 20:
        top = sorted(results["failure_patterns"].items(), key=lambda x: -x[1])[:20]
        results["failure_patterns"] = dict(top)
    
    return results
