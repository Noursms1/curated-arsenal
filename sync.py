import os
import shutil
import glob
import re
import json

PTC_DIR = r"C:\users\nour\ptc-webapp"
ARSENAL_DIR = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(ARSENAL_DIR, "data", "scripts")
REVIEWS = os.path.join(ARSENAL_DIR, "data", "reviews")
TOOLS_JSON = os.path.join(ARSENAL_DIR, "data", "tools.json")

os.makedirs(SCRIPTS, exist_ok=True)
os.makedirs(REVIEWS, exist_ok=True)

print("[*] Moving generated tools...")
moved = 0
for gen in glob.glob(os.path.join(PTC_DIR, "gen_*.py")):
    fname = os.path.basename(gen)
    try:
        with open(gen, "r", encoding="utf-8") as f:
            content = f.read(1000)
        m = re.search(r'TOOL_NAME\s*=\s*["\']([^"\']+)["\']', content)
        name = m.group(1).lower() if m else "gen_" + fname.replace(".py", "")
    except:
        name = "gen_" + fname.replace(".py", "")
    name = re.sub(r'[^a-z0-9_]', '_', name.lower())
    dest = os.path.join(SCRIPTS, name + ".py")
    if os.path.exists(dest):
        print("  skip: " + name)
        continue
    shutil.copy2(gen, dest)
    print("  + " + fname + " -> " + name + ".py")
    moved += 1
print("[+] Moved: " + str(moved))

print("")
print("[*] Generating reviews...")
new_reviews = 0
for script in glob.glob(os.path.join(SCRIPTS, "*.py")):
    tid = os.path.splitext(os.path.basename(script))[0]
    rpath = os.path.join(REVIEWS, tid + ".md")
    if os.path.exists(rpath):
        continue
    try:
        with open(script, "r", encoding="utf-8") as f:
            code = f.read()
        dm = re.search(r'^[ \t]*"""(.*?)"""', code, re.DOTALL | re.MULTILINE)
        doc = dm.group(1).strip() if dm else ""
        cm = re.search(r'CATEGORY:\s*(.+)', doc)
        cat = cm.group(1).strip() if cm else "General"
        tm = re.search(r'TECHNIQUES:\s*(.+)', doc)
        tech = tm.group(1).strip() if tm else "N/A"
        fcount = len(re.findall(r'^def [a-z_]+\(', code, re.MULTILINE))
        has_self = "--self-test" in code or "self_test" in code
        has_json = '"findings"' in code and '"status"' in code
        
        review = "# Review: " + tid.replace("_", " ").title() + "\n\n"
        review += "## Overview\n"
        review += "Auto-generated review for `" + tid + "`.\n\n"
        review += "## Metadata\n"
        review += "- Category: " + cat + "\n"
        review += "- Techniques: " + tech + "\n"
        review += "- Functions: " + str(fcount) + "\n"
        review += "- Self-test: " + ("Yes" if has_self else "No") + "\n"
        review += "- Standardized JSON: " + ("Yes" if has_json else "No") + "\n\n"
        review += "## Description\n"
        review += doc[:300] if doc else "No description." + "\n\n"
        review += "## Usage\n```\npython " + tid + ".py <target>\npython " + tid + ".py --self-test\n```\n\n"
        review += "## Quality\n"
        review += "- [" + ("x" if fcount >= 3 else " ") + "] Multi-functional\n"
        review += "- [" + ("x" if has_self else " ") + "] Self-test\n"
        review += "- [" + ("x" if has_json else " ") + "] JSON output\n"
        
        with open(rpath, "w", encoding="utf-8") as f:
            f.write(review)
        print("  + review: " + tid + ".md")
        new_reviews += 1
    except Exception as e:
        print("  ! " + tid + ": " + str(e))

print("[+] New reviews: " + str(new_reviews))

print("")
print("[*] Rebuilding tools.json...")
tools = []
for script in glob.glob(os.path.join(SCRIPTS, "*.py")):
    tid = os.path.splitext(os.path.basename(script))[0]
    rpath = os.path.join(REVIEWS, tid + ".md")
    has_r = os.path.exists(rpath)
    cat = "General"
    tn = tid.lower()
    if "recon" in tn or "sub" in tn or "enum" in tn or "dns" in tn:
        cat = "Recon"
    elif "port" in tn or "tcp" in tn:
        cat = "Network"
    elif "web" in tn or "http" in tn or "cors" in tn or "cookie" in tn or "wp" in tn or "wordpress" in tn:
        cat = "Web"
    elif "jwt" in tn or "crypto" in tn or "hash" in tn:
        cat = "Crypto"
    
    tools.append({
        "id": tid,
        "name": " ".join([w.capitalize() for w in tid.split("_")]),
        "category": cat,
        "description": "Tool: " + tid,
        "language": "Python",
        "file_path": "data/scripts/" + os.path.basename(script),
        "review_path": "data/reviews/" + tid + ".md" if has_r else "",
        "usage": "python " + os.path.basename(script) + " [args]",
        "tags": ["Python"],
        "author": "NSMSO",
        "confidence_score": 90 if has_r else 50,
        "created_at": "2026-10-24",
        "metrics": {"Speed": 8, "Accuracy": 7, "Stealth": 8, "Coverage": 7, "Ease of Use": 8}
    })

with open(TOOLS_JSON, "w", encoding="utf-8") as f:
    json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)

print("[OK] tools.json: " + str(len(tools)) + " tools")

from collections import Counter
counts = Counter(t["category"] for t in tools)
for cat, n in counts.most_common():
    print("  " + cat + ": " + str(n))