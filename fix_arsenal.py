import os
import re
import json
import glob

ARSENAL = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(ARSENAL, "data", "scripts")
REVIEWS = os.path.join(ARSENAL, "data", "reviews")
TOOLS_JSON = os.path.join(ARSENAL, "data", "tools.json")

# ============================================================
# 1. Rename badly-named files (gen_gen_XXXX -> actual TOOL_NAME)
# ============================================================
print("[*] Fixing badly-named files...")
renamed = 0
for script in glob.glob(os.path.join(SCRIPTS, "gen_gen_*.py")):
    try:
        with open(script, "r", encoding="utf-8") as f:
            content = f.read(2000)
        m = re.search(r'TOOL_NAME\s*=\s*["\']([^"\']+)["\']', content)
        if m:
            new_name = re.sub(r'[^a-z0-9_]', '_', m.group(1).lower())
            new_path = os.path.join(SCRIPTS, new_name + ".py")
            if not os.path.exists(new_path):
                os.rename(script, new_path)
                print("  + " + os.path.basename(script) + " -> " + new_name + ".py")
                renamed += 1
                # Rename review too
                old_review = script.replace(".py", "").replace(SCRIPTS, REVIEWS) + ".md"
                old_review_name = os.path.basename(script).replace(".py", ".md")
                old_review_path = os.path.join(REVIEWS, old_review_name)
                new_review_path = os.path.join(REVIEWS, new_name + ".md")
                if os.path.exists(old_review_path):
                    os.rename(old_review_path, new_review_path)
    except Exception as e:
        print("  ! " + os.path.basename(script) + ": " + str(e))
print("[+] Renamed: " + str(renamed))

# ============================================================
# 2. Smart categorization
# ============================================================
print("")
print("[*] Categorizing tools...")

def categorize(tid, doc=""):
    tn = tid.lower()
    combined = tn + " " + doc.lower()
    
    # Crypto/Blockchain
    if any(k in tn for k in ["wallet", "eth_", "erc20", "evm_", "token_", "contract", "reentrancy", "gas_price"]):
        return "Blockchain"
    
    # Crypto
    if any(k in tn for k in ["jwt", "hash", "crypto", "decoder", "base64", "password_strength"]):
        return "Crypto"
    
    # Web
    if any(k in tn for k in ["web", "http_", "cors", "cookie", "wp_", "wprecon", "wordpress", "open_redirect", "bypass_403", "gql"]):
        return "Web"
    
    # Recon
    if any(k in tn for k in ["recon", "sub_", "subdomain", "subenum", "dns_", "crtsh", "domain_scan", "cidr"]):
        return "Recon"
    
    # Network
    if any(k in tn for k in ["port_", "tcp_", "ipv6_", "snmp", "network", "scan_port"]):
        return "Network"
    
    # Malware
    if "malware" in tn or "signature" in tn:
        return "Malware"
    
    # OSINT
    if any(k in tn for k in ["leak", "ip_geo", "geolocation"]):
        return "OSINT"
    
    return "General"

# ============================================================
# 3. Rebuild tools.json with proper metadata
# ============================================================
all_scripts = glob.glob(os.path.join(SCRIPTS, "*.py"))
tools = []
seen_base_names = {}

for script in sorted(all_scripts):
    tid = os.path.splitext(os.path.basename(script))[0]
    
    # Read docstring
    try:
        with open(script, "r", encoding="utf-8") as f:
            code = f.read()
        dm = re.search(r'^[ \t]*"""(.*?)"""', code, re.DOTALL | re.MULTILINE)
        doc = dm.group(1).strip() if dm else ""
    except:
        doc = ""
    
    cat = categorize(tid, doc)
    review_path = os.path.join(REVIEWS, tid + ".md")
    has_review = os.path.exists(review_path)
    
    # Confidence: 90 if has review, 60 if not, +5 if has self-test
    confidence = 90 if has_review else 60
    if "--self-test" in (code if 'code' in dir() else ""):
        confidence = min(confidence + 5, 99)
    
    # Display name - proper title
    display_name = " ".join([w.capitalize() for w in tid.replace("-", "_").split("_")])
    
    # Mark as duplicate if base name already seen (e.g., port_scanner vs port_scanner_v4)
    base = re.sub(r'_v\d+.*$', '', tid)
    base = re.sub(r'_final$', '', base)
    base = re.sub(r'_\d+$', '', base)
    is_duplicate = base in seen_base_names and base != tid
    seen_base_names[base] = tid
    
    tool = {
        "id": tid,
        "name": display_name,
        "category": cat,
        "description": doc[:200] if doc else "Security tool: " + display_name,
        "language": "Python",
        "file_path": "data/scripts/" + os.path.basename(script),
        "review_path": "data/reviews/" + tid + ".md" if has_review else "",
        "usage": "python " + os.path.basename(script) + " [args]",
        "tags": [cat, "Python"],
        "author": "NSMSO",
        "confidence_score": confidence,
        "created_at": "2026-10-24",
        "metrics": {"Speed": 8, "Accuracy": 7, "Stealth": 8, "Coverage": 7, "Ease of Use": 8}
    }
    tools.append(tool)

# Sort by category then name
tools.sort(key=lambda t: (t["category"], t["name"]))

with open(TOOLS_JSON, "w", encoding="utf-8") as f:
    json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)

print("[OK] tools.json: " + str(len(tools)) + " tools")

from collections import Counter
counts = Counter(t["category"] for t in tools)
print("")
print("Categories:")
for cat, n in counts.most_common():
    print("  " + cat + ": " + str(n))

# ============================================================
# 4. Fix index.html confidence display
# ============================================================
print("")
print("[*] Fixing index.html confidence display...")

INDEX = os.path.join(ARSENAL, "templates", "index.html")
with open(INDEX, "r", encoding="utf-8") as f:
    html = f.read()

# Find the confidence span and fix it
old_span = '<span class="confidence">⭐ {{ tool.confidence }}%</span>'
new_span = '<span class="confidence">⭐ {{ tool.confidence_score }}%</span>'

if old_span in html:
    html = html.replace(old_span, new_span)
    print("  [+] Fixed confidence field")
else:
    # Try alternative
    pattern = r'<span class="confidence">[^<]*</span>'
    if re.search(pattern, html):
        html = re.sub(pattern, new_span, html, count=1)
        print("  [+] Fixed confidence (regex)")
    else:
        print("  [!] Confidence span not found")

with open(INDEX, "w", encoding="utf-8") as f:
    f.write(html)

print("")
print("[DONE] All fixes applied")
print("Restart Flask server and Ctrl+Shift+R in browser")