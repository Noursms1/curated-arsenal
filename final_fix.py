import os
import re
import json
import glob
import shutil

ARSENAL = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(ARSENAL, "data", "scripts")
REVIEWS = os.path.join(ARSENAL, "data", "reviews")
TOOLS_JSON = os.path.join(ARSENAL, "data", "tools.json")

# ============================================================
# 1. Fix specific naming issues
# ============================================================
print("[*] Fixing specific naming issues...")

# Rename gen_gen_* -> wprecon.py
for script in glob.glob(os.path.join(SCRIPTS, "gen_gen_*.py")):
    new_path = os.path.join(SCRIPTS, "wprecon.py")
    if not os.path.exists(new_path):
        os.rename(script, new_path)
        print("  + Renamed " + os.path.basename(script) + " -> wprecon.py")
        # Rename review
        old_review = script.replace(SCRIPTS, REVIEWS).replace(".py", ".md")
        new_review = os.path.join(REVIEWS, "wprecon.md")
        if os.path.exists(old_review):
            os.rename(old_review, new_review)

# ============================================================
# 2. Force categorization for specific tools
# ============================================================
FORCE_CATEGORY = {
    "wallte": "Blockchain",
    "address_validator": "Blockchain",
    "advanced_scanner": "Web",
    "wprecon": "Web",
    "file_signature_verifier": "Malware",
    "snmp_community_tester": "Network",
    "cookie_security_analyzer": "Web",
    "open_redirect_checker": "Web",
    "bypass_403": "Web",
}

# ============================================================
# 3. Mark duplicates (family grouping)
# ============================================================
# base_name -> preferred version
DUPLICATE_FAMILIES = {
    "port_scanner": "port_scanner_v41_final",  # v41_final is the best
    "domain_scanner": "advanced_domain_scanner_v2",  # v2 is better
    "leak_monitor": "leak_monitor_v2",
    "subenum": "subenum1",  # subenum1 has more sources
    "cidr_subnet_calc": "cidr_subnet_calculator",
    "ipv6_port_scanner": "ipv6_port_scanner",
}

def categorize(tid, doc=""):
    if tid in FORCE_CATEGORY:
        return FORCE_CATEGORY[tid]
    tn = tid.lower()
    combined = tn + " " + doc.lower()
    
    if any(k in tn for k in ["wallet", "eth_", "erc20", "evm_", "token_", "contract", "reentrancy", "gas_price"]):
        return "Blockchain"
    if any(k in tn for k in ["jwt", "hash", "crypto", "decoder", "base64", "password_strength"]):
        return "Crypto"
    if any(k in tn for k in ["web", "http_", "cors", "cookie", "wp_", "wprecon", "wordpress", "open_redirect", "bypass_403", "gql"]):
        return "Web"
    if any(k in tn for k in ["recon", "sub_", "subdomain", "subenum", "dns_", "crtsh", "domain_scan", "cidr"]):
        return "Recon"
    if any(k in tn for k in ["port_", "tcp_", "ipv6_", "snmp", "network", "scan_port"]):
        return "Network"
    if "malware" in tn or "signature" in tn:
        return "Malware"
    if any(k in tn for k in ["leak", "ip_geo", "geolocation"]):
        return "OSINT"
    return "General"

# ============================================================
# 4. Rebuild tools.json with proper naming + categorization
# ============================================================
all_scripts = glob.glob(os.path.join(SCRIPTS, "*.py"))
tools = []

for script in sorted(all_scripts):
    tid = os.path.splitext(os.path.basename(script))[0]
    
    # Skip if file is a duplicate that we want to hide
    # (Only hide exact filename duplicates like domain_scanner_v2 that's literally same as domain_scanner)
    base_id = re.sub(r'_v\d+.*$', '', tid)
    if base_id != tid and base_id in [t.lower() for t in os.listdir(SCRIPTS) if t.endswith('.py') and t.replace('.py', '').lower() == base_id]:
        # This is a versioned duplicate
        # Mark it but don't skip
        pass
    
    try:
        with open(script, "r", encoding="utf-8") as f:
            code = f.read()
        dm = re.search(r'^[ \t]*"""(.*?)"""', code, re.DOTALL | re.MULTILINE)
        doc = dm.group(1).strip() if dm else ""
    except:
        doc = ""
        code = ""
    
    cat = categorize(tid, doc)
    review_path = os.path.join(REVIEWS, tid + ".md")
    has_review = os.path.exists(review_path)
    
    confidence = 90 if has_review else 60
    if "--self-test" in code:
        confidence = min(confidence + 5, 99)
    
    # Better display name
    special_names = {
        "wprecon": "WPRecon",
        "wallte": "Wallte (ERC-20 Allowance)",
        "websecscanner": "WebSecScanner",
        "gql_assessor": "GraphQL Assessor",
        "jwt_tester": "JWT Tester",
    }
    
    display_name = special_names.get(tid) or " ".join([w.capitalize() for w in tid.split("_")])
    
    # Check if this is a duplicate
    duplicate_of = None
    for base, preferred in DUPLICATE_FAMILIES.items():
        if tid != preferred and tid.startswith(base) and tid != base:
            duplicate_of = preferred
            break
    
    # Clean description
    clean_desc = doc.split("\n")[0][:180] if doc else "Security tool: " + display_name
    # If doc is just "Security tool: X" repeat, clean it up
    if "Security tool:" in clean_desc:
        clean_desc = "Security tool for " + cat.lower() + " assessments"
    
    tool = {
        "id": tid,
        "name": display_name,
        "category": cat,
        "description": clean_desc,
        "language": "Python",
        "file_path": "data/scripts/" + os.path.basename(script),
        "review_path": "data/reviews/" + tid + ".md" if has_review else "",
        "usage": "python " + os.path.basename(script) + " [args]",
        "tags": [cat, "Python"],
        "author": "NSMSO",
        "confidence_score": confidence,
        "created_at": "2026-10-24",
        "duplicate_of": duplicate_of,
        "metrics": {"Speed": 8, "Accuracy": 7, "Stealth": 8, "Coverage": 7, "Ease of Use": 8}
    }
    tools.append(tool)

# Sort: preferred versions first (no duplicate_of), then category, then name
tools.sort(key=lambda t: (t["duplicate_of"] is not None, t["category"], t["name"]))

with open(TOOLS_JSON, "w", encoding="utf-8") as f:
    json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)

print("[OK] tools.json: " + str(len(tools)) + " tools")

from collections import Counter
counts = Counter(t["category"] for t in tools)
print("")
print("Categories:")
for cat, n in counts.most_common():
    print("  " + cat + ": " + str(n))

dupes = sum(1 for t in tools if t.get("duplicate_of"))
print("")
print("Duplicates marked: " + str(dupes))

# ============================================================
# 5. Update index.html to hide duplicates by default
# ============================================================
INDEX = os.path.join(ARSENAL, "templates", "index.html")
with open(INDEX, "r", encoding="utf-8") as f:
    html = f.read()

# Add data-duplicate attribute to cards
old_card = 'class="card" data-name="{{ tool.name | lower }}" data-cat="{{ tool.category | lower }}" data-tags="{{ tool.tags | join(\' \') | lower }}"'
new_card = 'class="card{% if tool.duplicate_of %} duplicate{% endif %}" data-name="{{ tool.name | lower }}" data-cat="{{ tool.category | lower }}" data-tags="{{ tool.tags | join(\' \') | lower }}" data-dup="{{ tool.duplicate_of or \'\' }}"'

if old_card in html:
    html = html.replace(old_card, new_card)
    print("[+] Added duplicate attribute to cards")

# Add CSS for duplicates
CSS = os.path.join(ARSENAL, "static", "css", "style.css")
with open(CSS, "r", encoding="utf-8") as f:
    css = f.read()

if ".card.duplicate" not in css:
    css += """

/* Duplicate tools - hidden by default */
.card.duplicate {
    display: none !important;
}

/* Show duplicates toggle */
.show-dupes-btn {
    background: var(--card-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 16px;
    border-radius: 20px;
    cursor: pointer;
    margin-left: 10px;
    font-size: 12px;
}
.show-dupes-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
}
"""
    with open(CSS, "w", encoding="utf-8") as f:
        f.write(css)
    print("[+] Added CSS for duplicate hiding")

with open(INDEX, "w", encoding="utf-8") as f:
    f.write(html)

print("")
print("[DONE] All fixes applied")
print("Restart Flask server and Ctrl+Shift+R")