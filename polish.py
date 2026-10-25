import os
import re
import json
import glob

ARSENAL = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(ARSENAL, "data", "scripts")
TOOLS_JSON = os.path.join(ARSENAL, "data", "tools.json")

def extract_clean_description(code, doc, cat, tid):
    """Extract a clean, meaningful description."""
    # Remove "===" separator lines and "PCT" prefix
    lines = [l.strip() for l in doc.split("\n") if l.strip()]
    lines = [l for l in lines if not l.startswith("===") and not l.startswith("---")]
    
    # Remove "Security tool for X assessments" generic text
    if not lines or "Security tool for" in lines[0]:
        # Try to find anything in docstring
        lines = [l for l in lines if "Security tool for" not in l]
    
    if not lines:
        return "Security tool: " + tid.replace("_", " ").title()
    
    first = lines[0]
    # Remove "PCT" prefix
    first = re.sub(r'^PCT\s+', '', first)
    # Remove "CATEGORY:" prefix  
    first = re.sub(r'^CATEGORY:\s*', '', first)
    # Cut at first period if long
    if len(first) > 120:
        first = first[:117] + "..."
    
    # If still generic, add category context
    if len(first) < 15:
        return first + " (" + cat + ")"
    
    return first

# Duplicate families: base -> preferred version (only show preferred)
FAMILIES = {
    "port_scanner": "port_scanner_v41_final",
    "leak_monitor": "leak_monitor_v2",  
    "subenum": "subenum1",
    "cidr_subnet_calc": "cidr_subnet_calculator",
    "domain_scanner_v2": "advanced_domain_scanner_v2",
    "http_security_header_scanner": "websecscanner",
    "http_methods_tester": "websecscanner",
}

FORCE_CATEGORY = {
    "wallte": "Blockchain",
    "address_validator": "Blockchain",
    "advanced_scanner": "Web",
    "wprecon": "Web",
}

def categorize(tid):
    if tid in FORCE_CATEGORY:
        return FORCE_CATEGORY[tid]
    tn = tid.lower()
    if any(k in tn for k in ["wallet", "eth_", "erc20", "evm_", "token_", "contract", "reentrancy", "gas_price"]):
        return "Blockchain"
    if any(k in tn for k in ["jwt", "hash", "crypto", "decoder", "base64", "password_strength"]):
        return "Crypto"
    if any(k in tn for k in ["web", "http_", "cors", "cookie", "wp_", "wprecon", "wordpress", "open_redirect", "bypass_403", "gql"]):
        return "Web"
    if any(k in tn for k in ["recon", "sub_", "subdomain", "subenum", "dns_", "crtsh", "domain_scan", "cidr"]):
        return "Recon"
    if any(k in tn for k in ["port_", "tcp_", "ipv6_", "snmp", "network"]):
        return "Network"
    if "malware" in tn or "signature" in tn:
        return "Malware"
    if any(k in tn for k in ["leak", "ip_geo", "geolocation"]):
        return "OSINT"
    return "General"

SPECIAL_NAMES = {
    "wprecon": "WPRecon",
    "wallte": "Wallte (ERC-20)",
    "websecscanner": "WebSecScanner",
    "gql_assessor": "GraphQL Assessor",
    "jwt_tester": "JWT Tester",
    "port_scanner_v41_final": "Port Scanner (Final)",
    "leak_monitor_v2": "Leak Monitor V2",
    "subenum1": "Subdomain Enumerator",
}

print("[*] Building clean tools.json...")
tools = []
seen = set()

for script in sorted(glob.glob(os.path.join(SCRIPTS, "*.py"))):
    tid = os.path.splitext(os.path.basename(script))[0]
    
    # Skip if it's in FAMILIES values (those are hidden bases)
    if tid in FAMILIES:
        print("  [hide] " + tid + " (has newer version)")
        continue
    
    # Skip exact duplicates
    if tid in seen:
        continue
    seen.add(tid)
    
    try:
        with open(script, "r", encoding="utf-8") as f:
            code = f.read()
        dm = re.search(r'^[ \t]*"""(.*?)"""', code, re.DOTALL | re.MULTILINE)
        doc = dm.group(1).strip() if dm else ""
    except:
        doc = ""
        code = ""
    
    cat = categorize(tid)
    desc = extract_clean_description(code, doc, cat, tid)
    confidence = 95 if "--self-test" in code else 88
    display = SPECIAL_NAMES.get(tid) or " ".join([w.capitalize() for w in tid.split("_")])
    
    tools.append({
        "id": tid,
        "name": display,
        "category": cat,
        "description": desc,
        "language": "Python",
        "file_path": "data/scripts/" + os.path.basename(script),
        "review_path": "data/reviews/" + tid + ".md",
        "usage": "python " + os.path.basename(script) + " [args]",
        "tags": [cat, "Python"],
        "author": "NSMSO",
        "confidence_score": confidence,
        "created_at": "2026-10-24",
        "metrics": {"Speed": 8, "Accuracy": 7, "Stealth": 8, "Coverage": 7, "Ease of Use": 8}
    })

tools.sort(key=lambda t: (t["category"], t["name"]))

with open(TOOLS_JSON, "w", encoding="utf-8") as f:
    json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)

from collections import Counter
counts = Counter(t["category"] for t in tools)
print("")
print("[OK] " + str(len(tools)) + " tools after polish")
print("Categories:")
for cat, n in counts.most_common():
    print("  " + cat + ": " + str(n))