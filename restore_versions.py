import os, re, json, glob

ARSENAL = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(ARSENAL, "data", "scripts")
TOOLS_JSON = os.path.join(ARSENAL, "data", "tools.json")

# Version families - group related tools together
# Format: base_id -> (family_name, sort_order)
VERSION_FAMILIES = {
    "port_scanner": ("Port Scanner", 1),
    "port_scanner_v4": ("Port Scanner", 4),
    "port_scanner_v41_final": ("Port Scanner", 41),
    "domain_scanner": ("Domain Scanner", 1),
    "domain_scanner_v2": ("Domain Scanner", 2),
    "advanced_domain_scanner_v2": ("Domain Scanner", 99),
    "subenum": ("Subdomain Enumerator", 1),
    "subenum1": ("Subdomain Enumerator", 2),
    "subdomain_enum": ("Subdomain Enumerator", 3),
    "leak_monitor": ("Leak Monitor", 1),
    "leak_monitor_v2": ("Leak Monitor", 2),
    "cidr_subnet_calc": ("CIDR Calculator", 1),
    "cidr_subnet_calculator": ("CIDR Calculator", 2),
    "http_methods_tester": ("HTTP Methods", 1),
    "http_security_header_scanner": ("HTTP Headers", 1),
    "websecscanner": ("HTTP Headers", 2),
}

# Your manually-developed tools (mark as Custom)
MANUAL_TOOLS = {
    "port_scanner_v41_final",
    "advanced_domain_scanner_v2",
    "subenum1",
    "leak_monitor_v2",
    "websecscanner",
    "wprecon",
    "wallte",
    "gql_assessor",
    "jwt_tester",
    "advanced_scanner",
}

FORCE_CATEGORY = {
    "wallte": "Blockchain", "address_validator": "Blockchain",
    "advanced_scanner": "Web", "wprecon": "Web",
}

DESCRIPTIONS = {
    "eth_address_validator": "Validates Ethereum/EVM wallet addresses (EIP-55 checksum, hex format)",
    "password_strength_analyzer": "Analyzes password strength: entropy, length, patterns",
    "ipv6_port_scanner": "Scans IPv6 addresses for open TCP ports",
    "ipv6_http_scanner": "HTTP header check for IPv6 targets",
    "snmp_community_tester": "Tests SNMP devices against common community strings",
    "is_contract_checker": "Checks if an EVM address is a smart contract or EOA",
    "reentrancy_scanner": "Detects reentrancy vulnerabilities in Solidity contracts",
    "token_approval_checker": "Checks ERC-20 token approvals and allowances",
    "wallet_validator": "Validates blockchain wallet addresses across EVM chains",
    "dns_resolver": "Resolves A, MX, NS, TXT records for a domain",
    "crtsh_subdomain_enumerator": "Enumerates subdomains via crt.sh logs",
    "cidr_subnet_calculator": "Calculates CIDR subnet: network, broadcast, hosts",
    "ip_geolocation_lookup": "Retrieves geolocation data (country, city, ASN) for an IP",
    "base64_payload_extractor": "Extracts and decodes Base64 payloads from input",
    "file_signature_verifier": "Identifies file types by magic bytes signature",
    "graphql_assessor": "Discovers GraphQL endpoints, introspection, IDOR tests",
    "advanced_scanner": "WordPress + CORS + security headers + port scan",
    "cookie_security_analyzer": "Analyzes cookie flags: HttpOnly, Secure, SameSite",
    "open_redirect_checker": "Tests parameters for open redirect vulnerabilities",
    "jwt_tester": "Detects JWT weaknesses: none algo, weak secrets, confusion",
    "wprecon": "WordPress recon: version, plugins, CVE mapping, user enum",
    "websecscanner": "CORS + HTTP methods + security headers scanner",
    "wallte": "Reads ERC-20 allowance via eth_call",
    "port_scanner_v41_final": "Port Scanner v4.1 — WAF-aware, HackerOne-safe, CVEs mapped",
    "port_scanner_v4": "Port Scanner v4.0 — base version",
    "port_scanner": "Port Scanner v1 — original",
    "advanced_domain_scanner_v2": "Domain Scanner v2.0 — full recon: ports + SSL + tech + robots",
    "domain_scanner_v2": "Domain Scanner v2 — basic",
    "domain_scanner": "Domain Scanner v1 — original",
    "subenum1": "Subdomain Enumerator v2 — 5 sources (crt.sh, OTX, URLScan, Wayback, HackerTarget)",
    "subenum": "Subdomain Enumerator v1 — 3 sources",
    "subdomain_enum": "Subdomain Enum — crt.sh only",
    "leak_monitor_v2": "Leak Monitor v2 — HIBP + LeakCheck + local",
    "leak_monitor": "Leak Monitor v1 — original",
    "cidr_subnet_calculator": "CIDR Calculator — full info",
    "cidr_subnet_calc": "CIDR Calculator — basic",
}

def categorize(tid):
    if tid in FORCE_CATEGORY:
        return FORCE_CATEGORY[tid]
    tn = tid.lower()
    if any(k in tn for k in ["wallet","eth_","erc20","evm_","token_","contract","reentrancy","gas_price"]): return "Blockchain"
    if any(k in tn for k in ["jwt","hash","crypto","decoder","base64","password_strength"]): return "Crypto"
    if any(k in tn for k in ["web","http_","cors","cookie","wp_","wprecon","wordpress","open_redirect","bypass_403","gql","advanced_scanner"]): return "Web"
    if any(k in tn for k in ["recon","sub_","subdomain","subenum","dns_","crtsh","domain_scan","cidr"]): return "Recon"
    if any(k in tn for k in ["port_","tcp_","ipv6_","snmp","network"]): return "Network"
    if "malware" in tn or "signature" in tn: return "Malware"
    if any(k in tn for k in ["leak","ip_geo","geolocation"]): return "OSINT"
    return "General"

print("[*] Building tools.json with version families (NO hiding!)...")
tools = []

for script in sorted(glob.glob(os.path.join(SCRIPTS, "*.py"))):
    tid = os.path.splitext(os.path.basename(script))[0]
    
    try:
        with open(script, "r", encoding="utf-8") as f:
            code = f.read()
    except:
        code = ""
    
    cat = categorize(tid)
    display = " ".join([w.capitalize() for w in tid.split("_")])
    if tid == "wprecon": display = "WPRecon"
    elif tid == "wallte": display = "Wallte (ERC-20)"
    elif tid == "websecscanner": display = "WebSecScanner"
    elif tid == "gql_assessor": display = "GraphQL Assessor"
    
    # Description
    if tid in DESCRIPTIONS:
        desc = DESCRIPTIONS[tid]
    else:
        dm = re.search(r'^[ \t]*"""(.*?)"""', code, re.DOTALL | re.MULTILINE)
        doc = dm.group(1).strip() if dm else ""
        lines = [l.strip() for l in doc.split("\n") if l.strip() and not l.strip().startswith("===")]
        desc = lines[0][:160] if lines else tid.replace("_", " ").title()
    
    # Version family info
    family_name, version_order = VERSION_FAMILIES.get(tid, (None, 0))
    is_manual = tid in MANUAL_TOOLS
    
    tools.append({
        "id": tid,
        "name": display,
        "category": cat,
        "description": desc,
        "language": "Python",
        "file_path": "data/scripts/" + os.path.basename(script),
        "review_path": "data/reviews/" + tid + ".md",
        "usage": "python " + os.path.basename(script) + " [args]",
        "tags": [cat, "Python"] + (["Custom"] if is_manual else []),
        "author": "NSMSO",
        "confidence_score": 95 if is_manual or "--self-test" in code else 88,
        "created_at": "2026-10-24",
        "family": family_name,
        "version_order": version_order,
        "is_manual": is_manual,
        "metrics": {"Speed": 8, "Accuracy": 7, "Stealth": 8, "Coverage": 7, "Ease of Use": 8}
    })

tools.sort(key=lambda t: (t["category"], t["family"] or t["name"], -t["version_order"]))

with open(TOOLS_JSON, "w", encoding="utf-8") as f:
    json.dump({"tools": tools}, f, indent=2, ensure_ascii=False)

print("[OK] " + str(len(tools)) + " tools (ALL kept, no hiding)")
print("")
print("Manual/Custom tools:")
for t in tools:
    if t["is_manual"]:
        print("  ★ " + t["name"] + " (" + t["category"] + ")")
print("")
print("Version families:")
families = {}
for t in tools:
    if t["family"]:
        families.setdefault(t["family"], []).append(t)
for fam, members in families.items():
    print("  " + fam + ": " + str(len(members)) + " versions")