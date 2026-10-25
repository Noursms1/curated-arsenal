# -*- coding: utf-8 -*-
"""Attack Chain Analyzer - Links findings into exploit chains."""

DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 1433: "MSSQL", 11211: "Memcached"}
DB_PORTS_HIGH = {9200: "Elasticsearch", 7001: "WebLogic"}


def analyze_attack_chains(scan_result):
    """Analyze a scan result and return exploit chain suggestions."""
    if not scan_result:
        return []
    
    chains = []
    techs = [t.lower() for t in scan_result.get("technologies", [])]
    headers = scan_result.get("security_headers", {}) or {}
    findings = scan_result.get("findings", []) or []
    ports = [p.get("port") for p in scan_result.get("open_ports", []) or []]
    status = scan_result.get("status") or scan_result.get("https_status")
    redirects = scan_result.get("redirects", []) or []
    
    # CHAIN 1: Rails + Missing CSP + Missing X-Frame-Options => XSS Session Hijack
    if "ruby on rails" in techs:
        issues = []
        if headers.get("Content-Security-Policy") == "MISSING":
            issues.append("Missing CSP")
        if headers.get("X-Frame-Options") == "MISSING":
            issues.append("Missing X-Frame-Options")
        
        if issues:
            chains.append({
                "name": "XSS Session Hijacking Risk",
                "severity": "High",
                "score": 8.0,
                "reasoning": "Rails app detected. " + " + ".join(issues) + " means XSS payloads won't be blocked by CSP, and session cookies can be stolen if HttpOnly is missing.",
                "test_suggestion": "Look for reflected XSS in search/error params. If successful, exfiltrate document.cookie to a webhook."
            })
    
    # CHAIN 2: Missing HSTS + HTTPS site => MITM Downgrade
    if headers.get("Strict-Transport-Security") == "MISSING":
        chains.append({
            "name": "MITM Downgrade Attack",
            "severity": "Medium",
            "score": 5.5,
            "reasoning": "Missing HSTS means first-time visitors can be downgraded to HTTP via MITM. Session cookies could leak.",
            "test_suggestion": "Check if http:// versions return content (not 301). Check if Set-Cookie has Secure flag."
        })
    
    # CHAIN 3: Open Database Ports => Data Breach
    exposed_dbs = [DB_PORTS[p] + " (port " + str(p) + ")" for p in ports if p in DB_PORTS]
    exposed_critical = [DB_PORTS_HIGH[p] + " (port " + str(p) + ")" for p in ports if p in DB_PORTS_HIGH]
    
    if exposed_dbs:
        chains.append({
            "name": "Database Exposure - Critical",
            "severity": "Critical",
            "score": 9.5,
            "reasoning": "Database ports directly exposed to internet: " + ", ".join(exposed_dbs) + ". Likely accessible from anywhere.",
            "test_suggestion": "Use nmap/redis-cli/mysql-client to connect without credentials. Default creds often work (root:root, admin:admin, no password)."
        })
    
    if exposed_critical:
        chains.append({
            "name": "Critical Service Exposure",
            "severity": "Critical",
            "score": 9.0,
            "reasoning": "Critical services exposed: " + ", ".join(exposed_critical) + ". Elasticsearch/WebLogic are known for unauth RCE.",
            "test_suggestion": "Check if Elasticsearch returns data at /_cat/indices (no auth). WebLogic CVE-2020-14882 RCE."
        })
    
    # CHAIN 4: WordPress + User Enumeration + Brute Force
    if "wordpress" in techs:
        chains.append({
            "name": "WordPress Attack Surface",
            "severity": "High",
            "score": 7.5,
            "reasoning": "WordPress detected. Common vectors: /wp-admin/ brute force, /xmlrpc.php amplification, /wp-json/wp/v2/users user enumeration.",
            "test_suggestion": "1) Enumerate users via /wp-json/wp/v2/users. 2) Check /xmlrpc.php for system.multicall. 3) Test /wp-admin/ for credentials in /wp-content/debug.log"
        })
    
    # CHAIN 5: Drupal CVE Risk
    if "drupal" in techs:
        chains.append({
            "name": "Drupal CVE Exploitation",
            "severity": "High",
            "score": 8.5,
            "reasoning": "Drupal detected. High-profile CVEs: Drupalgeddon2 (CVE-2018-7600), REST RCE (CVE-2019-6340), File Upload RCE (CVE-2020-13671).",
            "test_suggestion": "Check version: /CHANGELOG.txt. If 7.x or 8.x < 8.5.1, test Drupalgeddon2 with POST /user/register?element_parents=... or similar."
        })
    
    # CHAIN 6: 401/403 => Auth Bypass Opportunity
    if status in (401, 403):
        chains.append({
            "name": "Auth Bypass Opportunity",
            "severity": "Medium",
            "score": 6.5,
            "reasoning": "Endpoint returned " + str(status) + ". Bypass techniques may exist.",
            "test_suggestion": "Try: X-Original-URL: /admin, X-Rewrite-URL: /admin, /admin;, //admin, /admin/..;/, %2fadmin, /admin%00"
        })
    
    # CHAIN 7: Multiple Redirects => Open Redirect Risk
    if len(redirects) >= 2:
        chains.append({
            "name": "Open Redirect Risk",
            "severity": "Medium",
            "score": 5.0,
            "reasoning": "Multiple redirects detected. Check if user input controls the redirect destination.",
            "test_suggestion": "Look for ?url=, ?redirect=, ?next=, ?return=, ?continue= parameters. Try //evil.com or https://evil.com."
        })
    
    # CHAIN 8: Cloudflare + Rails => WAF Bypass worth testing
    if "cloudflare" in techs and "ruby on rails" in techs:
        chains.append({
            "name": "WAF Bypass Opportunity",
            "severity": "Low",
            "score": 3.5,
            "reasoning": "Cloudflare WAF is protecting a Rails app. Common bypasses exist for SQLi and XSS payloads.",
            "test_suggestion": "Try payload obfuscation: /*!50000SELECT*/, %00, unicode encoding, or JSON endpoints which sometimes bypass WAF."
        })
    
    # CHAIN 9: Sentry exposed => Error Leak
    if "sentry" in techs:
        chains.append({
            "name": "Sentry Error Leak",
            "severity": "Low",
            "score": 4.0,
            "reasoning": "Sentry SDK detected. If DSN is exposed in HTML, attacker could inject fake errors or extract stack traces.",
            "test_suggestion": "Search HTML for 'sentry.io/api/' or 'sentry_key'. If found, send malformed requests to trigger errors and see full stack traces."
        })
    
    # Sort by score descending
    chains.sort(key=lambda x: -x.get("score", 0))
    
    return chains
