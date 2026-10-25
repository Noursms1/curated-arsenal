USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
# -*- coding: utf-8 -*-
"""
=============================================================================
 PCT Advanced Domain Scanner v2.0
-----------------------------------------------------------------------------
 أداة شاملة لفحص النطاقات باستخدام مكتبات Python الأساسية فقط.
 
 الميزات:
 - DNS Lookup (A, MX, NS, TXT)
 - Port Scanning (منافذ شهيرة)
 - SSL Certificate Inspection
 - HTTP/HTTPS Status
 - Security Headers Check
 - Technology Detection
 - Redirect Chain
 - Robots.txt Reader
 - WHOIS Lookup (Basic)
 - Risk Assessment
=============================================================================
"""

import sys
import socket
import json
import ssl
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# Configuration
# ============================================================================
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

TECH_SIGNATURES = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"/wp-json/"],
    "Drupal": [r"/sites/default/files/", r"drupalSettings", r"Drupal[.]behaviors", r"/core/misc/drupal[.]js", r"/misc/drupal[.]js", r"Generator.{0,30}Drupal"],
    "Joomla": [r"/components/com_", r"/media/system/js/"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom[.]production", r"_reactRootContainer", r"data-reactroot", r"react[.]production[.]min"],
    "Next.js": [r"/_next/static/", r"__NEXT_DATA__"],
    "Nuxt.js": [r"__NUXT__", r"/_nuxt/"],
    "Vue.js": [r"vue(?:[.]min)?[.]js", r"__vue__", r"data-v-[a-f0-9]{8}"],
    "Angular": [r"ng-version=", r"ng-app=", r"angular(?:[.]min)?[.]js"],
    "Svelte": [r"__svelte", r"svelte-"],
    "Astro": [r"data-astro-", r"/_astro/"],
    "Ruby on Rails": [r"csrf-param", r"csrf-token", r"/assets/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+-[a-zA-Z0-9]{6,}[.](?:css|js)", r"action_dispatch", r"X-Request-Id"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express.js": [r"X-Powered-By:\s*Express"],
    "PHP": [r"X-Powered-By:\s*PHP", r"PHPSESSID"],
    "ASP.NET": [r"__VIEWSTATE", r"ASP[.]NET"],
    "jQuery": [r"jquery(?:[-.]\d+(?:[.]\d+)+)?(?:[.]min)?[.]js", r"jQuery v?[0-9]"],
    "Bootstrap": [r"bootstrap(?:[.]min)?[.](?:css|js)"],
    "Tailwind CSS": [r"tailwind"],
    "Turbo (Hotwire)": [r"data-turbo-track", r"turbo-frame", r"@hotwired/turbo"],
    "Stimulus": [r"data-controller=", r"data-action="],
    "GitHub": [r"github[.]com/", r"githubusercontent[.]com", r"github-actions", r"data-hydro-click"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache/"],
    "Cloudflare": [r"cf-ray", r"cf-cache-status"],
    "Shopify": [r"cdn[.]shopify", r"X-ShopId"],
    "Google Analytics": [r"google-analytics[.]com", r"gtag\(", r"googletagmanager[.]com"],
    "Facebook Pixel": [r"connect[.]facebook[.]net", r"fbq\("],
    "Sentry": [r"sentry[.]io", r"sentry-release-id", r"sentry-trace"],
    "Datadog RUM": [r"datadoghq-browser-agent", r"datadog-rum"],
}


# ============================================================================
# Helper Functions
# ============================================================================
def clean_domain(domain):
    """تنظيف اسم النطاق من بروتوكولات ومسارات"""
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "www."):
        domain = domain.replace(prefix, "")
    return domain.split("/")[0].split(":")[0]


def resolve_dns(domain):
    """تحويل النطاق لـ IP"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def scan_port(host, port, timeout=1.0):
    """فحص منفذ واحد"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(host, ports=None, max_workers=20):
    """فحص المنافذ بالتوازي (Concurrent)"""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append({
                    "port": result,
                    "service": COMMON_PORTS.get(result, "Unknown")
                })

    return sorted(open_ports, key=lambda x: x["port"])


def get_ssl_info(domain, port=443, timeout=5):
    """فحص شهادة SSL"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # استخراج تاريخ الانتهاء
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                
                days_left = None
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now()).days
                except Exception:
                    pass
                
                # استخراج المُصدر
                issuer = dict(x[0] for x in cert.get("issuer", []))
                
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName", ""),
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "issuer_cn": issuer.get("commonName", ""),
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "days_left": days_left,
                    "expired": days_left is not None and days_left < 0,
                    "expiring_soon": days_left is not None and 0 <= days_left < 30,
                    "serial": cert.get("serialNumber", ""),
                }
    except ssl.SSLError as e:
        return {"error": f"SSL Error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


def fetch_url(url, timeout=5, follow_redirects=True):
    """Fetch URL with redirect tracking."""
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    
    # Custom handler to track redirects
    class RedirectTracker(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            self.redirects = []
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            self.redirects.append({"status": code, "to": newurl})
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    
    tracker = RedirectTracker()
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_303 = http_error_307 = http_error_302
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect()
        )
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            tracker
        )
    
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {
                "status": resp.getcode(),
                "headers": dict(resp.headers),
                "content": resp.read(500000).decode("utf-8", errors="replace"),
                "final_url": resp.geturl(),
                "redirects": tracker.redirects,
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "content": "",
            "final_url": url,
            "redirects": tracker.redirects,
        }
    except Exception as e:
        return {"error": str(e), "redirects": tracker.redirects}



def check_https(domain, timeout=5):
    """فحص HTTPS"""
    return fetch_url(f"https://{domain}", timeout)


def check_http(domain, timeout=5):
    """فحص HTTP (لو HTTPS فشل)"""
    return fetch_url(f"http://{domain}", timeout)


def check_security_headers(headers):
    """فحص الترويسات الأمنية"""
    result = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for h in SECURITY_HEADERS:
        if h.lower() in headers_lower:
            result[h] = headers_lower[h.lower()]
        else:
            result[h] = "MISSING"
    
    return result


def detect_technologies(content, headers, debug=False):
    """Detect technologies by scanning FULL content + headers."""
    found = set()
    matches_log = []
    
    if not content:
        content = ""
    
    # Scan FULL content (up to 500KB)
    scan_content = content[:500000]
    
    header_str = ""
    try:
        if hasattr(headers, "items"):
            header_str = " ".join([str(k) + ": " + str(v) for k, v in headers.items()])
        else:
            header_str = str(headers)
    except Exception:
        header_str = str(headers)

    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            try:
                # Check headers first (usually more reliable)
                h_match = re.search(pattern, header_str, re.IGNORECASE)
                if h_match:
                    found.add(tech)
                    if debug:
                        matches_log.append("[HEADER] " + tech + ": " + pattern)
                    break
                
                # Then check body
                b_match = re.search(pattern, scan_content, re.IGNORECASE)
                if b_match:
                    found.add(tech)
                    if debug:
                        matches_log.append("[BODY@" + str(b_match.start()) + "] " + tech + ": " + pattern)
                    break
            except Exception:
                continue

    if debug:
        import sys
        for m in matches_log:
            print("[DEBUG] " + m, file=sys.stderr)

    return sorted(list(found))



def check_robots_txt(domain, timeout=5):
    """فحص robots.txt"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            f"https://{domain}/robots.txt",
            headers={"User-Agent": "PCT-Scanner/2.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            content = response.read(5000).decode("utf-8", errors="ignore")
            return {
                "exists": True,
                "content_preview": content[:1000],
                "disallow_count": content.lower().count("disallow:"),
            }
    except Exception:
        return {"exists": False}


def calculate_risk_score(scan_result):
    """حساب درجة المخاطر"""
    score = 0
    issues = []
    
    # 1. HTTPS
    if scan_result.get("https_status") != 200:
        score += 30
        issues.append("HTTPS لا يعمل بشكل صحيح")
    
    # 2. SSL
    ssl_info = scan_result.get("ssl", {})
    if ssl_info.get("expired"):
        score += 40
        issues.append("شهادة SSL منتهية")
    elif ssl_info.get("expiring_soon"):
        score += 15
        issues.append("شهادة SSL قاربت على الانتهاء")
    
    # 3. Security Headers
    headers = scan_result.get("security_headers", {})
    missing = sum(1 for v in headers.values() if v == "MISSING")
    if missing >= 5:
        score += 25
        issues.append(f"{missing} ترويسة أمنية مفقودة")
    elif missing >= 3:
        score += 15
        issues.append(f"{missing} ترويسة أمنية مفقودة")
    
    # 4. منافذ خطرة
    dangerous = {21, 23, 445, 3306, 3389, 5432, 6379, 27017}
    open_dangerous = [p for p in scan_result.get("open_ports", []) if p["port"] in dangerous]
    if open_dangerous:
        score += len(open_dangerous) * 10
        issues.append(f"{len(open_dangerous)} منفذ خطير مفتوح")
    
    # 5. تصنيف
    if score >= 70:
        level = "🔴 خطير"
    elif score >= 40:
        level = "🟠 متوسط الخطورة"
    elif score >= 15:
        level = "🟡 منخفض"
    else:
        level = "🟢 آمن"
    
    return {
        "score": min(score, 100),
        "level": level,
        "issues": issues
    }


# ============================================================================
# Main Scanner
# ============================================================================
def scan_domain(domain, scan_ports_flag=True, check_ssl_flag=True):
    """الفحص الشامل للنطاق"""
    domain = clean_domain(domain)
    
    result = {
        "domain": domain,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "ip_address": None,
        "http_status": None,
        "https_status": None,
        "server": None,
        "security_headers": {},
        "technologies": [],
        "open_ports": [],
        "ssl": {},
        "redirects": [],
        "robots": {},
        "risk": {},
        "error": None,
    }

    # 1. DNS
    ip = resolve_dns(domain)
    if not ip:
        result["error"] = "تعذر تحويل النطاق إلى IP (DNS resolution failed)"
        return result
    result["ip_address"] = ip

    # 2. HTTPS
    https_result = check_https(domain)
    if "error" not in https_result:
        result["https_status"] = https_result.get("status")
        result["final_url"] = https_result.get("final_url", "https://" + domain)
        result["redirects"] = https_result.get("redirects", [])
        if result["final_url"].rstrip("/") != ("https://" + domain).rstrip("/"):
            result.setdefault("findings", []).append("Redirected to: " + result["final_url"])
        result["server"] = https_result.get("headers", {}).get("Server", "Unknown")
        result["security_headers"] = check_security_headers(https_result.get("headers", {}))
        result["technologies"] = detect_technologies(
            https_result.get("content", ""),
            https_result.get("headers", {})
        )
        result["redirects"] = https_result.get("redirects", [])
    else:
        # 3. HTTP كخطة بديلة
        http_result = check_http(domain)
        if "error" not in http_result:
            result["http_status"] = http_result.get("status")
            result["server"] = http_result.get("headers", {}).get("Server", "Unknown")
            result["redirects"] = http_result.get("redirects", [])
        else:
            result["error"] = http_result.get("error")

    # 4. SSL
    if check_ssl_flag:
        result["ssl"] = get_ssl_info(domain)

    # 5. Port Scan
    if scan_ports_flag:
        result["open_ports"] = scan_ports(ip)

    # 6. Robots.txt
    result["robots"] = check_robots_txt(domain)

    # 7. Risk Assessment
    result["risk"] = calculate_risk_score(result)

    return result


# ============================================================================
# CLI Entry Point
# ============================================================================
def main():
    """CLI Entry Point with redirect control."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Domain Scanner")
    parser.add_argument("target", help="Domain, IP, or URL to scan")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects (keeps original URL)")
    args = parser.parse_args()
    
    target = args.target
    
    # Detect if target is a full URL with path
    is_url_with_path = target.startswith(("http://", "https://")) and target.count("/") > 3
    
    # Also detect path-only (like hackerone.com/login)
    stripped = target.replace("http://", "").replace("https://", "")
    has_path = "/" in stripped
    
    if has_path or args.no_redirect:
        # Direct URL scan without following redirects
        url = target if target.startswith(("http://", "https://")) else "https://" + target
        
        print("[*] جاري فحص الرابط مباشرة: " + url + "...", file=sys.stderr)
        
        result = fetch_url(url, timeout=10, follow_redirects=False)
        
        if "error" in result:
            print(json.dumps({"error": result["error"], "target": target}, ensure_ascii=False))
            return
        
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Build detailed output
        output = {
            "target": target,
            "domain": domain,
            "scan_type": "direct_url",
            "status": result.get("status"),
            "final_url": result.get("final_url", url),
            "followed_redirects": False,
            "redirects": result.get("redirects", []),
            "server": result.get("headers", {}).get("Server", "Unknown"),
            "content_length": len(result.get("content", "")),
            "technologies": detect_technologies(result.get("content", ""), result.get("headers", {})),
            "security_headers": {},
        }
        
        SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for h in SEC_HEADERS:
            output["security_headers"][h] = result.get("headers", {}).get(h, "MISSING")
            
        # SSL info
        try:
            output["ssl"] = get_ssl_info(domain)
        except Exception:
            output["ssl"] = {"info": "SSL check skipped"}
        
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return
    
    # Standard domain scan (with redirects)
    print("[*] جاري فحص النطاق: " + target + "...", file=sys.stderr)
    print("[*] هذا قد يستغرق 10-30 ثانية...", file=sys.stderr)
    
    scan_result = scan_domain(target)
    print(json.dumps(scan_result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
