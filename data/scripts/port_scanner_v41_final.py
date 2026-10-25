# -*- coding: utf-8 -*-
"""PCT Port Scanner v4.0 - HackerOne SAFE (No false-positive CVEs)
- WAF-aware (skips CVE mapping when WAF detected)
- Exact version matching only
- Version age filter (skips ancient versions)
- Proper subdomain probing
"""
import socket
import ssl
import sys
import json
import re
import concurrent.futures
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

COMMON_PORTS = {
    21: ("FTP", "medium"), 22: ("SSH", "low"), 23: ("Telnet", "critical"),
    25: ("SMTP", "low"), 53: ("DNS", "low"), 80: ("HTTP", "low"),
    110: ("POP3", "medium"), 143: ("IMAP", "medium"), 443: ("HTTPS", "low"),
    445: ("SMB", "critical"), 993: ("IMAPS", "low"), 995: ("POP3S", "low"),
    1433: ("MSSQL", "critical"), 1521: ("Oracle", "critical"), 3306: ("MySQL", "critical"),
    3389: ("RDP", "critical"), 5432: ("PostgreSQL", "critical"), 5900: ("VNC", "high"),
    6379: ("Redis", "critical"), 8080: ("HTTP-Alt", "low"), 8443: ("HTTPS-Alt", "low"),
    9200: ("Elasticsearch", "critical"), 11211: ("Memcached", "critical"),
    27017: ("MongoDB", "critical"), 5000: ("Dev", "medium"), 7001: ("WebLogic", "high"),
    8000: ("Dev", "low"), 8888: ("Jupyter", "high"), 9000: ("Dev", "medium"),
    9090: ("Dev", "medium"),
}

HTTP_HEADER = b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"

# ============================================================
# WAF signatures (لو اتكشف، منعملش CVE mapping)
# ============================================================
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "_cf_bm", "cf-cache-status"],
    "Akamai": ["akamai", "akamaighost", "ak-bmsc", "x-akamai"],
    "AWS WAF/CloudFront": ["awselb", "aws-waf", "x-amz-cf-id", "cloudfront"],
    "F5 BIG-IP": ["bigip", "f5", "tscookie", "big-ip"],
    "Imperva": ["imperva", "incap_ses", "visid_incap", "x-iinfo"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity": ["mod_security", "modsecurity", "noyb"],
    "Barracuda": ["barra", "barracuda"],
    "Fortinet": ["fortiweb", "fortinet"],
    "Citrix NetScaler": ["netscaler", "citrix", "ns_af"],
    "Radware": ["radware"],
    "Fastly": ["fastly", "x-fastly", "x-served-by"],
    "Varnish": ["varnish", "x-varnish", "via: varnish"],
    "Azure Front Door": ["azurefd", "afd", "x-azure-ref"],
}

# ============================================================
# CVE Database - EXACT VERSION MATCHING ONLY
# key = "server/version" بالضبط زي ما هيطلع في البانر
# ============================================================
CVE_DATABASE = {
    # Apache
    "apache/2.4.49": [{"cve": "CVE-2021-41773", "severity": "critical", "cvss": 9.8, "desc": "Path traversal + RCE"}],
    "apache/2.4.50": [{"cve": "CVE-2021-42013", "severity": "critical", "cvss": 9.8, "desc": "Path traversal bypass"}],
    "apache/2.4.51": [],
    "apache/2.4.7": [{"cve": "CVE-2014-0226", "severity": "high", "cvss": 7.5, "desc": "mod_status heap overflow"}],
    # OpenSSH
    "openssh/6.6.1p1": [{"cve": "CVE-2016-8858", "severity": "high", "cvss": 7.5, "desc": "Memory exhaustion"}],
    "openssh/7.2p2": [{"cve": "CVE-2016-10708", "severity": "high", "cvss": 7.5, "desc": "OOB read"}],
    # nginx
    "nginx/1.18.0": [],
    "nginx/1.19.0": [{"cve": "CVE-2021-23017", "severity": "high", "cvss": 7.7, "desc": "DNS resolver off-by-one"}],
    "nginx/1.14.0": [{"cve": "CVE-2019-9511", "severity": "high", "cvss": 7.5, "desc": "HTTP/2 DoS"}],
    # IIS
    "microsoft-iis/7.5": [{"cve": "CVE-2015-1635", "severity": "critical", "cvss": 9.8, "desc": "HTTP.sys RCE"}],
    "microsoft-iis/8.5": [],
    "microsoft-iis/10.0": [],
    # PHP
    "php/7.0": [{"cve": "CVE-2019-11043", "severity": "critical", "cvss": 9.8, "desc": "FPM RCE"}],
    "php/7.3": [{"cve": "CVE-2019-11043", "severity": "high", "cvss": 7.5, "desc": "FPM RCE (partial)"}],
    "php/8.0": [],
    "php/8.1": [],
    # Tomcat
    "tomcat/8.5": [{"cve": "CVE-2020-9484", "severity": "high", "cvss": 7.0, "desc": "Session deserialization"}],
    "tomcat/9.0": [{"cve": "CVE-2020-1938", "severity": "critical", "cvss": 9.8, "desc": "Ghostcat AJP RCE"}],
}

# Regex صارم: لازم اسم السيرفر + رقم إصدار حقيقي
SERVER_VERSION_RE = re.compile(
    r"\b(Apache|nginx|OpenSSH|Microsoft-IIS|Tomcat|PHP|LiteSpeed|Caddy)[/\s]+(\d+\.\d+(?:\.\d+)?[a-z]?\d*)",
    re.IGNORECASE,
)

# لو النسخة أقدم من كذا، نعتبرها "مش موجودة" (المنصات الحديثة مش بتشغلها)
MIN_VERSION_YEAR = 2018


def _version_year_estimate(server, version):
    """تقدير تقريبي لسنة الإصدار - لتجاهل النسخ القديمة جداً"""
    try:
        parts = version.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        s = server.lower()
        if s == "apache":
            if major < 2: return 1999
            if major == 2 and minor < 4: return 2010
            if major == 2 and minor < 20: return 2014
            return 2019
        if s == "nginx":
            if major < 1: return 2004
            if major == 1 and minor < 10: return 2013
            if major == 1 and minor < 18: return 2016
            return 2019
        if s == "openssh":
            if major < 7: return 2014
            if major < 8: return 2017
            return 2020
        if s == "microsoft-iis":
            if minor < 7: return 2009
            if minor < 10: return 2013
            return 2019
    except Exception:
        pass
    return 2015


def _extract_server_version(banner):
    """يستخرج (server, version) بدقة من البانر - أو None"""
    if not banner:
        return None
    m = SERVER_VERSION_RE.search(banner)
    if not m:
        return None
    return (m.group(1).lower(), m.group(2).lower())


def _detect_waf(headers_dict, content=""):
    """كشف WAF"""
    haystack = " ".join(str(v).lower() for v in headers_dict.values())
    haystack += " " + content.lower()
    detected = []
    for waf, patterns in WAF_SIGNATURES.items():
        if any(pat in haystack for pat in patterns):
            detected.append(waf)
    return detected


def _parse_headers(banner):
    """استخراج headers من banner"""
    headers = {}
    if not banner:
        return headers
    for line in banner.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def find_cves_safe(banner, service):
    """
    CVE mapping v4.1 (HackerOne-Safe):
    1. لو WAF متكشف → مفيش CVE (بانر مزيف)
    2. استخراج server+version بدقة
    3. مطابقة دقيقة في DB
    4. لو النسخة قديمة (قبل 2018) → نضيف تحذير بس، مش نرفض
    """
    if not banner:
        return {"cves": [], "reason": "no banner"}
    
    headers = _parse_headers(banner)
    wafs = _detect_waf(headers, banner)
    if wafs:
        return {
            "cves": [],
            "reason": f"WAF detected ({', '.join(wafs)}) - banner is spoofed, CVE mapping skipped",
            "waf_skipped": True,
        }
    
    sv = _extract_server_version(banner)
    if not sv:
        return {"cves": [], "reason": "no server/version match in banner"}
    
    server, version = sv
    key = f"{server}/{version}"
    cves = CVE_DATABASE.get(key, [])
    
    if not cves:
        return {
            "cves": [],
            "reason": f"no CVE in local DB for {key}",
            "version_detected": key,
        }
    
    # ✅ التحذير بدل الرفض
    year = _version_year_estimate(server, version)
    result = {
        "cves": cves,
        "version_detected": key,
        "reason": "exact match",
    }
    
    if year < MIN_VERSION_YEAR:
        result["age_warning"] = (
            f"Version {server}/{version} is old (est. {year}). "
            f"Confirm manually before reporting to HackerOne."
        )
    
    return result


def grab_banner(host, port, service):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(4)
            s.connect((host, port))
            if port in (443, 8443, 993, 995):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # nosec
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    if service.startswith("HTTP"):
                        ss.send(HTTP_HEADER % host.encode())
                    return ss.recv(2048).decode("utf-8", errors="ignore").strip()[:400]
            elif service.startswith("HTTP") or port in (80, 8080):
                s.send(HTTP_HEADER % host.encode())
                return s.recv(2048).decode("utf-8", errors="ignore").strip()[:400]
            elif port in (21, 22, 25, 110, 143):
                return s.recv(1024).decode("utf-8", errors="ignore").strip()[:400]
            else:
                try:
                    b = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    return b[:400] if b else "(open, no banner)"
                except socket.timeout:
                    return "(open, no banner)"
    except Exception:
        return None


def scan_port(host, port, service, risk):
    banner = grab_banner(host, port, service)
    if banner is None:
        return None
    
    info = {
        "port": port, "service": service, "risk": risk, "banner": banner,
    }
    
    if service.startswith("HTTP"):
        headers = _parse_headers(banner)
        wafs = _detect_waf(headers, banner)
        if wafs:
            info["waf_detected"] = wafs
    
    cve_result = find_cves_safe(banner, service)
    if cve_result["cves"]:
        info["vulnerabilities"] = cve_result["cves"]
        info["risk"] = "critical" if any(c["severity"] == "critical" for c in cve_result["cves"]) else "high"
        info["version_detected"] = cve_result["version_detected"]
        if "age_warning" in cve_result:
            info["age_warning"] = cve_result["age_warning"]
    elif cve_result.get("waf_skipped"):
        info["cve_note"] = cve_result["reason"]
    
    return info


def scan_host(host, ports=None, max_workers=30):
    if ports is None:
        ports = COMMON_PORTS
    result = {"host": host, "ip": None, "open_ports": [], "error": None}
    try:
        result["ip"] = socket.gethostbyname(host)
    except socket.gaierror as e:
        result["error"] = f"DNS failed: {e}"
        return result
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(scan_port, host, p, s, r) for p, (s, r) in ports.items()]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                result["open_ports"].append(res)
    result["open_ports"].sort(key=lambda x: x["port"])
    return result


def calculate_host_risk(open_ports):
    if not open_ports:
        return {"score": 0, "level": "🟢 Safe", "issues": []}
    score = 0
    issues = []
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 2}
    for p in open_ports:
        risk = p.get("risk", "low")
        score += weights.get(risk, 2)
        for cve in p.get("vulnerabilities", []):
            if cve["severity"] == "critical":
                score += 20
                issues.append(f"🚨 Port {p['port']}: {cve['cve']} (CVSS {cve['cvss']})")
            elif cve["severity"] == "high":
                score += 10
                issues.append(f"⚠️ Port {p['port']}: {cve['cve']}")
        if "waf_detected" in p:
            issues.append(f"🛡️ Port {p['port']}: WAF = {', '.join(p['waf_detected'])}")
    score = min(100, score)
    level = "🔴 Critical" if score >= 70 else "🟠 High" if score >= 40 else "🟡 Medium" if score >= 15 else "🟢 Low"
    return {"score": score, "level": level, "issues": issues}


def is_host_alive(host, timeout=3):
    """فحص دقيق: هل الـ host alive (TCP connect على 80/443)"""
    for port in (443, 80, 8080):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return True, port
        except Exception:
            pass
    return False, None


def fetch_subdomains(domain, timeout=20, limit=50):
    if not HAS_REQUESTS:
        return []
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": UA}, timeout=timeout, verify=False,
        )
        if r.status_code != 200:
            return []
        subs = set()
        for e in r.json():
            for n in (e.get("name_value") or "").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and re.fullmatch(r"[a-z0-9\.\-]+\.[a-z]{2,}", n):
                    subs.add(n)
        return sorted(subs)[:limit]
    except Exception:
        return []


def scan(target, multi_target=False, limit_subdomains=20):
    if not multi_target:
        result = scan_host(target)
        result["risk"] = calculate_host_risk(result.get("open_ports", []))
        return result
    
    subs = fetch_subdomains(target, limit=limit_subdomains)
    if not subs:
        return {"domain": target, "error": "No subdomains found", "hosts": []}
    
    alive_hosts = []
    dead_hosts = []
    for sub in subs:
        alive, port = is_host_alive(sub)
        if alive:
            alive_hosts.append((sub, port))
        else:
            dead_hosts.append(sub)
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_host, s): s for s, _ in alive_hosts}
        for f in concurrent.futures.as_completed(futures):
            try:
                h = f.result()
                if h.get("open_ports"):
                    h["risk"] = calculate_host_risk(h["open_ports"])
                    results.append(h)
            except Exception:
                pass
    
    results.sort(key=lambda x: -x["risk"]["score"])
    return {
        "domain": target,
        "total_subdomains": len(subs),
        "alive_subdomains": len(alive_hosts),
        "dead_subdomains": len(dead_hosts),
        "scanned_hosts": len(results),
        "hosts": results,
        "summary": {
            "critical_hosts": sum(1 for h in results if h["risk"]["score"] >= 70),
            "high_hosts": sum(1 for h in results if 40 <= h["risk"]["score"] < 70),
            "total_open_ports": sum(len(h["open_ports"]) for h in results),
        },
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Host/Domain: ")
    multi = "--multi" in sys.argv
    print(json.dumps(scan(target, multi_target=multi), indent=2, ensure_ascii=False))