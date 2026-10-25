
"""
Advanced Network Scanner v3 - WordPress & CORS Edition
متوافق مع PCT Tool Runner (JSON فقط على stdout، التشخيص على stderr).
"""
import socket
import ssl
import json
import concurrent.futures
import ipaddress
import sys
import warnings
from datetime import datetime, timezone

try:
    import requests
    import http.client
    HAS_REQUESTS = True
except ImportError:
    requests = None
    http = None
    HAS_REQUESTS = False

# إخفاء تحذيرات SSL غير الموثوقة عشان الشاشة متتقلبش
warnings.filterwarnings("ignore")
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


class AdvancedScanner:
    def __init__(self, target, max_threads=20):
        self.target = target
        self.max_threads = max_threads
        self.ip = None
        self.results = {
            "target": self.target, "ip": None, "open_ports": [],
            "security_headers": {}, "ssl_info": {}, "findings": [], "errors": [],
            "wordpress": {}, "cors_misconfig": False
        }

    def _log(self, msg):
        """كل رسائل التشخيص تروح لـ stderr عشان متلخبطش الـ JSON في stdout"""
        print(msg, file=sys.stderr, flush=True)

    def resolve_ip(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            self.results["ip"] = self.ip
            ip_obj = ipaddress.ip_address(self.ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                raise ValueError(f"Target {self.ip} is private/internal (SSRF blocked)")
            return True
        except Exception as e:
            self.results["errors"].append(f"DNS Resolution Failed: {str(e)}")
            return False

    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        }
        return services.get(port, "Unknown")

    def grab_banner(self, sock, port):
        try:
            if port in (80, 8080):
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nConnection: close\r\n\r\n")
                return sock.recv(1024).decode("utf-8", errors="ignore")
            elif port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    ssock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nConnection: close\r\n\r\n")
                    return ssock.recv(1024).decode("utf-8", errors="ignore")
            else:
                return sock.recv(1024).decode("utf-8", errors="ignore")
        except Exception:
            return None

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((self.ip, port)) == 0:
                    banner = self.grab_banner(s, port)
                    return {
                        "port": port,
                        "service": self.get_service_name(port),
                        "banner": banner.strip() if banner else "No Banner",
                    }
        except Exception:
            pass
        return None

    def scan_ports(self, ports_to_scan):
        self._log(f"[*] Scanning ports for {self.target} ({self.ip})...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, p) for p in ports_to_scan]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results["open_ports"].append(res)
        self.results["open_ports"].sort(key=lambda x: x["port"])

    def _parse_headers(self, headers_dict):
        lower = {k.lower(): v for k, v in dict(headers_dict).items()}
        self.results["security_headers"] = {
            "Strict-Transport-Security": lower.get("strict-transport-security", "MISSING"),
            "Content-Security-Policy": lower.get("content-security-policy", "MISSING"),
            "X-Frame-Options": lower.get("x-frame-options", "MISSING"),
            "X-Content-Type-Options": lower.get("x-content-type-options", "MISSING"),
            "Server": lower.get("server", "Unknown"),
        }
        for header, value in self.results["security_headers"].items():
            if value == "MISSING":
                self.results["findings"].append(f"Missing Security Header: {header}")

    def _fetch_headers_fallback(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(self.target, context=ctx, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        headers_dict = dict(response.getheaders())
        conn.close()
        return headers_dict

    def _safe_get(self, url):
        """دالة مساعدة لطلب GET مع تجاهل الأخطاء"""
        if not HAS_REQUESTS:
            return None
        try:
            return requests.get(url, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            return None

    def _check_cors(self, headers_dict):
        """فحص CORS Misconfiguration"""
        lower = {k.lower(): v for k, v in dict(headers_dict).items()}
        acao = lower.get("access-control-allow-origin", "")
        acac = lower.get("access-control-allow-credentials", "").lower()
        
        # الثغرة الخطيرة: ACAO=* مع ACAC=true
        if acao == "*" and acac == "true":
            if not self.results["cors_misconfig"]:
                self.results["cors_misconfig"] = True
                self.results["findings"].append("CORS Misconfiguration (ACAO: * with Credentials: true)")

    def check_security_headers(self):
        self._log("[*] Analyzing Security Headers...")
        if not HAS_REQUESTS:
            return
        
        r = self._safe_get(f"https://{self.target}")
        if r:
            self._parse_headers(r.headers)
            self._check_cors(r.headers)
        else:
            try:
                self._parse_headers(self._fetch_headers_fallback())
            except Exception as fe:
                self.results["errors"].append(f"Header fallback failed: {fe}")

    def check_ssl(self):
        self._log("[*] Extracting SSL Information...")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.utcnow()).days
                        self.results["ssl_info"] = {
                            "subject": dict(x[0] for x in cert["subject"]).get("commonName"),
                            "issuer": dict(x[0] for x in cert["issuer"]).get("organizationName"),
                            "valid_until": expire_date.strftime("%Y-%m-%d"),
                            "days_left": days_left,
                            "expired": days_left < 0,
                        }
                        if days_left < 0:
                            self.results["findings"].append("SSL Certificate is Expired")
                    else:
                        self.results["ssl_info"] = {"info": "Cert could not be parsed"}
        except Exception as e:
            self.results["errors"].append(f"SSL Check Failed: {e}")

    def check_wordpress(self):
        """فحص WordPress User Enumeration و Plugins/Drafts Disclosure"""
        if not HAS_REQUESTS:
            return
            
        self._log("[*] Checking for WordPress...")
        base_url = f"https://{self.target}"
        
        # 1. اكتشاف WordPress
        is_wordpress = False
        wp_resp = self._safe_get(f"{base_url}/wp-json/")
        
        if wp_resp and wp_resp.status_code in (200, 401, 403):
            if "wp/v2" in wp_resp.text or wp_resp.headers.get("Content-Type", "").startswith("application/json"):
                is_wordpress = True
        
        # خطة بديلة: البحث عن wp-content في الصفحة الرئيسية
        if not is_wordpress:
            home_resp = self._safe_get(base_url)
            if home_resp and ("wp-content" in home_resp.text or "wp-includes" in home_resp.text):
                is_wordpress = True

        if not is_wordpress:
            self._log("[-] WordPress not detected.")
            return

        self._log("[+] WordPress detected! Probing endpoints...")
        self.results["wordpress"] = {
            "detected": True,
            "exposed_users": [],
            "exposed_plugins": [],
            "exposed_drafts": []
        }
        
        # 2. فحص الـ Endpoints
        endpoints = {
            "users": "/wp-json/wp/v2/users",
            "drafts": "/wp-json/wp/v2/posts?status=draft",
            "plugins": "/wp-json/wp/v2/plugins"
        }

        for key, path in endpoints.items():
            url = f"{base_url}{path}"
            self._log(f"    → Probing {key} endpoint...")
            
            resp = self._safe_get(url)
            if resp and resp.status_code == 200:
                # فحص CORS على الـ Endpoint
                self._check_cors(resp.headers)
                
                try:
                    data = resp.json()
                    if isinstance(data, list) and data:
                        if key == "users":
                            users = [u.get("name", "Unknown") for u in data]
                            self.results["wordpress"]["exposed_users"] = users
                            self.results["findings"].append(f"WordPress User Enumeration: {len(users)} users exposed")
                        elif key == "drafts":
                            drafts = [p.get("title", {}).get("rendered", "Untitled") for p in data]
                            self.results["wordpress"]["exposed_drafts"] = drafts
                            self.results["findings"].append(f"WordPress Drafts Disclosure: {len(drafts)} drafts exposed")
                        elif key == "plugins":
                            plugins = [p.get("name", "Unknown") for p in data]
                            self.results["wordpress"]["exposed_plugins"] = plugins
                            self.results["findings"].append(f"WordPress Plugins Disclosure: {len(plugins)} plugins exposed")
                except Exception:
                    pass

    def run(self):
        if not self.resolve_ip():
            return self.results
        
        self.scan_ports([21, 22, 25, 53, 80, 110, 443, 3306, 8080, 8443])
        
        if any(p["port"] in (443, 8443) for p in self.results["open_ports"]):
            self.check_security_headers()
            self.check_ssl()
            self.check_wordpress()

        # حساب درجة المخاطرة
        score = len(self.results["findings"]) * 10 + len(self.results["errors"]) * 5
        if score >= 70: level = "🔴 Critical"
        elif score >= 40: level = "🟠 High"
        elif score >= 15: level = "🟡 Medium"
        else: level = "🟢 Low"
        
        self.results["risk"] = {
            "score": min(score, 100),
            "level": level,
            "issues": self.results["findings"]
        }
        
        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: advanced_scanner.py <domain>"}))
        sys.exit(1)
    
    try:
        result = AdvancedScanner(sys.argv[1]).run()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)