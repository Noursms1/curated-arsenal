# -*- coding: utf-8 -*-
"""PCT Subdomain Enumerator v2.0"""
import sys, json, time, ssl, re
try:
    import requests
    from requests.adapters import HTTPAdapter
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print(json.dumps({"error": "requests not installed"}))
    sys.exit(1)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # nosec
        ctx.verify_mode = ssl.CERT_NONE  # nosec
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

def fetch_crtsh(domain, timeout=30, max_retries=3):
    session = requests.Session()
    session.mount("https://", SSLAdapter())
    headers = {"User-Agent": UA, "Accept": "application/json"}
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    last_error = None
    for attempt in range(max_retries):
        try:
            r = session.get(url, headers=headers, timeout=timeout)
            if r.status_code == 502:
                time.sleep(2 + attempt)
                last_error = "HTTP 502 (server busy)"
                continue
            if r.status_code != 200:
                return None, f"HTTP {r.status_code}"
            try:
                return r.json(), None
            except json.JSONDecodeError:
                last_error = "Invalid JSON (rate limited)"
                time.sleep(3 + attempt)
                continue
        except requests.exceptions.Timeout:
            last_error = f"Timeout after {timeout}s"
            time.sleep(2 + attempt)
        except Exception as e:
            last_error = str(e)[:100]
            time.sleep(2 + attempt)
    return None, last_error or "Unknown error"

def probe_http(host, timeout=3):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{host}", timeout=timeout,
                headers={"User-Agent": UA},
                allow_redirects=False, verify=False,
            )
            return {"scheme": scheme, "status": r.status_code,
                    "server": r.headers.get("Server", "")}
        except Exception:
            continue
    return None

def enumerate_subdomains(domain, probe=False, limit=500, timeout=30):
    domain = domain.strip().lower().replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    
    result = {"domain": domain, "source": "crt.sh", "count": 0,
              "live_count": 0, "subdomains": [], "live_subdomains": [], "error": None}
    
    data, error = fetch_crtsh(domain, timeout=timeout)
    if error:
        result["error"] = error
        return result
    if not isinstance(data, list):
        result["error"] = "Unexpected response format"
        return result
    
    subs = set()
    for entry in data:
        name_value = entry.get("name_value", "") or ""
        for n in name_value.split("\n"):
            n = n.strip().lower()
            if not n or "*" in n: continue
            if not re.fullmatch(r"[a-z0-9\.\-]+\.[a-z]{2,}", n): continue
            subs.add(n)
    
    subs.add(domain)
    subs_list = sorted(subs)
    total_found = len(subs_list)
    if total_found > limit:
        subs_list = subs_list[:limit]
    
    result["count"] = total_found
    result["subdomains"] = subs_list
    if total_found > limit:
        result["note"] = f"Showing {limit}/{total_found}"
    
    if probe:
        live = []
        for i, sub in enumerate(subs_list):
            if i > 0 and i % 10 == 0:
                time.sleep(0.3)
            info = probe_http(sub)
            if info:
                live.append({"subdomain": sub, **info})
        result["live_subdomains"] = live
        result["live_count"] = len(live)
    
    return result

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Domain: ")
    probe = "--probe" in sys.argv
    limit = 500
    for arg in sys.argv:
        if arg.startswith("--limit="):
            try: limit = int(arg.split("=")[1])
            except: pass
    result = enumerate_subdomains(domain, probe=probe, limit=limit)
    print(json.dumps(result, indent=2, ensure_ascii=False))