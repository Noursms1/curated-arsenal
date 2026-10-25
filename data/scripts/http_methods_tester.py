# -*- coding: utf-8 -*-
"""HTTP Methods Tester v2.0 - Full vulnerability detection"""
import sys, json, time, re
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print(json.dumps({"error": "requests not installed. Run: pip install requests"}))
    sys.exit(1)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Methods اللي بنختبرها (بدون HEAD - مكرر)
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "CONNECT"]

# Methods خطيرة لو اشتغلت
DANGEROUS_METHODS = {
    "PUT": "File upload possible (server allows PUT)",
    "DELETE": "Resource deletion possible",
    "TRACE": "Cross-Site Tracing (XST) - server echoes request",
    "CONNECT": "Proxy tunneling possible",
    "PATCH": "Partial modification possible without auth",
}

def _is_trace_reflected(body, marker="PCT_TRACE_TEST"):
    """التحقق إن TRACE فعلا بيرجع نفس الـ request (مش بس 200 كداب)"""
    if not body: return False
    return marker in body or "TRACE /" in body or "TRACE http" in body

def test_single_method(url, method, marker):
    """اختبار method واحدة مع timeout"""
    headers = {"User-Agent": UA}
    if method == "TRACE":
        headers["X-Trace-Marker"] = marker
    try:
        r = requests.request(
            method, url,
            timeout=8,
            headers=headers,
            allow_redirects=False,
            verify=False,
        )
        info = {
            "status": r.status_code,
            "allow_header": r.headers.get("Allow"),
            "server": r.headers.get("Server"),
            "content_type": r.headers.get("Content-Type"),
            "content_length": len(r.content),
        }
        
        # فحص ثغرات محددة
        vulns = []
        if method in DANGEROUS_METHODS and r.status_code in (200, 201, 204):
            if method == "TRACE":
                # TRACE محتاج تحقق فعلي
                body_text = r.text[:2000] if r.text else ""
                if _is_trace_reflected(body_text, marker):
                    vulns.append({
                        "type": "XST (Cross-Site Tracing)",
                        "severity": "medium",
                        "detail": "TRACE echoes request body — cookie theft risk",
                    })
            else:
                vulns.append({
                    "type": DANGEROUS_METHODS[method],
                    "severity": "high" if method in ("PUT", "DELETE") else "medium",
                })
        
        # فحص OPTIONS لو Allow header ضخم
        if method == "OPTIONS" and r.status_code == 200:
            allow = r.headers.get("Allow", "")
            if "TRACE" in allow.upper():
                vulns.append({
                    "type": "OPTIONS exposes TRACE in Allow header",
                    "severity": "low",
                })
        
        if vulns:
            info["vulnerabilities"] = vulns
        
        return info
    except requests.exceptions.Timeout:
        return {"error": "timeout (8s)"}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"connection: {str(e)[:100]}"}
    except requests.exceptions.SSLError:
        return {"error": "SSL error (cert invalid)"}
    except Exception as e:
        return {"error": str(e)[:150]}

def test_methods(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    marker = "PCT_TRACE_MARKER_2026"
    results = {"url": url, "marker_used": marker, "methods": {}, "summary": {}}
    
    total_vulns = 0
    for i, method in enumerate(METHODS_TO_TEST):
        results["methods"][method] = test_single_method(url, method, marker)
        
        # Rate limiting (نأخد نفسنا شوية)
        if i < len(METHODS_TO_TEST) - 1:
            time.sleep(0.3)
        
        # عد الثغرات
        if "vulnerabilities" in results["methods"][method]:
            total_vulns += len(results["methods"][method]["vulnerabilities"])
    
    # ملخص
    enabled_methods = [m for m, r in results["methods"].items() 
                       if r.get("status", 0) in (200, 201, 204)]
    results["summary"] = {
        "enabled_methods": enabled_methods,
        "dangerous_methods": [m for m in enabled_methods if m in DANGEROUS_METHODS],
        "total_vulnerabilities": total_vulns,
        "risk_level": "🔴 Critical" if total_vulns >= 3 else "🟠 High" if total_vulns >= 1 else "🟢 Low",
    }
    return results

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else input("URL: ")
    print(json.dumps(test_methods(url), indent=2, ensure_ascii=False))
