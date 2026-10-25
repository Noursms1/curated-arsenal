# -*- coding: utf-8 -*-
"""
=============================================================================
 PCT Leak Monitor v2.0
-----------------------------------------------------------------------------
 بديل كامل لأداة فحص التسريبات القديمة.
 
 الميزات:
 - HIBP Pwned Passwords (مجاني، بدون مفتاح، k-anonymity)
 - HIBP Breaches (مفتاح اختياري)
 - LeakCheck.io (مفتاح اختياري)
 - البحث المحلي في ملفات تسريبات (CSV/TXT/JSON/SQL)
 - تحليل قوة كلمة المرور (zxcvbn إن وجد)
 
 الإخراج: JSON على stdout (متوافق مع PCT Tool Runner)
 التشخيص: stderr

 ⚠️ قانوني: للاستخدام على بياناتك أو البيانات المصرح لك بفحصها فقط.
=============================================================================
"""

import os
import sys
import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

# محاولة تحميل مكتبات اختيارية
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

try:
    from dotenv import load_dotenv
    _root = Path(__file__).resolve().parent.parent.parent
    load_dotenv(dotenv_path=_root / ".env", override=False)
except Exception:
    pass


# ============================================================================
# Config
# ============================================================================
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "").strip()
HIBP_USER_AGENT = "PCT-LeakMonitor/2.0"
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MAX_LOCAL_FILE_SIZE = 500 * 1024 * 1024  # 500 MB


def _log(msg):
    """كل التشخيص يروح stderr"""
    print(f"[LEAK] {msg}", file=sys.stderr, flush=True)


# ============================================================================
# 1) Password Pwned Check (FREE - no key needed)
# ============================================================================
def check_password_pwned(password):
    """
    فحص كلمة المرور عبر HIBP Pwned Passwords (k-anonymity).
    مجاني تماماً، لا يحتاج مفتاح، ولا يرسل كلمة المرور كاملة.
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not installed. Run: pip install requests"}
    if not password:
        return {"error": "password is required"}

    # SHA-1 hash → أول 5 حروف تتبعت، الباقي يتم مقارنته محلياً
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        _log(f"Checking password hash (prefix={prefix[:2]}...)")
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        r = requests.get(url, headers={"User-Agent": HIBP_USER_AGENT}, timeout=15)

        if r.status_code != 200:
            return {"error": f"HIBP API error: HTTP {r.status_code}"}

        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                severity = "critical" if count > 100000 else "high" if count > 1000 else "medium"
                return {
                    "pwned": True,
                    "count": count,
                    "message": f"كلمة المرور ظهرت في {count:,} تسريب معروف",
                    "severity": severity,
                    "recommendation": "غيّر كلمة المرور فوراً، ولا تستخدمها في أي مكان آخر",
                }

        return {
            "pwned": False,
            "count": 0,
            "message": "كلمة المرور لم تظهر في قاعدة HIBP (آمنة حتى الآن)",
            "severity": "info",
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 2) Password Strength (using zxcvbn)
# ============================================================================
def analyze_password_strength(password):
    """تحليل قوة كلمة المرور باستخدام zxcvbn"""
    if not password:
        return {"error": "password is required"}

    if HAS_ZXCVBN:
        try:
            result = zxcvbn(password)
            score = result.get("score", 0)  # 0-4
            labels = ["very_weak", "weak", "medium", "strong", "very_strong"]
            return {
                "score": score,
                "score_label": labels[score] if 0 <= score <= 4 else "unknown",
                "guesses_log10": result.get("guesses_log10", 0),
                "crack_time_display": result.get("crack_times_display", {}).get("offline_slow_hashing_1e4_per_second", "N/A"),
                "feedback": result.get("feedback", {}),
                "engine": "zxcvbn",
            }
        except Exception as e:
            return {"error": f"zxcvbn failed: {e}"}

    # Fallback لو zxcvbn مش متاح
    score = 0
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1

    return {
        "score": min(4, score),
        "score_label": ["very_weak", "weak", "medium", "strong", "very_strong"][min(4, score)],
        "engine": "basic_fallback",
        "hint": "لتحليل أدق: pip install zxcvbn",
    }


# ============================================================================
# 3) HIBP Breaches (optional API key)
# ============================================================================
def check_email_hibp(email):
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    if not EMAIL_REGEX.match(email):
        return {"error": "Invalid email format"}
    if not HIBP_API_KEY:
        return {
            "error": "HIBP_API_KEY not configured",
            "hint": "احصل على مفتاح من https://haveibeenpwned.com/API/Key",
            "skipped": True,
        }

    try:
        _log(f"Checking breaches for {email}...")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": HIBP_USER_AGENT}
        r = requests.get(url, headers=headers, timeout=20)

        if r.status_code == 404:
            return {"email": email, "pwned": False, "count": 0, "breaches": []}
        if r.status_code == 401:
            return {"error": "Invalid HIBP API key"}
        if r.status_code == 429:
            return {"error": "Rate limit exceeded (retry in a few minutes)"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}

        breaches = r.json()
        formatted = [{
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses", []),
            "is_verified": b.get("IsVerified"),
            "is_sensitive": b.get("IsSensitive"),
            "description": (b.get("Description") or "")[:200],
        } for b in breaches]

        severity = "critical" if any("Passwords" in b["data_classes"] for b in formatted) \
                   else "high" if len(formatted) > 3 else "medium"

        return {
            "email": email,
            "pwned": len(formatted) > 0,
            "count": len(formatted),
            "breaches": formatted,
            "severity": severity,
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 4) LeakCheck.io (optional API key)
# ============================================================================
def check_leakcheck(query, query_type="email"):
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    if not LEAKCHECK_API_KEY:
        return {
            "error": "LEAKCHECK_API_KEY not configured",
            "hint": "احصل على مفتاح من https://leakcheck.io/api",
            "skipped": True,
        }

    try:
        _log(f"Querying LeakCheck for {query}...")
        url = f"https://leakcheck.io/api/v2/query/{query}"
        headers = {"X-API-Key": LEAKCHECK_API_KEY}
        params = {"type": query_type, "limit": 100}
        r = requests.get(url, headers=headers, params=params, timeout=25)

        if r.status_code == 404:
            return {"query": query, "found": False, "count": 0, "sources": []}
        if r.status_code == 401:
            return {"error": "Invalid LeakCheck API key"}
        if r.status_code == 429:
            return {"error": "Rate limit exceeded"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}

        data = r.json()
        if not data.get("success"):
            return {"error": data.get("error", "Unknown LeakCheck error")}

        results = data.get("result", [])
        sources = list({r.get("source", {}).get("name", "Unknown") for r in results if r.get("source")})
        fields = list({k for r in results for k in r.keys() if k not in ("source",)})

        return {
            "query": query,
            "query_type": query_type,
            "found": len(results) > 0,
            "count": len(results),
            "sources": sources,
            "fields_exposed": fields,
            "severity": "critical" if any("password" in str(r).lower() for r in results) else "high" if len(results) > 5 else "medium",
        }
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 5) Local Dump Search
# ============================================================================
def search_local_dump(file_path, query, max_results=50):
    if not os.path.exists(file_path):
        return {"error": "File not found"}
    if not query:
        return {"error": "query is required"}

    ext = Path(file_path).suffix.lower()
    if ext not in (".txt", ".csv", ".json", ".sql", ".log"):
        return {"error": f"Unsupported file type: {ext} (use .txt/.csv/.json/.sql/.log)"}

    if os.path.getsize(file_path) > MAX_LOCAL_FILE_SIZE:
        return {"error": "File too large (>500MB). Split it first."}

    query_lower = query.lower()
    matches = []
    total_lines = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                total_lines += 1
                if query_lower in line.lower():
                    snippet = line.strip()[:300]
                    # إخفاء البيانات الحساسة في العرض
                    snippet = re.sub(r"(:\s*)[^\s,;\"]{6,}", r"\1[REDACTED]", snippet)
                    matches.append({
                        "line": line_no,
                        "snippet": snippet,
                        "match_type": "email" if "@" in query else "keyword",
                    })
                    if len(matches) >= max_results:
                        break
    except Exception as e:
        return {"error": str(e)}

    return {
        "file": os.path.basename(file_path),
        "query": query,
        "total_lines_scanned": total_lines,
        "matches_found": len(matches),
        "matches": matches,
        "truncated": len(matches) >= max_results,
    }


# ============================================================================
# 6) Unified Check
# ============================================================================
def check_leaks(query, query_type="email", local_file=None):
    """الدالة الرئيسية"""
    result = {
        "query": query,
        "query_type": query_type,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "sources": {},
        "total_findings": 0,
        "risk_level": "none",
        "available_sources": [],
        "missing_sources": [],
        "disclaimer": "⚠️ للاستخدام على بياناتك أو البيانات المصرح بها فقط.",
    }

    # ===== Password =====
    if query_type == "password":
        pw_result = check_password_pwned(query)
        result["sources"]["hibp_pwned_passwords"] = pw_result
        result["available_sources"].append("hibp_pwned_passwords")
        if pw_result.get("pwned"):
            result["total_findings"] += 1

        strength = analyze_password_strength(query)
        result["sources"]["password_strength"] = strength
        result["available_sources"].append(f"password_strength_{strength.get('engine', 'unknown')}")

    # ===== Email =====
    elif query_type == "email":
        if not EMAIL_REGEX.match(query):
            return {**result, "error": "Invalid email format"}

        email_result = check_email_hibp(query)
        result["sources"]["hibp_breaches"] = email_result
        if email_result.get("skipped"):
            result["missing_sources"].append("hibp_breaches")
        else:
            result["available_sources"].append("hibp_breaches")
            if email_result.get("pwned"):
                result["total_findings"] += email_result.get("count", 0)

        lc_result = check_leakcheck(query, "email")
        result["sources"]["leakcheck"] = lc_result
        if lc_result.get("skipped"):
            result["missing_sources"].append("leakcheck")
        else:
            result["available_sources"].append("leakcheck")
            if lc_result.get("found"):
                result["total_findings"] += lc_result.get("count", 0)

    # ===== Domain =====
    elif query_type == "domain":
        lc_result = check_leakcheck(query, "domain")
        result["sources"]["leakcheck"] = lc_result
        if lc_result.get("skipped"):
            result["missing_sources"].append("leakcheck")
        else:
            result["available_sources"].append("leakcheck")
            if lc_result.get("found"):
                result["total_findings"] += lc_result.get("count", 0)

    # ===== Username =====
    elif query_type == "username":
        lc_result = check_leakcheck(query, "username")
        result["sources"]["leakcheck"] = lc_result
        if lc_result.get("skipped"):
            result["missing_sources"].append("leakcheck")
        else:
            result["available_sources"].append("leakcheck")
            if lc_result.get("found"):
                result["total_findings"] += lc_result.get("count", 0)

    else:
        return {**result, "error": f"Unknown query_type: {query_type}"}

    # ===== Local file =====
    if local_file:
        local_result = search_local_dump(local_file, query)
        result["sources"]["local_dump"] = local_result
        if local_result.get("error"):
            result["missing_sources"].append("local_dump")
        else:
            result["available_sources"].append("local_dump")
            if local_result.get("matches_found"):
                result["total_findings"] += local_result.get("matches_found", 0)

    # ===== Risk level =====
    tf = result["total_findings"]
    if tf >= 20: result["risk_level"] = "🔴 Critical"
    elif tf >= 5: result["risk_level"] = "🟠 High"
    elif tf > 0: result["risk_level"] = "🟡 Medium"
    else: result["risk_level"] = "🟢 Clean"

    # ===== Scan ID =====
    result["scan_id"] = hashlib.sha256(
        f"{query}:{query_type}:{result['scan_time']}".encode()
    ).hexdigest()[:16]

    # ===== Warnings =====
    if result["missing_sources"]:
        result["warning"] = f"مصادر غير مفعّلة: {', '.join(result['missing_sources'])}. أضف مفاتيحها في .env لتفعيلها."

    return result


# ============================================================================
# CLI Entry
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: leak_monitor.py <query> [type] [local_file]"}))
        sys.exit(1)

    query = sys.argv[1]
    qtype = sys.argv[2] if len(sys.argv) > 2 else ("password" if len(query) < 20 and "@" not in query else "email")
    local_file = sys.argv[3] if len(sys.argv) > 3 else None

    _log(f"Checking: {qtype} = {query}")
    try:
        result = check_leaks(query, qtype, local_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e), "trace": "internal_error"}))
        sys.exit(1)