import sys, json, requests

def fetch_url(url):
    """جلب رأس الاستجابة للعنوان المحدد مع مهلة 10 ثوانٍ وتعطيل التحقق من الشهادة."""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        return resp
    except Exception as e:
        return e

def parse_cookies(set_cookie_header):
    """تحليل سلسلة Set-Cookie وإرجاع قائمة القواميس التي تمثل كل ملف تعريف ارتباط."""
    cookies = []
    if not set_cookie_header:
        return cookies
    # قد يحتوي Header على عدة ملفات تعريف ارتباط مفصولة بفواصل غير موثوقة؛
    # لذلك نستخدم طريقة بديلة عبر split على '\n' إذا كان موجودًا، وإلا نفترض فاصل الفاصلة.
    raw_parts = set_cookie_header.split('\n') if '\n' in set_cookie_header else set_cookie_header.split(',')
    # تجميع الأجزاء التي تمثل ملف تعريف ارتباط كامل (تحتوي على '=')
    current = ''
    for part in raw_parts:
        if '=' in part and not current:
            current = part.strip()
        else:
            current += ',' + part.strip()
        if ';' in part:
            # نفترض أن الفاصل انتهى عند وجود سمة؛
            # لا توجد طريقة مثالية بدون مكتبة خارجية، لذا نضيف ما لدينا الآن.
            cookies.append(current)
            current = ''
    if current:
        cookies.append(current)
    return cookies

def analyze_cookie(cookie_str):
    """تحليل ملف تعريف الارتباط وإرجاع القيم المطلوبة للعلامات الأمنية."""
    parts = [p.strip() for p in cookie_str.split(';')]
    name_val = parts[0] if parts else ''
    name = name_val.split('=')[0] if '=' in name_val else name_val
    attrs = {p.lower() for p in parts[1:]}
    flags = {
        "HttpOnly": "httponly" in attrs,
        "Secure": "secure" in attrs,
        "SameSite": any(a.startswith('samesite') for a in attrs)
    }
    return {"name": name, "flags": flags}

def main():
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = sys.stdin.read().strip()
    
    # Auto-add https:// prefix
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    result = {"url": url, "cookies": [], "error": None}
    
    try:
        import requests
        # Use requests to get proper cookie objects
        resp = requests.get(url, timeout=15, verify=False, allow_redirects=True)
        
        # requests handles Set-Cookie parsing correctly
        for c in resp.cookies:
            result["cookies"].append({
                "name": c.name,
                "value": (c.value[:20] + "...") if c.value and len(c.value) > 20 else c.value,
                "domain": c.domain or "",
                "path": c.path or "",
                "secure": bool(c.secure),
                "httponly": "HttpOnly" in str(c._rest),
                "samesite": c._rest.get("SameSite", "MISSING") if hasattr(c, "_rest") else "MISSING",
                "expires": c.expires
            })
        
        if not result["cookies"]:
            result["info"] = "No cookies in response (this is normal for some endpoints)"
            
    except Exception as e:
        result["error"] = str(e)
    
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2))



if __name__ == "__main__":
    main()
