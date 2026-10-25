import sys
import json
import requests
from urllib.parse import urlparse

def fetch_subdomains(domain):
    """تسترجع النطاقات الفرعية من أرشيف Wayback باستخدام API CDX.
    
    تُعيد قائمة فريدة من النطاقات الفرعية.
    """
    api_url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        resp = requests.get(api_url, timeout=10, verify=False)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    subdomains = set()
    for entry in data:
        # كل entry هو قائمة ذات عنصر واحد يحتوي على URL كامل
        if not entry:
            continue
        url = entry[0]
        parsed = urlparse(url)
        host = parsed.hostname
        if host and host.endswith('.' + domain):
            subdomains.add(host)
    return sorted(subdomains)

def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    else:
        domain = sys.stdin.read().strip()
    if not domain:
        print(json.dumps({"error": "no domain provided"}, ensure_ascii=False))
        return
    result = fetch_subdomains(domain)
    output = {"domain": domain, "subdomains": result}
    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
