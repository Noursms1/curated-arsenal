import ssl, urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = "https://hackerone.com"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"})

with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
    html = resp.read().decode("utf-8", errors="replace")
    print("[*] Final URL:", resp.geturl())
    print("[*] Status:", resp.getcode())
    print("[*] Content-Type:", resp.headers.get("Content-Type"))
    print("[*] Size:", len(html), "bytes")
    print()
    
    # Check for specific fingerprints
    checks = {
        "csrf-param": "csrf-param" in html,
        "authenticity_token": "authenticity_token" in html,
        "drupalSettings": "drupalSettings" in html,
        "wp-content": "wp-content" in html,
        "jquery": "jquery" in html.lower(),
        "gtag(": "gtag(" in html,
        "cloudflare": "cloudflare" in html.lower(),
        "just a moment": "just a moment" in html.lower(),  # Cloudflare challenge
        "ray id": "ray id" in html.lower(),
    }
    print("[*] Fingerprints in fetched HTML:")
    for k, v in checks.items():
        print(f"    {'[YES]' if v else '[NO] '} {k}")
    
    print()
    print("[*] First 800 chars of HTML:")
    print("=" * 60)
    print(html[:800])