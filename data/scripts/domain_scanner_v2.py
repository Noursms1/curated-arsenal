import os
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
domain_scanner – أداة فحص سريعة للنطاقات مع دعم الـ Proxy.

المميزات الحالية:
* تنظيف اسم النطاق.
* استخراج عنوان الـ IP.
* فحص HTTP/HTTPS (مع تجاهل شهادة SSL للسهولة).
* جمع رؤوس الأمان الشائعة.
* استخراج قيمة حقل Server.
* دعم الـ Proxy عبر سطر الأوامر أو المتغيّر البيئي PROXY.
"""

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from typing import Dict, Optional

USER_AGENT = "PCT-Scanner/1.0"
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def build_opener(proxy_url: Optional[str] = None):
    handlers = []
    if proxy_url:
        proxy_dict = {"http": proxy_url, "https": proxy_url}
        handlers.append(urllib.request.ProxyHandler(proxy_dict))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    handlers.append(urllib.request.HTTPHandler())
    return urllib.request.build_opener(*handlers)


def clean_domain(raw):
    return raw.replace("http://", "").replace("https://", "").split("/")[0]


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def fetch_url(opener, url, timeout=5):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return opener.open(req, timeout=timeout)


def scan_domain(domain, proxy=None):
    domain = clean_domain(domain)
    result = {
        "domain": domain,
        "ip_address": None,
        "http_status": None,
        "https_status": None,
        "security_headers": {},
        "server": None,
        "error": None,
        "used_proxy": proxy or "",
    }

    ip = get_ip(domain)
    if not ip:
        result["error"] = "تعذر تحويل النطاق إلى IP (Domain might not exist)"
        return result
    result["ip_address"] = ip

    opener = build_opener(proxy)

    https_url = "https://" + domain
    try:
        with fetch_url(opener, https_url) as resp:
            result["https_status"] = resp.getcode()
            headers = dict(resp.headers)
            result["server"] = headers.get("Server", "Unknown")
            for h in SECURITY_HEADERS:
                result["security_headers"][h] = headers.get(h, "MISSING")
    except urllib.error.HTTPError as http_err:
        result["https_status"] = http_err.code
        headers = dict(http_err.headers)
        result["server"] = headers.get("Server", "Unknown")
        for h in SECURITY_HEADERS:
            result["security_headers"][h] = headers.get(h, "MISSING")
    except Exception as exc_https:
        try:
            http_url = "http://" + domain
            with fetch_url(opener, http_url) as resp:
                result["http_status"] = resp.getcode()
                headers = dict(resp.headers)
                result["server"] = headers.get("Server", "Unknown")
                for h in SECURITY_HEADERS:
                    result["security_headers"][h] = headers.get(h, "MISSING")
        except urllib.error.HTTPError as http_err:
            result["http_status"] = http_err.code
            headers = dict(http_err.headers)
            result["server"] = headers.get("Server", "Unknown")
            for h in SECURITY_HEADERS:
                result["security_headers"][h] = headers.get(h, "MISSING")
        except Exception as exc_http:
            result["error"] = "فشل الاتصال: {} | {}".format(exc_https, exc_http)

    return result


def main():
    parser = argparse.ArgumentParser(description="فحص سريع للنطاق مع دعم الـ Proxy.")
    parser.add_argument("domain", nargs="?", help="النطاق المراد فحصه")
    parser.add_argument("-p", "--proxy", dest="proxy", default=None,
                        help="عنوان الـ proxy (مثال: http://127.0.0.1:8080)")
    args = parser.parse_args()

    proxy_url = args.proxy or os.getenv("PROXY")

    if args.domain:
        target = args.domain
    else:
        target = input("أدخل النطاق للفحص: ").strip()

    print("[*] جارٍ فحص النطاق: " + target)
    if proxy_url:
        print("    باستخدام Proxy: " + proxy_url)

    result = scan_domain(target, proxy=proxy_url)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
